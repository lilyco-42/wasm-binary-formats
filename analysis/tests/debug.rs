//! The Information window: a PE's debug directory, and the CodeView block that names its program
//! database.
//!
//! `test/fixtures/debug.probe.json` comes from `scripts/make-debug-fixtures.py`, which links `dbg.exe`
//! with `clang -g -gcodeview` and `lld-link /debug` and then asks three implementations about it: the
//! bytes themselves, `llvm-readobj --coff-debug-directory`, and pefile's own `DIRECTORY_ENTRY_DEBUG`.
//! A row is not written unless all three agree on each entry's type number, time stamp, version pair,
//! body size and both locations, and - for a body that starts with `RSDS` - on the signature, the GUID,
//! the age and the path.
//!
//! The GUID is the interesting one to compare, because it does not travel in the order it is printed:
//! three little-endian integers and then eight bytes, so LLVM's bracketed form and pefile's 32 plain
//! digits are both conversions of the same sixteen. The probe holds the digits and refuses to be
//! written unless both readers produce them, so the rule is theirs rather than this reader's memory -
//! and it is why a GUID lld filled with its own placeholder still reads `LLD PDB.` in ASCII at the end.
//!
//! Three facts the fixtures settled. `/pdbaltpath` is what keeps a local absolute path out of a
//! committed file, and it is also the realistic shape, since that name is what a symbol service looks
//! up. `/timeStamp` has to be pinned, because the linker otherwise stamps the header and the debug
//! entry from the clock and a probe written yesterday would fail today. Re-running the generator gives
//! the committed file back exactly, but a *second* link inside one run moves eight bytes of the GUID, so
//! those digits are compared against the probe and never spelled out in an assertion. And a COFF object
//! carries `.debug$S` *sections* with no directory to point at them,
//! which `cv.obj` shows: two readers list nothing there, so this reader must not invent a table either.

use apk_lens_analysis::{analyse, debug_at, debug_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-debug-fixtures.py: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("debug.probe.json");
    let head = body
        .find(&format!("\"{file}\": {{"))
        .unwrap_or_else(|| panic!("{file} is not in the probe"));
    let start = body[head..]
        .find("\"rows\": [")
        .unwrap_or_else(|| panic!("{file} has no rows list"));
    let tail = &body[head + start + "\"rows\": [".len()..];
    if tail.starts_with(']') {
        return Vec::new();
    }
    let end = tail
        .find("\n  ]")
        .unwrap_or_else(|| panic!("{file}'s rows list never closes"));
    tail[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_suffix(',').unwrap_or(line);
            let line = line.strip_prefix('"')?;
            let line = line.strip_suffix('"')?;
            Some(line.replace("\\t", "\t"))
        })
        .collect()
}

fn rows(name: &str) -> Vec<String> {
    let bytes = fs::read(format!("{FIXTURES}{name}"))
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-debug-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = debug_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = debug_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

fn cell(row: &str, key: &str) -> Option<String> {
    let parts: Vec<&str> = row.split('\t').collect();
    parts.iter().position(|one| *one == key).map(|at| parts[at + 1].to_owned())
}

/// What this reader says against what the two external ones said, as one line rather than as two walls
/// of text.
fn difference(name: &str) -> String {
    let mine = rows(name);
    let wanted = probe_rows(name);
    if mine.len() != wanted.len() {
        return format!("{name}: the probe lists {} rows, this reader {}", wanted.len(), mine.len());
    }
    for (index, (one, two)) in mine.iter().zip(&wanted).enumerate() {
        if one != two {
            return format!("{name} row {index}: the readers said {two:?}, this reader says {one:?}");
        }
    }
    String::new()
}

/// The entry a linker writes when it is asked for debug information: one record, one CodeView body, and
/// a path that names the `.pdb` beside it.
#[test]
fn the_codeview_block_names_the_program_database_and_the_guid_that_ties_it() {
    let listed = rows("dbg.exe");
    assert_eq!(listed.len(), 3, "{listed:?}");
    assert_eq!(
        listed[0],
        "debug\tentries\t1\tsize\t28\tdir\t6\trva\t0x2000\toff\t1536\tcv\t1"
    );
    assert_eq!(
        listed[1],
        "entry\t0\ttype\t2\tname\tCodeView\ttime\t0x6553f100\tmajor\t0\tminor\t0\tbytes\t32\trva\t0x201c\tbody\t1564\tptr\t1564"
    );
    // The GUID row is checked at its ends rather than as one string: a second link of the same command
    // moves those digits, so no assertion here spells them out, while `difference` below still compares
    // the whole row against the probe the same run wrote.
    let cv = &listed[2];
    assert!(cv.starts_with("cv\t0\tsig\tRSDS\tguid\t"), "{cv}");
    assert!(cv.ends_with("\tage\t1\tpath\tdbg.pdb"), "{cv}");
    assert!(cv.contains("4c4c44205044422e"), "the GUID is not what lld wrote: {cv}");
    assert_eq!(difference("dbg.exe"), "");
}

/// Every fixture, row for row, against `llvm-readobj` and pefile - including `lab.exe`, whose CodeView
/// block carries a GUID and an empty path, which is the shape a link with no PDB name leaves behind.
#[test]
fn every_entry_the_readers_listed_comes_back_the_same_way() {
    for name in ["dbg.exe", "nodbg.exe", "lab.exe", "cv.obj"] {
        assert_eq!(difference(name), "", "{name} does not match the two readers");
    }
    let empty = probe_rows("lab.exe");
    assert!(empty.last().expect("the CodeView row").ends_with("\tpath\t"),
        "the probe no longer holds the empty-path case: {:?}", empty.last());
}

/// The body an entry points at is read back and compared with the signature the row prints, and the
/// GUID row is checked against the bytes at that offset - so a section mapping that landed one word off
/// would fail here even where the numbers still look plausible.
#[test]
fn every_body_the_directory_names_is_where_the_directory_says_it_is() {
    let bytes = fs::read(format!("{FIXTURES}dbg.exe")).expect("the fixture the probe was made from");
    let listed = rows("dbg.exe");
    for row in listed.iter().filter(|one| one.starts_with("entry\t")) {
        let at: usize = cell(row, "body").expect("a body offset").parse().expect("a number");
        let size: usize = cell(row, "bytes").expect("a size").parse().expect("a number");
        assert!(at + size <= bytes.len(), "{row} reads past the end of the file");
        assert_eq!(&bytes[at..at + 4], b"RSDS", "{row} points at something else");
        assert_eq!(at.to_string(), cell(row, "ptr").expect("the stated pointer"),
                   "the RVA and the entry's own pointer disagree: {row}");
    }
    let cv = &listed[2];
    let guid = cell(cv, "guid").expect("a GUID in a CodeView row");
    let at: usize = cell(&listed[1], "body").expect("a body offset").parse().expect("a number");
    let (one, two, three) = (
        u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()),
        u16::from_le_bytes(bytes[at + 8..at + 10].try_into().unwrap()),
        u16::from_le_bytes(bytes[at + 10..at + 12].try_into().unwrap()),
    );
    let tail: String = bytes[at + 12..at + 20].iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(guid, format!("{one:08x}{two:04x}{three:04x}{tail}"), "the GUID is not the file's bytes");
    // Those last eight bytes are the only part of the GUID that reaches a row unchanged - the first
    // three groups are little-endian integers - which is why lld's placeholder reads as ASCII there.
    assert_eq!(&bytes[at + 12..at + 20], b"LLD PDB.", "{guid}");
    assert_eq!(cell(cv, "path").expect("a path"), "dbg.pdb");
}

/// A link with no `/debug` has an empty directory, and an object file has no directory to be empty: both
/// answer with no rows, as does an ELF, whose equivalents are `PT_DYNAMIC` and the section table.
#[test]
fn a_file_with_nothing_to_report_answers_with_nothing() {
    assert_eq!(rows("nodbg.exe"), Vec::<String>::new());
    assert_eq!(rows("cv.obj"), Vec::<String>::new());
    for name in ["lab.elf", "libuser.so"] {
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect("the fixture");
        assert!(analyse(&bytes).is_some(), "{name} has to parse");
        assert_eq!(debug_count(), 0, "{name} answered with a debug directory");
    }
}
