//! The Dynamic window: what an ELF tells its loader to bring in, read out of `PT_DYNAMIC`.
//!
//! `test/fixtures/dynamic.probe.json` comes from `scripts/make-dynamic-fixtures.py`, which builds three
//! of the files here and then asks three implementations about all six that carry a dynamic section:
//!
//!   * `liblab.so` / `libuser.so` - `clang --target=x86_64-unknown-linux-gnu -shared`, so the entries a
//!     real load needs are present: `DT_NEEDED`, `DT_SONAME`, and a `DT_RUNPATH` whose path has to be
//!     read back out of the string table rather than from the command line that asked for it.
//!   * `many.so` - the same compiler, told to need seventy stub libraries with `--no-as-needed`, which
//!     is what pushes the section past the row cap every other window has.
//!   * `lab.so`, `lab32.so`, `labarm.so` - the ELF fixtures the relocation panels were made from, which
//!     carry a dynamic section but no library names at all (`-nostdlib` leaves nothing to need), and one
//!     of which stores each entry in 8 bytes rather than 16.
//!
//! The readers are a Python walk of the bytes, `readelf -dW` and `llvm-readobj --dynamic-table`. A row is
//! not written unless the three agree on the entry's order, its tag number and its value, and unless both
//! readers spell the tag the same word - which is why the tag names below are the ones two external
//! programs used in these files rather than a `DT_*` table copied out of memory. The same rule earns the
//! `word` column: `DT_STRSZ` is a byte count and `DT_PLTREL` holds a relocation type, and the readers say
//! so, so the row carries `BYTES`, `RELA` or `REL`. `DT_INIT` and `DT_FINI` were in the first draft of the
//! string list and do not index the string table at all, which is the kind of mistake a witness catches
//! and a specification summary does not.
//!
//! The other thing the fixtures settled: `DT_STRTAB`'s own value is an address, so resolving a name is
//! two conversions through the `PT_LOAD` records - the same mapping that turns an RVA into a file offset
//! in the Resources window, and a wrong one of them reads a name out of the wrong place.

use apk_lens_analysis::{analyse, dynamic_at, dynamic_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-dynamic-fixtures.py: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: the script writes one row per line inside
/// `"rows": [ ... ]`, and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("dynamic.probe.json");
    let head = body
        .find(&format!("\"{file}\": {{"))
        .unwrap_or_else(|| panic!("{file} is not in the probe"));
    let start = body[head..]
        .find("\"rows\": [")
        .unwrap_or_else(|| panic!("{file} has no rows list"));
    let tail = &body[head + start + "\"rows\": [".len()..];
    // An empty list is written on one line, `[]`, and the closing bracket of the next file's list is
    // still two lines down - so the shape is checked before the end is looked for.
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
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-dynamic-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = dynamic_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = dynamic_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// What this reader says against what the two external ones said, reported as one line rather than as
/// two walls of text: a 66-row file hides its own difference in a full diff.
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

/// The shape a distribution's shared objects have: what to load, what the file calls itself, and where
/// else to look for the first.
#[test]
fn the_names_a_loader_acts_on_come_back_through_the_string_table() {
    assert_eq!(
        rows("liblab.so"),
        vec![
            "dynamic\tentries\t7\twidth\t16\tvaddr\t0x22d8\toff\t728\tfilesz\t112\tstrtab\t0x250\tstrlen\t21\tneeded\t0\ttext\t1",
            "entry\t0\ttag\t0xe\tname\tSONAME\tvalue\t0xb\ttext\tliblab.so",
            "entry\t1\ttag\t0x6\tname\tSYMTAB\tvalue\t0x200",
            "entry\t2\ttag\t0xb\tname\tSYMENT\tvalue\t0x18\tword\tBYTES",
            "entry\t3\ttag\t0x5\tname\tSTRTAB\tvalue\t0x250",
            "entry\t4\ttag\t0xa\tname\tSTRSZ\tvalue\t0x15\tword\tBYTES",
            "entry\t5\ttag\t0x6ffffef5\tname\tGNU_HASH\tvalue\t0x230",
            "entry\t6\ttag\t0x0\tname\tNULL\tvalue\t0x0",
        ]
    );
    let user = rows("libuser.so").join("\n");
    assert!(user.contains("entry\t0\ttag\t0x1d\tname\tRUNPATH\tvalue\t0x12\ttext\t/opt/lab/lib"), "{user}");
    assert!(user.contains("entry\t1\ttag\t0x1\tname\tNEEDED\tvalue\t0x1f\ttext\tliblab.so"), "{user}");
    assert!(user.contains("entry\t6\ttag\t0x14\tname\tPLTREL\tvalue\t0x7\tword\tRELA"), "{user}");
}

/// Every file that carries a dynamic section, row for row against `readelf` and `llvm-readobj` -
/// including the 32-bit one, whose records are 8 bytes wide and whose `DT_PLTREL` therefore says `REL`.
#[test]
fn every_entry_the_readers_listed_comes_back_the_same_way() {
    for name in ["liblab.so", "libuser.so", "many.so", "lab.so", "lab32.so", "labarm.so"] {
        assert_eq!(difference(name), "", "{name} does not match the two readers");
    }
}

/// The totals row counts what the file holds, not what the panel is allowed to show: `many.so` needs
/// seventy libraries and lists sixty-four rows, so a reader that derived its totals from its own list
/// would report sixty-four entries and sixty-four names.
#[test]
fn the_seventieth_need_is_counted_even_though_it_is_not_listed() {
    let listed = rows("many.so");
    assert_eq!(listed.len(), 66, "one totals row, the cap, and the cut");
    assert!(listed[0].starts_with("dynamic\tentries\t81\t"), "{}", listed[0]);
    assert!(listed[0].contains("needed\t70\t"), "{}", listed[0]);
    assert!(listed[0].ends_with("text\t71"), "{}", listed[0]);
    assert_eq!(listed[65], "cut\tentries\t81\tlisted\t64");
    assert_eq!(
        listed.iter().filter(|row| row.starts_with("entry\t")).count(),
        64,
        "the list ran past the cap"
    );
    assert_eq!(listed[1], "entry\t0\ttag\t0x1\tname\tNEEDED\tvalue\t0x12\ttext\tlibst0.so");
    assert_eq!(listed[64], "entry\t63\ttag\t0x1\tname\tNEEDED\tvalue\t0x2bd\ttext\tlibst63.so");
}

/// A static executable has no `PT_DYNAMIC`, so the panel is empty rather than guessed at - and a PE has
/// no such list at all, because it names its imports through a data directory instead.
#[test]
fn a_file_with_nothing_to_load_answers_with_nothing() {
    assert_eq!(probe_rows("lab.elf"), Vec::<String>::new());
    assert_eq!(difference("lab.elf"), "");
    for name in ["res.dll", "answer.obj"] {
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect("the fixture");
        assert!(analyse(&bytes).is_some(), "{name} has to parse");
        assert_eq!(dynamic_count(), 0, "{name} answered with a dynamic section");
    }
}
