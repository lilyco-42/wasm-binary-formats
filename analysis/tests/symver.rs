//! Which version of a name each dynamic symbol carries, checked against `readelf -VW` and
//! `llvm-readobj --version-info`.
//!
//! `test/fixtures/symver.probe.json` comes from `scripts/make-symver-fixtures.py`, which links
//! `libver.so` and `libver32.so` from one object and one two-node version script, then links
//! `libuse.so` against the first so that the *needs* side exists too. A row is written only where the
//! byte walk and both listings agree on every index, hash, flag, name and count, and only where
//! `DT_VERDEFNUM` and `DT_VERNEEDNUM` match what the chains actually reached.
//!
//! Two things the fixtures settled. The hash a version record carries is the SysV ELF hash of its name:
//! `readelf` prints none at all, LLVM prints its own, and this test recomputes it from the name in the
//! row - so a hash here is a derived thing rather than a transcription, and it is also what catches a
//! record read at the wrong offset, since `vna_other`, the u16 six bytes into a Vernaux, is the version
//! index and has nothing to do with where the record sits. And the two listings part company on the
//! reserved indices: binutils calls 0 and 1 `*local*` and `*global*`, LLVM gives them no version word at
//! all, so the rows print `-` for them and name nothing the file itself does not name.
//!
//! `libver32.so` is the same producer for `i386`, and it exists because `.gnu.version` is an array of
//! 16-bit indices in both classes while the tables beside it are reached through class-wide words. The
//! two files agree on every version fact except where their sections lie and how wide the addresses
//! are - which is the assertion that a reader did not quietly assume one class.

use apk_lens_analysis::{analyse, symver_at, symver_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-symver-fixtures.py: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("symver.probe.json");
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
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-symver-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = symver_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = symver_at(index, slot.as_mut_ptr(), slot.len() as i32);
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

/// The SysV ELF hash, computed here for the same reason the fixtures script computes it: so that a
/// number in a row is checked against a derivation rather than copied through.
fn elf_hash(name: &str) -> u32 {
    let mut total: u32 = 0;
    for one in name.as_bytes() {
        total = (total << 4) + u32::from(*one);
        let high = total & 0xF000_0000;
        if high != 0 {
            total ^= high >> 24;
        }
        total &= !high;
    }
    total
}

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

/// The defining file: three dynamic symbols, three version indices, and two versions of its own name
/// plus the BASE one that carries the file's own soname.
#[test]
fn a_defining_file_lists_the_versions_its_script_asked_for() {
    let listed = rows("libver.so");
    assert_eq!(
        listed,
        vec![
            "symver\tsymbols\t3\tdefs\t3\tneeds\t0\tversym\t640\tverdef\t648\tverneed\t-1\tbits\t64",
            "symbol\t0\tvalue\t0x0\tindex\t0\tname\t-\thidden\tno",
            "symbol\t1\tvalue\t0x2\tindex\t2\tname\tLAB_1\thidden\tno",
            "symbol\t2\tvalue\t0x3\tindex\t3\tname\tLAB_2\thidden\tno",
            "def\t0\tindex\t1\thash\t164382575\tflags\tBASE\tname\tlibver.so\tcnt\t1\tversion\t1",
            "def\t1\tindex\t2\thash\t5265441\tflags\tnone\tname\tLAB_1\tcnt\t1\tversion\t1",
            "def\t2\tindex\t3\thash\t5265442\tflags\tnone\tname\tLAB_2\tcnt\t1\tversion\t1",
        ]
    );
    // Index 1 is the BASE record, and it is the file's own name - which is why `-Wl,-soname` is part of
    // building the fixture rather than decoration.
    assert_eq!(cell(&listed[4], "name").expect("a base name"), "libver.so");
    assert_eq!(cell(&listed[4], "flags").expect("a flag word"), "BASE");
}

/// The asking file: it defines nothing, and one of its two symbols is a versioned reference to
/// `libver.so`'s `LAB_2` while the other carries the unversioned global index.
#[test]
fn a_caller_names_the_file_and_the_version_it_needs() {
    let listed = rows("libuse.so");
    assert_eq!(
        listed,
        vec![
            "symver\tsymbols\t3\tdefs\t0\tneeds\t1\tversym\t640\tverdef\t-1\tverneed\t648\tbits\t64",
            "symbol\t0\tvalue\t0x0\tindex\t0\tname\t-\thidden\tno",
            "symbol\t1\tvalue\t0x2\tindex\t2\tname\tLAB_2\thidden\tno",
            "symbol\t2\tvalue\t0x1\tindex\t1\tname\t-\thidden\tno",
            "need\t0\tfile\tlibver.so\tname\tLAB_2\thash\t5265442\tindex\t2\tflags\tnone\tversion\t1",
        ]
    );
    // The same index in the two files reaches the same name, and the caller reaches it through a need
    // rather than a definition - the difference the tables exist to record.
    let here = rows("libver.so");
    assert!(here.iter().any(|one| one.starts_with("def\t2") && cell(one, "name").as_deref() == Some("LAB_2")));
    assert!(!here.iter().any(|one| one.starts_with("need\t")));
}

/// Every hash in a row is the ELF hash of the name beside it, and every index a symbol row carries is
/// one of the indices the tables in the same file name.
#[test]
fn the_hashes_are_recomputed_and_the_indices_resolve() {
    for name in ["libver.so", "libver32.so", "libuse.so"] {
        let listed = rows(name);
        let named: Vec<String> = listed
            .iter()
            .filter(|one| one.starts_with("def\t") || one.starts_with("need\t"))
            .map(|one| {
                let hash: u32 = cell(one, "hash").expect("a hash").parse().expect("a number");
                let spelled = cell(one, "name").expect("a name");
                assert_eq!(hash, elf_hash(&spelled), "{name}: {one} does not hash to its own name");
                cell(one, "index").expect("an index")
            })
            .collect();
        for row in listed.iter().filter(|one| one.starts_with("symbol\t")) {
            let index = cell(row, "index").expect("an index");
            let reached = cell(row, "name").expect("a name column");
            if reached == "-" {
                assert!(index == "0" || index == "1" || !named.contains(&index),
                        "{name}: {row} resolves to nothing yet {named:?} names it");
                continue;
            }
            assert!(named.contains(&index), "{name}: {row} names {reached} for an index no table carries");
        }
    }
}

/// The 32-bit build of the same producer and script says the same thing about versions, and differs
/// only in where its sections lie and how wide its addresses are.
#[test]
fn the_same_version_facts_survive_the_other_class() {
    assert_eq!(difference("libver32.so"), "");
    let wide = rows("libver.so");
    let thin = rows("libver32.so");
    assert_eq!(cell(&wide[0], "bits").expect("bits"), "64");
    assert_eq!(cell(&thin[0], "bits").expect("bits"), "32");
    assert_ne!(cell(&wide[0], "versym").expect("a place"), cell(&thin[0], "versym").expect("a place"));
    // Only the totals row carries anything class-dependent: the places and the width. Everything below
    // it has to be the same statement about the same version script.
    for (index, (one, two)) in wide.iter().skip(1).zip(thin.iter().skip(1)).enumerate() {
        assert_eq!(one, two, "row {index} differs between the two classes");
    }
}

/// Every file, row for row, against both listings.
#[test]
fn every_table_the_readers_listed_comes_back_the_same_way() {
    for name in ["libver.so", "libver32.so", "libuse.so", "lab.so", "lab.elf", "liblab.so"] {
        assert_eq!(difference(name), "", "{name} does not match the two readers");
    }
    // The three negatives are three different reasons: `lab.so` has a dynamic section but no version
    // script, `lab.elf` is static and has neither, and `liblab.so` is the dynamic-window fixture,
    // which is dynamic but unversioned. All three answer with no rows rather than with an empty table.
    for name in ["lab.so", "lab.elf", "liblab.so"] {
        assert_eq!(probe_rows(name), Vec::<String>::new(), "{name} grew version tables in the probe");
    }
    let bytes = fs::read(format!("{FIXTURES}res.dll")).expect("a PE fixture");
    assert!(analyse(&bytes).is_some());
    assert_eq!(symver_count(), 0, "a PE was given ELF version tables");
}
