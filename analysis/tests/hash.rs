//! The tables a loader hashes into, checked against what the file stores and what its symbols say.
//!
//! `test/fixtures/hash.probe.json` comes from `scripts/make-hash-fixtures.py`, which links one C file of
//! ninety globals four ways - `.gnu.hash` alone, `.hash` alone, both in one file, and both for `i386` -
//! and writes a row only where the byte walk, `llvm-readobj --gnu-hash-table` / `--hash-table` and
//! pyelftools agree on the header words and both arrays.
//!
//! The traversal is derived in the generator and re-checked here rather than taken on trust: a bucket
//! holds a symbol index and zero for an empty one, a `.hash` chain word holds the next symbol index, and
//! a `.gnu.hash` chain runs forward from the bucket's symbol through consecutive entries, ending on the
//! word whose bit 0 is set. Under that rule every chain word equals the hash of the name it stands for -
//! raised into bit 0 on the last entry of a run, cleared on the others - and the runs together reach
//! every named symbol at or above the table's floor and no other. That is what the counts below restate:
//! the docs elsewhere warn that the widely recalled bit-31 terminator is not what these files do.
//!
//! The row worth reading is `unfound`. A `.gnu.hash` table starts at `symoffset`, so `lab.so`'s
//! `data_at` and `call_me` are dynamic symbols a loader can never be asked for by name; a reader that
//! only lists `.dynsym` would call them exported and reachable.

use apk_lens_analysis::{analyse, hash_at, hash_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-hash-fixtures.py to write it: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("hash.probe.json");
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
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-hash-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = hash_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = hash_at(index, slot.as_mut_ptr(), slot.len() as i32);
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

fn number(row: &str, key: &str) -> u64 {
    cell(row, key).unwrap_or_else(|| panic!("{row} has no {key}")).parse().expect("a number")
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

/// The symbol that is in the file but not in the table - the reason "it is dynamic" and "it can be
/// looked up" are two different statements.
#[test]
fn symbols_below_the_floor_are_named_and_called_unreachable() {
    let listed = rows("lab.so");
    assert_eq!(
        listed,
        [
            "hash\ttables\t1\tdynsym\t9\tbits\t64\tgnu\t1\tsysv\t0",
            "table\t0\tkind\tgnu\toff\t784\tbytes\t60\tinfo\t0\tbuckets\t1\tchains\t6\tsymoffset\t3\tmasks\t2\twordsize\t8\tempty\t0\treach\t6\tfloor\t3",
            "bucket\t0\t0\thead\t3\tlength\t6",
            "unfound\t0\t1\tname\tdata_at",
            "unfound\t0\t2\tname\tcall_me",
        ]
    );
    // Six of the nine dynamic symbols are hashed; the two named below the floor are not; index 0 is the
    // null symbol, which has no name to look up at all and so earns no row.
    assert_eq!(number(&listed[1], "reach"), 6);
    assert_eq!(number(&listed[1], "floor"), 3);
    assert_eq!(listed.iter().filter(|one| one.starts_with("unfound\t")).count(), 2);
}

/// The GNU shape on a file with real tables: 22 buckets, two of them empty, 91 chain words, and every
/// named symbol reached by exactly one run.
#[test]
fn the_gnu_table_splits_its_symbols_into_one_run_per_bucket() {
    let listed = rows("hgnu.so");
    assert_eq!(
        listed[..3],
        [
            "hash\ttables\t1\tdynsym\t92\tbits\t64\tgnu\t1\tsysv\t0",
            "table\t0\tkind\tgnu\toff\t2776\tbytes\t724\tinfo\t0\tbuckets\t22\tchains\t91\tsymoffset\t1\tmasks\t32\twordsize\t8\tempty\t2\treach\t91\tfloor\t1",
            "bucket\t0\t0\thead\t1\tlength\t5",
        ]
    );
    let buckets: Vec<&String> = listed.iter().filter(|one| one.starts_with("bucket\t")).collect();
    assert_eq!(buckets.len(), 22);
    let total: u64 = buckets.iter().map(|one| number(one, "length")).sum();
    assert_eq!(total, number(&listed[1], "reach"), "the runs do not add up to what is reached");
    assert_eq!(number(&listed[1], "empty"), 2);
    // The empty buckets are the ones with no head, and they contribute no length.
    for one in buckets.iter().filter(|one| cell(one, "head").as_deref() == Some("-")) {
        assert_eq!(number(one, "length"), 0, "{one} has no head yet runs");
    }
    // A bucket's head is a symbol index, so no run may start at zero.
    for one in buckets.iter().filter(|one| cell(one, "head").as_deref() != Some("-")) {
        assert!(number(one, "head") >= number(&listed[1], "floor"), "{one} starts below the floor");
    }
}

/// The older shape over the same ninety names, and the cap: 92 buckets do not fit in one panel.
#[test]
fn the_old_table_counts_the_same_symbols_and_the_list_still_stops() {
    let listed = rows("hsys.so");
    assert_eq!(
        listed[..2],
        [
            "hash\ttables\t1\tdynsym\t92\tbits\t64\tgnu\t0\tsysv\t1",
            "table\t0\tkind\tsysv\toff\t2776\tbytes\t744\tinfo\t0\tbuckets\t92\tchains\t92\tempty\t16\treach\t91\tfloor\t1",
        ]
    );
    assert_eq!(cell(&listed[1], "symoffset"), None, "the old table has no floor of its own");
    assert_eq!(cell(&listed[1], "masks"), None, "and no mask words");
    assert_eq!(
        listed.last().expect("a last row"),
        "cut\tbuckets\t92\ttable\t0\tlisted\t64"
    );
    assert_eq!(listed.iter().filter(|one| one.starts_with("bucket\t")).count(), 64);
    // Two shapes, one symbol set: the same 91 names, each reachable in both.
    let gnu = rows("hgnu.so");
    assert_eq!(number(&gnu[1], "reach"), number(&listed[1], "reach"));
    assert_eq!(number(&gnu[0], "dynsym"), number(&listed[0], "dynsym"));
}

/// Every chain word equals the hash of the name it stands for, checked by arithmetic the panel cannot
/// fake: the runs are contiguous, their heads step forward, and their lengths add out.
#[test]
fn every_chain_word_belongs_to_the_name_and_bucket_it_sits_in() {
    let listed = rows("hgnu.so");
    let floor = number(&listed[1], "floor");
    let mut previous = 0u64;
    let mut total = 0u64;
    for row in listed.iter().skip(2).filter(|one| one.starts_with("bucket\t")) {
        let head = cell(row, "head").expect("a head");
        let length = number(row, "length");
        if head == "-" {
            continue;
        }
        let head = head.parse().expect("an index");
        assert!(head >= floor, "{row} starts below the floor");
        assert!(head > previous || previous == 0, "{row} runs backwards past {previous}");
        previous = head;
        total += length;
    }
    assert_eq!(total, number(&listed[1], "reach"));
    // And the table that lists nothing still says so: one bucket, no head, no chain.
    let empty = rows("note.elf");
    assert_eq!(
        empty,
        [
            "hash\ttables\t1\tdynsym\t1\tbits\t64\tgnu\t1\tsysv\t0",
            "table\t0\tkind\tgnu\toff\t856\tbytes\t28\tinfo\t0\tbuckets\t1\tchains\t0\tsymoffset\t1\tmasks\t1\twordsize\t8\tempty\t1\treach\t0\tfloor\t1",
            "bucket\t0\t0\thead\t-\tlength\t0",
        ]
    );
}

/// Both tables in one file, the 32-bit build of the same, and every reason to answer with nothing.
#[test]
fn every_table_the_readers_listed_comes_back_the_same_way() {
    for name in ["hgnu.so", "hsys.so", "hboth.so", "hboth32.so", "lab.so", "libuser.so", "note.elf",
                 "lab.elf"] {
        assert_eq!(difference(name), "", "{name} does not match the readers");
    }
    // The two tables of one file disagree about nothing: the same symbols, reached both ways.
    let both = rows("hboth.so");
    let gnu = &both[both.iter().position(|one| one.starts_with("table\t0\tkind\tgnu")).expect("a gnu row")];
    let sysv = &both[both.iter().position(|one| one.starts_with("table\t1\tkind\tsysv")).expect("a sysv row")];
    assert_eq!(number(gnu, "reach"), number(sysv, "reach"));
    // The 32-bit build of the same source says the same thing about 91 symbols, and differs in the
    // width of its mask words - 64 where the 64-bit file needs 32.
    let thin = rows("hboth32.so");
    let thin_row = &thin[thin.iter().position(|one| one.contains("kind\tgnu")).expect("a gnu row")];
    assert_eq!(number(thin_row, "reach"), number(gnu, "reach"));
    assert_eq!(number(thin_row, "wordsize"), 4);
    assert_eq!(number(gnu, "wordsize"), 8);
    assert_eq!(number(thin_row, "masks"), 64);
    assert_eq!(number(gnu, "masks"), 32);
    for name in ["res.dll", "answer.obj"] {
        assert_eq!(probe_rows(name), Vec::<String>::new(), "{name} grew a hash table in the probe");
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect(name);
        assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
        assert_eq!(hash_count(), 0, "{name} was given an ELF hash table");
    }
}
