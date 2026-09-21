//! A PE's thread-local storage table, checked against the file's own account of it.
//!
//! `test/fixtures/tls.probe.json` comes from `scripts/make-tls-fixtures.py`, which builds `tls.dll` from
//! a source with seventy callbacks in it and `plain.dll` from a source with none, then writes a row only
//! where five readings agree: the script's own walk, `llvm-readobj --coff-tls-directory`, pefile's
//! `DIRECTORY_ENTRY_TLS`, the base-relocation list, and the Windows loader actually running the
//! callbacks and reporting the order it walked them in. Run that script with a Python that has `pefile`
//! installed; it is the third reader.
//!
//! Two things the fixtures settled. The four addresses in the record are virtual, not relative, and both
//! listings print them with the image base still on - so a row states the number the bytes hold, that
//! number as an RVA, and the file offset the RVA names, and this test checks the three against each other
//! rather than trusting any one. And the order of the array is the array's own: `plain.dll`'s two
//! callbacks come back with the higher address first, which a reader that sorted them would get wrong in
//! silence. The 32-bit arm of the walk has no fixture either way - no 32-bit Windows toolchain is on this
//! host - so `bits` is 64 in every row here, and `lab32.so` answers with nothing at all.

use apk_lens_analysis::{analyse, tls_at, tls_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-tls-fixtures.py to write it: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("tls.probe.json");
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
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-tls-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = tls_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = tls_at(index, slot.as_mut_ptr(), slot.len() as i32);
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
    let spelled = cell(row, key).unwrap_or_else(|| panic!("{row} has no {key}"));
    u64::from_str_radix(spelled.strip_prefix("0x").unwrap_or(&spelled), 16)
        .unwrap_or_else(|_| panic!("{key} is {spelled}, which is not a number"))
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

/// The defining file: seventy callbacks of its own, three the runtime contributes, and a list long
/// enough that the panel had to stop.
#[test]
fn a_table_of_seventy_callbacks_lists_the_first_sixty_four() {
    let listed = rows("tls.dll");
    assert_eq!(
        listed[..6],
        [
            "tls\tdir\t9\trva\t0xb040\toff\t37440\tbytes\t40\tbits\t64\tbase\t0x2f6620000\tcallbacks\t73\tzero\t0\tchar\t0x0",
            "field\tstart\tvalue\t0x2f6631000\trva\t0x11000\toff\t52224\tsection\t.tls",
            "field\tend\tvalue\t0x2f6631008\trva\t0x11008\toff\t52232\tsection\t.tls",
            "field\tindex\tvalue\t0x2f662e46c\trva\t0xe46c\toff\t-1\tsection\t.bss",
            "field\tcallbacks\tvalue\t0x2f662b868\trva\t0xb868\toff\t39528\tsection\t.rdata",
            "callback\t0\tvalue\t0x2f6621490\trva\t0x1490\toff\t2192\tsection\t.text\tname\tlab_cb_0",
        ]
    );
    assert_eq!(listed.last().expect("a last row"), "cut\tcallbacks\t73\tlisted\t64");
    // One totals row, four fields, sixty-four listed callbacks and the note that stops them.
    assert_eq!(listed.len(), 70, "the window filled a different number of rows");
    // The index has no bytes in the file at all: the loader allocates it. A reader that rounded that to
    // an offset of zero would report a real-looking address for something the file never stores.
    assert_eq!(cell(&listed[3], "off").expect("a place"), "-1");
    assert_eq!(cell(&listed[3], "section").expect("a section"), ".bss");
    // The export table names the file's own callbacks and nothing else, which is what the `-` below is.
    assert_eq!(cell(&listed[4], "name"), None, "the field rows invent a name");
}

/// A translation unit that never mentions `_Thread_local` still carries the table, because its runtime
/// supplies one - and its two callbacks come back in the array's order, not sorted by address.
#[test]
fn a_file_built_without_thread_local_data_still_has_a_table() {
    let listed = rows("plain.dll");
    assert_eq!(
        listed,
        [
            "tls\tdir\t9\trva\t0x4020\toff\t7200\tbytes\t40\tbits\t64\tbase\t0x20e8e0000\tcallbacks\t2\tzero\t0\tchar\t0x0",
            "field\tstart\tvalue\t0x20e8ea000\trva\t0xa000\toff\t11264\tsection\t.tls",
            "field\tend\tvalue\t0x20e8ea008\trva\t0xa008\toff\t11272\tsection\t.tls",
            "field\tindex\tvalue\t0x20e8e704c\trva\t0x704c\toff\t-1\tsection\t.bss",
            "field\tcallbacks\tvalue\t0x20e8e4578\trva\t0x4578\toff\t8568\tsection\t.rdata",
            "callback\t0\tvalue\t0x20e8e15c0\trva\t0x15c0\toff\t2496\tsection\t.text\tname\t-",
            "callback\t1\tvalue\t0x20e8e1590\trva\t0x1590\toff\t2448\tsection\t.text\tname\t-",
        ]
    );
    assert!(number(&listed[5], "rva") > number(&listed[6], "rva"), "the array came back sorted");
    assert!(number(&listed[5], "off") > number(&listed[6], "off"), "and sorted in the file too");
}

/// Every row that states an address states three things about it that have to agree: the number in the
/// bytes, the same number without the image base, and where that lands in the file.
#[test]
fn the_three_spellings_of_an_address_agree() {
    for name in ["tls.dll", "plain.dll"] {
        let listed = rows(name);
        let base = number(&listed[0], "base");
        for row in listed
            .iter()
            .skip(1)
            .filter(|one| one.starts_with("field\t") || one.starts_with("callback\t"))
        {
            let value = number(row, "value");
            let rva = number(row, "rva");
            assert_eq!(value.wrapping_sub(base), rva, "{name}: {row} does not subtract the base once");
            assert!(value >= base, "{name}: {row} holds an address under the image base");
            let place: i64 = cell(row, "off").expect("a place").parse().expect("a number");
            let section = cell(row, "section").expect("a section");
            if place < 0 {
                assert_ne!(section, "-", "{name}: {row} is in no section yet states an offset");
                continue;
            }
            assert_ne!(section, "-", "{name}: {row} names a byte in no section");
        }
        // The callback rows are the file's own enumeration, so their indices run from zero without a
        // gap, and the count in the totals row is the number of them - not the number listed.
        let callbacks: Vec<usize> = listed
            .iter()
            .filter(|one| one.starts_with("callback\t"))
            .enumerate()
            .map(|(index, one)| {
                assert_eq!(cell(one, "callback").expect("no such column"), index.to_string(), "a gap");
                index
            })
            .collect();
        let stated: usize = cell(&listed[0], "callbacks").expect("a count").parse().expect("a number");
        assert!(callbacks.len() <= stated, "{name}: listed {callbacks:?} of {stated}");
        if stated > callbacks.len() {
            assert_eq!(
                cell(&listed[listed.len() - 1], "callbacks").unwrap_or_else(|| panic!("{name}: no cut row")),
                stated.to_string()
            );
        }
    }
}

/// The names on the callback rows are the export table's, and they run in the order the array lists
/// them - which is the order the loader reported walking it, and the reason the list cannot be read off
/// a sorted table of functions.
#[test]
fn the_named_callbacks_are_the_exports_in_the_arrays_order() {
    let listed = rows("tls.dll");
    for index in 0..64 {
        let row = &listed[5 + index];
        let named = format!("lab_cb_{index}");
        assert_eq!(
            cell(row, "name").expect("a name column"),
            named,
            "callback {index} is not the one the source declared"
        );
        // The same address, seen through the name index the module builds for `objdump -d`: a callback is
        // a body the file exports, so the two windows have to agree on what it is called.
        assert_eq!(
            apk_lens_analysis::name_for(number(row, "value")).expect("a name for an exported body"),
            named,
            "{row} is not in the name index"
        );
    }
    // And the address order is not the name order, which is what makes the array's own order the thing
    // that has to be reported: sixty-four of these are strictly increasing, but the file's list decides
    // that rather than a sort.
    let rising = listed
        .iter()
        .skip(5)
        .take(63)
        .zip(listed.iter().skip(6).take(63))
        .filter(|(low, high)| number(low, "rva") < number(high, "rva"))
        .count();
    assert!(rising > 60, "the array came back {rising} steps up out of 63, which is not its own order");
}

/// Every file, row for row, against the five readings.
#[test]
fn every_table_the_readers_listed_comes_back_the_same_way() {
    for name in ["tls.dll", "plain.dll"] {
        assert_eq!(difference(name), "", "{name} does not match the readers");
    }
    // The negatives are four different reasons: `reloc.dll` is an image whose directory is empty,
    // `answer.obj` is an object file with no data directories at all, `lab.elf` and `lab32.so` are ELFs,
    // which keep thread-local bookkeeping in program headers, and `res.dll` is a PE32 image - the width
    // this reader has no fixture for, so it had better answer with nothing rather than guess.
    for name in ["reloc.dll", "answer.obj"] {
        assert_eq!(probe_rows(name), Vec::<String>::new(), "{name} grew a TLS table in the probe");
    }
    for name in ["reloc.dll", "answer.obj", "lab.elf", "lab32.so", "res.dll"] {
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect(name);
        assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
        assert_eq!(tls_count(), 0, "{name} was given a TLS directory it does not have");
    }
}
