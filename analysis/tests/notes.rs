//! What an ELF's notes say, checked against `readelf -nW` and `llvm-readobj --notes`.
//!
//! `test/fixtures/note.probe.json` comes from `scripts/make-note-fixtures.py`, which compiles the same
//! four lines of C three ways: once for an object file, once linked with `-fcf-protection=full` and a
//! build ID, once with `-fcf-protection=branch` alone. A fourth file carries a note written by hand in
//! assembly. A row reaches the probe only where the byte walk, binutils and LLVM agree on the owner, the
//! descriptor length, the type word and the decoded payload.
//!
//! Two things the fixtures settled. A note's name and descriptor are each rounded up to a multiple of
//! four, and that is the only thing separating one note from the next: the hand-written pair has a
//! four-byte name and a five-byte descriptor, so the second note begins eight bytes past where it is
//! declared rather than five, and both listings find it there. And neither listing names a type it does
//! not know - they both say `Unknown` and print the bytes, which is why that is the word the row carries
//! and why the bytes, not an interpretation of them, are the payload.
//!
//! `note.o` exists because a relocatable object has no program headers at all: the same note is only
//! reachable through its section there, which is the other route the walk takes.

use apk_lens_analysis::{analyse, note_at, note_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-note-fixtures.py to write it: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("note.probe.json");
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
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-note-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
    let total = note_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = note_at(index, slot.as_mut_ptr(), slot.len() as i32);
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

/// The linked image: two note segments' worth of payload, one build ID and both x86 feature bits.
#[test]
fn a_linked_image_carries_the_build_id_and_the_features_it_asked_for() {
    let listed = rows("note.elf");
    assert_eq!(
        listed,
        [
            "notes\tentries\t2\tbits\t64\twalked\tsegment",
            "note\t0\tkind\tsegment\tplace\tPT_NOTE\tnamesz\t4\tdescsz\t20\ttype\t0x3\towner\tGNU\tword\tNT_GNU_BUILD_ID\ttext\t3b360ec6488de7e3c0a0c36b78b67d83f9f78962",
            "note\t1\tkind\tsegment\tplace\tPT_NOTE\tnamesz\t4\tdescsz\t16\ttype\t0x5\towner\tGNU\tword\tNT_GNU_PROPERTY_TYPE_0\ttext\tx86 feature: IBT, SHSTK",
            "prop\t1\t0\ttype\t0xc0000002\tbytes\t4\tvalue\t0x3",
        ]
    );
    // The feature word is a reading of the record beside it, so the two have to say the same thing:
    // IBT is bit 0 and SHSTK bit 1 of a four-byte value.
    let value = u64::from_str_radix(&cell(&listed[3], "value").expect("a value").replace("0x", ""), 16).expect("hex");
    let text = cell(&listed[2], "text").expect("a spelling");
    assert_eq!(value, 3);
    assert_eq!(text, "x86 feature: IBT, SHSTK");
    // A build ID is 20 bytes, and both listings print it as 40 hex digits.
    assert_eq!(cell(&listed[1], "text").expect("an id").len(), 40);
}

/// The branch-only build: the same note kind with one bit fewer, which is the difference between what
/// the file says and what a reader that always claims both would say.
#[test]
fn the_second_feature_bit_is_only_claimed_when_the_file_sets_it() {
    let both = rows("note.elf");
    let one = rows("note1.elf");
    assert_eq!(
        cell(&one[1], "text").expect("a spelling"),
        "x86 feature: IBT",
        "a file built for branch tracking alone grew a second feature"
    );
    assert_eq!(cell(&one[2], "value").expect("a record"), "0x1");
    assert_eq!(
        cell(&both[2], "text").expect("a spelling"),
        "x86 feature: IBT, SHSTK",
        "and the full build lost one"
    );
    assert_eq!(cell(&one[0], "entries").expect("a count"), "1");
    assert!(cell(&one[1], "word").expect("a word") == "NT_GNU_PROPERTY_TYPE_0");
    // The build ID is a link option, so its absence is the file's, not the reader's.
    assert!(!one.iter().any(|row| row.contains("NT_GNU_BUILD_ID")));
}

/// The hand-written pair: two notes in one stretch of bytes, whose boundary is only recoverable by
/// rounding each field up to four - and which neither listing can name.
#[test]
fn notes_are_told_apart_by_their_padding_and_stay_unnamed_when_no_listing_names_them() {
    let listed = rows("notelab.elf");
    assert_eq!(
        listed,
        [
            "notes\tentries\t3\tbits\t64\twalked\tsegment",
            "note\t0\tkind\tsegment\tplace\tPT_NOTE\tnamesz\t4\tdescsz\t5\ttype\t0x1234\towner\tLAB\tword\tUnknown\ttext\t4142434445",
            "note\t1\tkind\tsegment\tplace\tPT_NOTE\tnamesz\t2\tdescsz\t4\ttype\t0x7\towner\tQ\tword\tUnknown\ttext\t78797a00",
            "note\t2\tkind\tsegment\tplace\tPT_NOTE\tnamesz\t4\tdescsz\t16\ttype\t0x5\towner\tGNU\tword\tNT_GNU_PROPERTY_TYPE_0\ttext\tx86 feature: IBT",
            "prop\t2\t0\ttype\t0xc0000002\tbytes\t4\tvalue\t0x1",
        ]
    );
    // A five-byte descriptor followed by a two-byte name: the second note is at 24, not 21, and the
    // third - which is a real GNU note both listings decode - follows it at 44. If either offset were
    // computed without rounding, note 2 would not read as `NT_GNU_PROPERTY_TYPE_0`.
    assert_eq!(cell(&listed[2], "namesz").expect("a length"), "2", "the second note's name kept its padding");
    assert_eq!(cell(&listed[2], "owner").expect("an owner"), "Q");
    assert_eq!(cell(&listed[3], "word").expect("a word"), "NT_GNU_PROPERTY_TYPE_0");
    // Nothing interprets an unknown payload: the row carries the bytes, not a reading of them.
    assert_eq!(cell(&listed[2], "text").expect("a payload"), "78797a00");
}

/// The object file has no program headers, so its note is reached through its section - and named by it.
#[test]
fn an_object_reaches_the_same_note_through_its_section() {
    let listed = rows("note.o");
    assert_eq!(
        listed,
        [
            "notes\tentries\t1\tbits\t64\twalked\tsection",
            "note\t0\tkind\tsection\tplace\t.note.gnu.property\tnamesz\t4\tdescsz\t16\ttype\t0x5\towner\tGNU\tword\tNT_GNU_PROPERTY_TYPE_0\ttext\tx86 feature: IBT",
            "prop\t0\t0\ttype\t0xc0000002\tbytes\t4\tvalue\t0x1",
        ]
    );
    // The same statement the linked image makes about its own bytes, seen the other way round.
    let image = rows("note1.elf");
    for (one, two) in listed.iter().skip(1).zip(image.iter().skip(1)) {
        assert_eq!(cell(one, "text"), cell(two, "text"), "{one} and {two} disagree");
        assert_eq!(cell(one, "type"), cell(two, "type"), "{one} and {two} disagree");
    }
    assert_eq!(cell(&listed[0], "walked").expect("a route"), "section");
    assert_eq!(cell(&image[0], "walked").expect("a route"), "segment");
}

/// Every file, row for row, against both listings.
#[test]
fn every_note_the_listings_read_comes_back_the_same_way() {
    for name in ["note.elf", "note1.elf", "notelab.elf", "note.o"] {
        assert_eq!(difference(name), "", "{name} does not match the listings");
    }
    // An ELF linked without notes, a PE, and a COFF object: three different reasons to answer nothing.
    for name in ["lab.elf", "res.dll", "answer.obj"] {
        assert_eq!(probe_rows(name), Vec::<String>::new(), "{name} grew notes in the probe");
    }
    for name in ["lab.elf", "res.dll", "answer.obj", "tls.dll"] {
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect(name);
        assert!(analyse(&bytes).is_some(), "{name} has to be an object file");
        assert_eq!(note_count(), 0, "{name} was given notes it does not carry");
    }
}
