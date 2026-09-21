//! The Segments window: the program headers four real ELF files hand their loader.
//!
//! `test/fixtures/segment.probe.json` is written by `scripts/make-segment-fixtures.py`, which reads every
//! header three times - the bytes at `e_phoff`, `readelf -lW`, and `llvm-readobj --segments` - and refuses
//! to write a row unless the three agree on the offsets, both addresses, both sizes and the alignment, and
//! unless the two readers use the same word for the type (LLVM's being readelf's with `PT_` in front). What
//! is asserted below is therefore those programs' listing of these files, not this reader's.
//!
//! The two traps the fixtures exist to catch are both field-position ones: a 32-bit record puts `p_flags`
//! between `p_memsz` and `p_align` where a 64-bit record puts it second, and the data encoding comes from
//! `e_ident` rather than from the class. Read either the same way for both files and `lab32.so`'s first
//! segment reports a permission word as its file offset.

use apk_lens_analysis::{analyse, segment_at, segment_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-segment-fixtures.py: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object");
    let total = segment_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = segment_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// A freestanding image states four headers, two of them loadable and one of those executable, and 615
/// bytes to map - which is the sum of `p_memsz`, so a `NOBITS` tail would be counted here and not in the
/// file's `filesz`.
#[test]
fn a_static_image_lists_the_four_ranges_its_loader_is_handed() {
    assert_eq!(
        rows("lab.elf"),
        vec![
            "segments\ttotal\t4\tload\t2\twritable\t1\texec\t1\tmapped\t615\tbits\t64",
            "segment\t0\ttype\t6\tname\tPHDR\toff\t64\tvaddr\t0x200040\tpaddr\t0x200040\tfilesz\t224\tmemsz\t224\tflags\tr--\talign\t8",
            "segment\t1\ttype\t1\tname\tLOAD\toff\t0\tvaddr\t0x200000\tpaddr\t0x200000\tfilesz\t385\tmemsz\t385\tflags\tr--\talign\t4096",
            "segment\t2\ttype\t1\tname\tLOAD\toff\t400\tvaddr\t0x201190\tpaddr\t0x201190\tfilesz\t6\tmemsz\t6\tflags\tr-x\talign\t4096",
            "segment\t3\ttype\t1685382481\tname\tGNU_STACK\toff\t0\tvaddr\t0x0\tpaddr\t0x0\tfilesz\t0\tmemsz\t0\tflags\trw-\talign\t0",
        ]
    );
}

/// Nine headers, of which four are `LOAD`: the fourth's `memsz` is bigger than its `filesz` because the
/// linker asked for room the file does not fill, and the `GNU_RELRO` record shares an address with a
/// `LOAD` on purpose - it names the part of it that gets protected after relocation.
#[test]
fn a_shared_object_shows_the_load_segments_and_the_kinds_that_overlap_them() {
    let listed = rows("lab.so");
    assert_eq!(listed.len(), 10, "a different number of rows: {listed:#?}");
    assert_eq!(
        listed[0],
        "segments\ttotal\t9\tload\t4\twritable\t4\texec\t1\tmapped\t7596\tbits\t64"
    );
    assert_eq!(
        listed[4],
        "segment\t3\ttype\t1\tname\tLOAD\toff\t1440\tvaddr\t0x25a0\tpaddr\t0x25a0\tfilesz\t264\tmemsz\t2656\tflags\trw-\talign\t4096"
    );
    assert_eq!(
        listed[7],
        "segment\t6\ttype\t1685382482\tname\tGNU_RELRO\toff\t1440\tvaddr\t0x25a0\tpaddr\t0x25a0\tfilesz\t264\tmemsz\t2656\tflags\tr--\talign\t1"
    );
    assert_eq!(
        listed[9],
        "segment\t8\ttype\t1685382481\tname\tGNU_STACK\toff\t0\tvaddr\t0x0\tpaddr\t0x0\tfilesz\t0\tmemsz\t0\tflags\trw-\talign\t0"
    );
}

/// The 32-bit file is the one that catches the field-position trap: its first record's offset is 52, its
/// permission word is `r--`, and its alignment is 4 - a reading that took the words in the 64-bit order
/// would print the flags as an offset or the offset as an alignment. The page size is 4096 here and 65 536
/// in the aarch64 file below, because the two linkers were asked for their own defaults.
#[test]
fn a_thirty_two_bit_record_is_read_at_its_own_field_positions() {
    let listed = rows("lab32.so");
    assert_eq!(listed.len(), 10, "{listed:#?}");
    assert_eq!(
        listed[0],
        "segments\ttotal\t9\tload\t4\twritable\t4\texec\t1\tmapped\t7652\tbits\t32"
    );
    assert_eq!(
        listed[1],
        "segment\t0\ttype\t6\tname\tPHDR\toff\t52\tvaddr\t0x34\tpaddr\t0x34\tfilesz\t288\tmemsz\t288\tflags\tr--\talign\t4"
    );
    assert_eq!(
        listed[5],
        "segment\t4\ttype\t1\tname\tLOAD\toff\t1140\tvaddr\t0x3474\tpaddr\t0x3474\tfilesz\t44\tmemsz\t48\tflags\trw-\talign\t4096"
    );
    assert_eq!(
        listed[6],
        "segment\t5\ttype\t2\tname\tDYNAMIC\toff\t1008\tvaddr\t0x23f0\tpaddr\t0x23f0\tfilesz\t112\tmemsz\t112\tflags\trw-\talign\t4"
    );
}

/// The aarch64 file is the same nine headers with the linker's own 65 536 page size, which is the one
/// column in this window that a different machine answers differently.
#[test]
fn the_aarch64_file_is_the_same_table_with_its_own_alignment() {
    let listed = rows("labarm.so");
    assert_eq!(
        listed[0],
        "segments\ttotal\t9\tload\t4\twritable\t4\texec\t1\tmapped\t7560\tbits\t64"
    );
    assert_eq!(
        listed[2],
        "segment\t1\ttype\t1\tname\tLOAD\toff\t0\tvaddr\t0x0\tpaddr\t0x0\tfilesz\t1252\tmemsz\t1252\tflags\tr--\talign\t65536"
    );
}

/// A PE and a COFF object have no program header table, so the window answers with nothing at all rather
/// than translating sections into headers they do not have - the loader's contract for those is the
/// section table and the image base, which the panels above already report.
#[test]
fn a_pe_names_no_segments_because_the_format_has_no_header_table() {
    for file in ["exp.dll", "lab.dll", "answer.obj"] {
        let listed = rows(file);
        assert!(listed.is_empty(), "{file} listed segments it cannot have: {listed:#?}");
    }
}
