//! HDF5: the superblock, its two widths, and the addresses inside it that sign what they point at.
//!
//! `test/fixtures/{tree-v0,links-v3}.h5` are written by h5py twice over, once with `libver=earliest`
//! and once with `libver=latest`, so the old symbol-table superblock (v0, with its B-tree and local
//! heap) and the modern one (v3, whose root is an `OHDR` object header) are both real library output
//! from the same writer - and h5py opens both again and the datasets and attribute are checked before
//! either file is committed (`scripts/make-h5-fixtures.py`, whose probe lists every slot it found).
//!
//! Deliberately absent: a field-by-field walk of the superblock and any traversal below the root
//! group. The generations lay the fields out differently, the object-header message kinds are a table
//! these two files cannot verify, and B-tree/heap/link walking is its own piece of work. What this
//! reader *does* claim is checkable from the bytes: the two widths, and for every 64-bit slot either
//! that it equals the file's length (the `eof` row, which is what `walked end` rests on) or that the
//! address it holds points at four ASCII letters - the signature HDF5 gives each of its structures.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_H5};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-h5-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

#[test]
fn the_old_superblock_points_at_a_btree_and_a_local_heap() {
    let bytes = fixture("tree-v0.h5");
    assert_eq!(parse(&bytes), FORMAT_H5);
    assert_eq!(kind(), FORMAT_H5, "kind() must agree with the return code");
    assert_eq!(name(), "h5", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "h5\t0\t8\t8\t29\t4",
            "eof\t40\t10240\tfile\t10240",
            "addr\t80\t136\tsig\tTREE",
            "addr\t88\t680\tsig\tHEAP",
            "addr\t120\t136\tsig\tTREE",
            "walked\tend",
        ],
        "the superblock's own slots name the structures they point at"
    );
}

#[test]
fn the_modern_superblock_points_at_an_object_header_instead() {
    let bytes = fixture("links-v3.h5");
    assert_eq!(parse(&bytes), FORMAT_H5);
    assert_eq!(
        report(),
        vec![
            "h5\t3\t8\t8\t29\t2",
            "eof\t28\t6236\tfile\t6236",
            "addr\t36\t48\tsig\tOHDR",
            "walked\tend",
        ]
    );
}

#[test]
fn the_two_width_positions_are_told_apart_by_the_version_byte() {
    // Both files say 8 and 8, but they say it in different places: reading one where the other keeps
    // its widths yields zero, which is not an address width, so a reader that picked one position
    // would reject the other generation outright.
    let mut old = fixture("tree-v0.h5");
    old[13] = 0;
    old[14] = 0;
    assert_eq!(parse(&old), -2, "v0 widths are at 13 and 14");
    let mut modern = fixture("links-v3.h5");
    modern[9] = 0;
    modern[10] = 0;
    assert_eq!(parse(&modern), -2, "v3 widths are at 9 and 10");
    assert_eq!(parse(&fixture("tree-v0.h5")), FORMAT_H5);
    assert_eq!(parse(&fixture("links-v3.h5")), FORMAT_H5);
}

#[test]
fn a_superblock_that_no_longer_describes_the_file_loses_its_end() {
    // The pointers are still real; only the claim about where the file ends is withdrawn.
    let mut bytes = fixture("links-v3.h5");
    let shifted = 6236u64 + 8;
    bytes[28..36].copy_from_slice(&shifted.to_le_bytes());
    assert_eq!(parse(&bytes), FORMAT_H5);
    let lines = report();
    assert_eq!(lines[0], "h5\t3\t8\t8\t29\t1");
    assert!(
        !lines.iter().any(|line| line.starts_with("eof\t")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "addr\t36\t48\tsig\tOHDR"),
        "{lines:?}"
    );
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_version_byte_beyond_the_known_ones_is_not_claimed() {
    for byte in 4..=8 {
        let mut bytes = fixture("links-v3.h5");
        bytes[8] = byte;
        assert_eq!(parse(&bytes), -2, "superblock version {byte} is not read");
    }
    let mut signed = fixture("links-v3.h5");
    signed[1] = b'X';
    assert_eq!(parse(&signed), -2, "the signature has to be HDF");
    assert_eq!(
        parse(b"\x89HDF\r\n\x1a\n\x03\x08\x08"),
        -2,
        "too short for widths"
    );
    assert_eq!(parse(&[0u8; 128]), -2, "zero bytes carry no HDF5 signature");
}
