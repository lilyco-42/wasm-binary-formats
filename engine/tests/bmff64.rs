//! ISO base-media lengths that do not fit in 32 bits - the one part of this family that no ordinary
//! file exercises.
//!
//! `test/fixtures/tet.stl`-shaped gaps are the same in every reader: a format has a form that real
//! writers rarely emit, so the code that handles it is never run. Here it is the size-1 box header,
//! where the length moves to a 64-bit slot *after* the type, and the version-1 `mvhd`, where the same
//! widening happens to the times. `test/fixtures/wide.mov` is built in
//! `scripts/make-bmff-wide-fixture.py` to carry both, and it is built by hand because a 64-bit box in
//! the wild means a file over 4 GB, which this lab does not have.
//!
//! That would be a self-assertion if the file were only read here, so the fixture is checked against
//! two other implementations before it is committed: `mutagen` parses the same header with
//! `struct.unpack(">Q", ...)` at box + 8 and reports the box as 48 bytes at 148, and `ffprobe` reads
//! the version-1 64-bit creation stamp back as the date that was written into it. Both numbers are
//! recorded in `test/fixtures/wide.probe.json`. The byte order is then proved to matter rather than
//! assumed: the same file with the two 64-bit lengths reversed makes mutagen compute
//! 3,458,764,513,820,540,928 - which is what the reader used to print, because it read that slot
//! little-endian.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_BMFF};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");
/// The mdat box in `wide.mov`: size 1, then the type, then the 64-bit length at 148 + 8.
const MDAT: usize = 148;

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-bmff-wide-fixture.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_BMFF, "{} bytes", bytes.len());
    assert_eq!(
        kind(),
        FORMAT_BMFF,
        "kind() must agree with the return code"
    );
    assert_eq!(
        name(),
        "iso-base-media",
        "the reader has to name what it walked"
    );
    report()
}

fn swap_octet(bytes: &mut Vec<u8>, at: usize) {
    bytes[at..at + 8].reverse();
}

#[test]
fn reads_the_box_whose_length_does_not_fit_in_32_bits() {
    assert_eq!(
        rows(&fixture("wide.mov")),
        vec![
            "ftyp\tisom\t512",
            "brand\tisom",
            "box\tftyp\t20\t0",
            "box\tmoov\t128\t20",
            "child\tmvhd\t120\t28",
            "duration\t44100\t110250\t2500",
            "box\tmdat\t48\t148\twide",
            "walked\tend",
        ]
    );
}

#[test]
fn a_little_endian_reading_of_the_same_eight_bytes_is_a_different_number() {
    // The regression this fixture exists for: read at box + 8 little-endian and the length of a
    // 48-byte box becomes 3.4 exabytes, which mutagen also computes from the same reversed bytes.
    let mut bytes = fixture("wide.mov");
    swap_octet(&mut bytes, MDAT + 8);
    let lines = rows(&bytes);
    assert_eq!(
        lines[lines.len() - 1],
        "box\tmdat\t3458764513820540928\t148\twide"
    );
    assert_eq!(lines.len(), 7, "the walk stops where the box says it does");
    assert!(
        !lines.iter().any(|line| line == "walked\tend"),
        "a box longer than the file cannot be walked to the end: {lines:?}"
    );
}

#[test]
fn a_length_beyond_i64_answers_as_zero_rather_than_wrapping() {
    // A negative i64 would become a huge usize through `as`, and `cursor + size` with it.
    let mut bytes = fixture("wide.mov");
    bytes[MDAT + 8] = 0xFF;
    let lines = rows(&bytes);
    assert_eq!(lines[lines.len() - 1], "box\tmdat\t0\t148\twide");
    assert_eq!(lines.len(), 7);
}

#[test]
fn the_size_zero_form_still_means_to_the_end_of_the_file() {
    let mut bytes = fixture("wide.mov");
    bytes[MDAT..MDAT + 4].copy_from_slice(&0u32.to_be_bytes());
    let lines = rows(&bytes);
    // Same 48 bytes, and no `wide`: the two forms are different statements and the row says which.
    assert_eq!(lines[lines.len() - 2], "box\tmdat\t48\t148");
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn a_version_one_header_reports_milliseconds_the_way_version_zero_does() {
    // The v1 branch reads the timescale four bytes past where v0 puts it and the duration eight wide;
    // both files have to land on the same kind of answer, and the real one is the control.
    let wide = rows(&fixture("wide.mov"));
    assert_eq!(wide[5], "duration\t44100\t110250\t2500");
    let ordinary = rows(&fixture("media.mp4"));
    assert_eq!(
        ordinary[ordinary
            .iter()
            .position(|l| l.starts_with("duration"))
            .unwrap()],
        "duration\t1000\t1000\t1000"
    );
}

#[test]
fn an_ordinary_file_says_nothing_about_wide_boxes() {
    // media.mp4 is the ffmpeg-written control: 1-second clip, every box 32-bit, walked to the end.
    assert_eq!(
        rows(&fixture("media.mp4")),
        vec![
            "ftyp\tisom\t512",
            "brand\tisom",
            "brand\tiso2",
            "brand\tavc1",
            "brand\tmp41",
            "box\tftyp\t32\t0",
            "box\tfree\t8\t32",
            "box\tmdat\t2977\t40",
            "box\tmoov\t949\t3017",
            "child\tmvhd\t108\t3025",
            "duration\t1000\t1000\t1000",
            "child\ttrak\t736\t3133",
            "child\tudta\t97\t3869",
            "walked\tend",
        ]
    );
}
