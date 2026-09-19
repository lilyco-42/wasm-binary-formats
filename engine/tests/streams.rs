//! Compressed-stream framing tests.
//!
//! Every fixture is produced by the reference command-line tool for that format - `xz`, `bzip2`,
//! `lz4`, `zstd`, `gzip` - and each file is round-tripped by the same tool before it is committed.
//! The expectations below are the bytes those tools produced, read with `xxd`, not a recollection of
//! the specification: writing this file corrected two such recollections (the .xz footer ends with
//! the two bytes "YZ", and the bzip2 block magic is byte-aligned right after the level digit).

use apk_lens::streams::{
    count, field, kind, parse, FORMAT_BZIP2, FORMAT_GZIP, FORMAT_LZ4, FORMAT_XZ, FORMAT_ZSTD,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}{}", FIXTURES, name);
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-stream-fixtures.sh: {error}")
    })
}

fn fields() -> Vec<String> {
    (0..count()).filter_map(field).collect()
}

fn value(named: &str) -> i64 {
    let line = fields()
        .into_iter()
        .find(|entry| entry.starts_with(named))
        .unwrap_or_else(|| panic!("no field named {named} in the report"));
    line.split('\t')
        .nth(1)
        .unwrap_or_default()
        .parse()
        .unwrap_or(-1)
}

#[test]
fn reads_the_xz_stream_a_real_xz_wrote() {
    let xz = fixture("tiny.xz");
    assert_eq!(parse(&xz), FORMAT_XZ);
    assert_eq!(kind(), FORMAT_XZ, "kind() must agree with the return code");
    assert_eq!(
        value("checkType"),
        4,
        "stream flags byte 1 is the check type"
    );
    assert_eq!(value("blockHeaderSize"), 20, "(first byte + 1) * 4 for this block");
    assert_eq!(value("backwardSize"), 2, "index size / 4 - 1");
    assert_eq!(value("indexSize"), 12);
    assert_eq!(
        value("footerMagic"),
        0x5a59,
        "the footer is the two bytes YZ, little-endian"
    );
}

#[test]
fn reads_the_bzip2_stream_a_real_bzip2_wrote() {
    let bz = fixture("tiny.bz2");
    assert_eq!(parse(&bz), FORMAT_BZIP2);
    assert_eq!(
        value("level"),
        1,
        "the digit after BZh is the 100k block multiplier"
    );
    assert_eq!(value("nominalBlockSize"), 100_000);
    assert_eq!(
        fields()[1],
        format!("blockMagic\t{:#x}", 0x3141_5926_5359u64)
    );
}

#[test]
fn reads_the_lz4_frame_a_real_lz4_wrote() {
    let lz4 = fixture("tiny.lz4");
    assert_eq!(parse(&lz4), FORMAT_LZ4);
    assert_eq!(value("version"), 1);
    assert_eq!(value("blockIndep"), 1);
    assert_eq!(
        value("contentChecksum"),
        0,
        "the fixture was written with --no-crc"
    );
    assert_eq!(
        value("blockMaxSize"),
        64 * 1024,
        "BD bits 4-6 select 4 = 64 KiB"
    );
}

#[test]
fn reads_the_zstd_frame_a_real_zstd_wrote() {
    let zst = fixture("tiny.zst");
    assert_eq!(parse(&zst), FORMAT_ZSTD);
    assert_eq!(value("frameHeaderDescriptor"), 0x60);
    assert_eq!(value("windowDescriptor"), 0xbc);
}

#[test]
fn reads_the_gzip_member_a_real_gzip_wrote() {
    let gz = fixture("tiny.gz");
    assert_eq!(parse(&gz), FORMAT_GZIP);
    assert_eq!(value("method"), 8, "deflate");
    assert_eq!(
        value("flags") & 0x08,
        0x08,
        "FNAME is set because the tool stored the file name"
    );
}

#[test]
fn rejects_short_and_unrelated_buffers() {
    assert_eq!(parse(b"tiny"), -1, "shorter than any header");
    assert_eq!(parse(&vec![b'q'; 64]), -2, "no known magic");
    assert_eq!(
        count(),
        0,
        "a rejection must not leave fields from the previous stream"
    );
    assert_eq!(kind(), 0);
}
