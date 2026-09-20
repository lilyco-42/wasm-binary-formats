//! QOI: the header, and the pixel accounting that says the chunk stream really was read.
//!
//! `test/fixtures/{tiny,srgb,all6}.qoi` are encoded by Pillow (`scripts/make-qoi-fixtures.py`),
//! which also decodes them back, and `qoi.probe.json` records the chunk classes counted off the
//! finished bytes. `all6.qoi` is the one that matters for the walk: its bands were built so that
//! Pillow's encoder would use all six chunk classes, so the row below with six non-zero-ish counts
//! is a claim about the classifier rather than about a single convenient file.
//!
//! QOI has no unknown tags - every byte value names a chunk - so there is no "unrecognized marker"
//! to fall back on. What a hostile file can break instead is the length, and the three cases here
//! are exactly that: a stream that walks past the pixel count the header claims, a chunk whose body
//! would have to overlap the terminator, and a terminator that is not there.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_QOI};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-qoi-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

/// `qoif`, width, height, channels, colourspace, then a body and the standard terminator.
fn qoi(width: u32, height: u32, channels: u8, colorspace: u8, body: &[u8]) -> Vec<u8> {
    let mut out = b"qoif".to_vec();
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(channels);
    out.push(colorspace);
    out.extend_from_slice(body);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    out
}

#[test]
fn reads_the_chunks_pillow_encoded_and_accounts_for_every_pixel() {
    let bytes = fixture("tiny.qoi");
    assert_eq!(parse(&bytes), FORMAT_QOI);
    assert_eq!(kind(), FORMAT_QOI, "kind() must agree with the return code");
    assert_eq!(name(), "qoi", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "qoi\t8\t6\t4\t1",
            "chunks\t2\trgb\t1\targb\t0\tindex\t0\tdiff\t0\tluma\t0\trun\t1",
            "pixels\t48\twalked\t48\tterminator\t1",
            "stopped\t0\tnone",
            "walked\tend",
        ],
        "one RGB pixel then a run of 47 is the whole 8x6 image"
    );
}

#[test]
fn the_colour_and_channels_bytes_are_read_as_single_bytes() {
    // Pillow only writes colourspace 0 when the caller asks for sRGB, so the two 27-byte fixtures
    // differ in those two bytes and in nothing else. Reading them as a u32 would print 167772160.
    let srgb = fixture("srgb.qoi");
    assert_eq!(parse(&srgb), FORMAT_QOI);
    assert_eq!(report()[0], "qoi\t8\t6\t3\t0");
    let tiny = fixture("tiny.qoi");
    assert_eq!(parse(&tiny), FORMAT_QOI);
    assert_eq!(report()[0], "qoi\t8\t6\t4\t1");
}

#[test]
fn classifies_all_six_chunk_kinds_from_one_encoders_output() {
    let bytes = fixture("all6.qoi");
    assert_eq!(parse(&bytes), FORMAT_QOI);
    assert_eq!(
        report(),
        vec![
            "qoi\t64\t8\t4\t1",
            "chunks\t296\trgb\t11\targb\t14\tindex\t162\tdiff\t28\tluma\t1\trun\t80",
            "pixels\t512\twalked\t512\tterminator\t1",
            "stopped\t0\tnone",
            "walked\tend",
        ],
        "the six classes have to come out apart, and the pixels add up"
    );
}

#[test]
fn a_stream_past_the_pixels_the_header_claims_is_an_overrun() {
    // Self-authored: one pixel claimed, a run of ten written.
    let bytes = qoi(1, 1, 3, 0, &[0xC0 + 9]);
    assert_eq!(parse(&bytes), FORMAT_QOI);
    let lines = report();
    assert_eq!(lines[0], "qoi\t1\t1\t3\t0");
    assert_eq!(lines[2], "pixels\t1\twalked\t10\tterminator\t1");
    assert_eq!(lines[3], "stopped\t1\toverrun");
    assert_eq!(lines.len(), 4, "an overrun never claims the end: {lines:?}");
}

#[test]
fn a_chunk_that_would_reach_into_the_terminator_stops_the_walk() {
    // Self-authored: an RGB chunk needs four bytes and the object area holds one.
    let bytes = qoi(1, 1, 3, 0, &[0xFE]);
    assert_eq!(parse(&bytes), FORMAT_QOI);
    let lines = report();
    assert_eq!(
        lines[1],
        "chunks\t0\trgb\t0\targb\t0\tindex\t0\tdiff\t0\tluma\t0\trun\t0"
    );
    assert_eq!(lines[2], "pixels\t1\twalked\t0\tterminator\t1");
    assert_eq!(lines[3], "stopped\t1\tshort");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_terminator_that_is_not_there_is_said_without_blaming_the_walk() {
    // The chunk stream is still complete; only the last byte of the file is wrong.
    let mut bytes = fixture("tiny.qoi");
    let last = bytes.len() - 1;
    bytes[last] = 0;
    assert_eq!(parse(&bytes), FORMAT_QOI);
    let lines = report();
    assert_eq!(lines[2], "pixels\t48\twalked\t48\tterminator\t0");
    assert_eq!(lines[3], "stopped\t0\tnone");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn the_chunk_budget_is_a_stop_not_a_hang() {
    // A million single-byte index chunks: the walk has to give up and say so rather than read an
    // unbounded stream, and a file can be made to ask for exactly that.
    let body = vec![0x00u8; (1 << 20) + 1];
    let bytes = qoi(1024, 1024, 3, 0, &body);
    assert_eq!(parse(&bytes), FORMAT_QOI);
    let lines = report();
    assert_eq!(
        lines[1],
        "chunks\t1048576\trgb\t0\targb\t0\tindex\t1048576\tdiff\t0\tluma\t0\trun\t0"
    );
    assert_eq!(lines[3], "stopped\t1\tbudget");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_short_or_foreign_file_is_not_a_qoi_image() {
    assert_eq!(
        parse(b"qoif\x00\x00\x00\x08\x00\x00\x00\x06\x03\x01"),
        -2,
        "no terminator room"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no qoif magic");
    assert_eq!(
        parse(&qoi(0, 0, 3, 0, &[])),
        FORMAT_QOI,
        "a 0x0 image is still a QOI header"
    );
    let lines = report();
    assert_eq!(lines[0], "qoi\t0\t0\t3\t0");
    assert_eq!(lines[2], "pixels\t0\twalked\t0\tterminator\t1");
    assert!(lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}
