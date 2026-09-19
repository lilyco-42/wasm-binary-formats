//! Netpbm reader tests.
//!
//! The binary variants come from Pillow (`scripts/make-netpbm-fixtures.py`); the ASCII one is
//! written straight from the published layout because it is the case that carries a comment inside
//! the header, which is the part of this parser a reader could plausibly get wrong. Every number
//! below was read out of the committed file first: a `P6` 5x3 pixmap is 11 header bytes plus 45
//! samples, a `P5` greymap the same header plus 15, and a `P4` bitmap 7 header bytes plus three
//! rows of one packed byte each.

use apk_lens::containers::{at, count, kind, parse, FORMAT_NETPBM};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-netpbm-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn number(lines: &[String], named: &str) -> i64 {
    let line = lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"));
    line.split('\t')
        .nth(1)
        .unwrap_or_else(|| panic!("row {line} has no value"))
        .parse()
        .unwrap_or_else(|error| panic!("row {line} is not a number: {error}"))
}

#[test]
fn reads_a_ppm_pillow_wrote_and_finds_the_sample_area() {
    let ppm = fixture("tiny.ppm");
    assert_eq!(parse(&ppm), FORMAT_NETPBM);
    assert_eq!(kind(), FORMAT_NETPBM);
    let lines = report();
    assert_eq!(lines[0], "netpbm\tP6\tbinary");
    assert_eq!(number(&lines, "width"), 5);
    assert_eq!(number(&lines, "height"), 3);
    assert_eq!(number(&lines, "maxval"), 255);
    assert_eq!(number(&lines, "header_bytes"), 11);
    assert_eq!(
        number(&lines, "payload_bytes"),
        45,
        "3 bytes per pixel, 15 pixels"
    );
    assert_eq!(number(&lines, "complete"), 1);
    // The reported header length has to be exactly where the samples start, which this checks
    // against a pixel value the fixture generator chose rather than against a constant here.
    let start = number(&lines, "header_bytes") as usize;
    assert_eq!(&ppm[start..start + 3], &[0u8, 0, 200], "the top-left pixel");
}

#[test]
fn reads_a_pgm_and_a_pbm_whose_headers_differ_by_the_maxval_line() {
    let pgm = fixture("tiny.pgm");
    assert_eq!(parse(&pgm), FORMAT_NETPBM);
    let lines = report();
    assert_eq!(lines[0], "netpbm\tP5\tbinary");
    assert_eq!(
        number(&lines, "header_bytes"),
        11,
        "same shape as the PPM header"
    );
    assert_eq!(number(&lines, "payload_bytes"), 15, "one byte per pixel");
    assert_eq!(number(&lines, "complete"), 1);

    let pbm = fixture("tiny.pbm");
    assert_eq!(parse(&pbm), FORMAT_NETPBM);
    let lines = report();
    assert_eq!(lines[0], "netpbm\tP4\tbinary");
    assert_eq!(
        number(&lines, "maxval"),
        1,
        "bitmaps have no maximum sample value"
    );
    assert_eq!(
        number(&lines, "header_bytes"),
        7,
        "the header is two numbers, not three"
    );
    assert_eq!(
        number(&lines, "payload_bytes"),
        3,
        "five pixels per row pack into one byte, three rows"
    );
    assert_eq!(pbm.len(), 10);
    assert_eq!(number(&lines, "complete"), 1);
}

#[test]
fn skips_comments_in_an_ascii_header() {
    let ppm = fixture("tiny.ppm-ascii");
    assert_eq!(parse(&ppm), FORMAT_NETPBM);
    let lines = report();
    assert_eq!(lines[0], "netpbm\tP3\tascii");
    assert_eq!(
        number(&lines, "width"),
        5,
        "the comment line must not shift the geometry"
    );
    assert_eq!(number(&lines, "height"), 3);
    assert_eq!(number(&lines, "maxval"), 255);
    assert_eq!(
        number(&lines, "payload_bytes"),
        -1,
        "ASCII sample counts are not fixed"
    );
    let start = number(&lines, "header_bytes") as usize;
    assert_eq!(
        &ppm[start..start + 1],
        b"0",
        "the sample area begins with the first value"
    );
}

#[test]
fn refuses_pam_and_truncated_headers() {
    // P7 ends its header with the token ENDHDR, so a loop that stops after five integers would
    // report a geometry from the wrong place. It is refused instead.
    let pam = b"P7\n2 3\n3 255\nENDHDR\nxyz";
    assert_ne!(parse(pam), FORMAT_NETPBM, "PAM is not read as a P6");
    // A header whose numbers are there but whose sample area is not must say so.
    let truncated = b"P6\n5 3\n255\n\x00\x00".to_vec();
    assert_eq!(parse(&truncated), FORMAT_NETPBM);
    let lines = report();
    assert_eq!(
        number(&lines, "complete"),
        0,
        "45 bytes were promised, two arrived"
    );
    assert_eq!(parse(b"P6\nx"), -1, "too short to hold a header");
}
