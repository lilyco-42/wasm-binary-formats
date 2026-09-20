//! JPEG 2000 PCA containers: the box list, the `jp2h` superbox, and the two boxes that describe the
//! image.
//!
//! `test/fixtures/{tiny,rgba,grey}.jp2` are encoded by Pillow through its openjpeg-backed writer
//! (`scripts/make-jp2-fixtures.py`), and the generator refuses to commit a file Pillow cannot open
//! again with the same size and mode - which is the witness for the two `ihdr` surprises below.
//! `jp2.probe.json` records the box lengths and field values read off the finished bytes.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_JP2};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-jp2-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn box_of(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(8 + body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(body);
    out
}

fn signature() -> Vec<u8> {
    box_of("jP  ", &[0x0D, 0x0A, 0x87, 0x0A])
}

fn header(height: u32, width: u32, components: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&width.to_be_bytes());
    body.extend_from_slice(&components.to_be_bytes());
    body.extend_from_slice(&[7, 7, 0, 0]);
    box_of("ihdr", &body)
}

#[test]
fn walks_the_boxes_and_reads_height_before_width_from_ihdr() {
    let bytes = fixture("tiny.jp2");
    assert_eq!(parse(&bytes), FORMAT_JP2);
    assert_eq!(kind(), FORMAT_JP2, "kind() must agree with the return code");
    assert_eq!(name(), "jp2", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "jp2\t316\t316\t4\t0",
            "box\tjP  \t12\t0",
            "box\tftyp\t20\t12",
            "box\tjp2h\t45\t32",
            "child\tihdr\t22\t40",
            "child\tcolr\t15\t62",
            "box\tjp2c\t239\t77",
            // The image is 32 wide and 20 tall, and `ihdr` says 20 first: reading these two as
            // width-then-height would swap them without any other row noticing.
            "ihdr\t20\t32\t3\t8\tfilter\t7",
            "colr\t1\t16",
            "walked\tend",
        ]
    );
}

#[test]
fn the_depth_byte_is_stored_one_below_the_bits_and_the_components_follow_the_mode() {
    let rgba = fixture("rgba.jp2");
    assert_eq!(parse(&rgba), FORMAT_JP2);
    let lines = report();
    assert_eq!(lines[0], "jp2\t292\t292\t4\t0");
    assert_eq!(
        lines[6], "child\tcdef\t34\t77",
        "the alpha channel brings a fourth child with it: {lines:?}"
    );
    assert_eq!(lines[8], "ihdr\t16\t16\t4\t8\tfilter\t7");
    assert_eq!(lines[9], "colr\t1\t16");

    let grey = fixture("grey.jp2");
    assert_eq!(parse(&grey), FORMAT_JP2);
    let lines = report();
    assert_eq!(lines[0], "jp2\t225\t225\t4\t0");
    assert_eq!(lines[7], "ihdr\t8\t64\t1\t8\tfilter\t7");
    assert_eq!(
        lines[8], "colr\t1\t17",
        "one component, and the enumerated colourspace number is a different one"
    );
}

#[test]
fn a_box_that_overshoots_the_file_leaves_the_walk_incomplete_and_says_so() {
    // The first three boxes of tiny.jp2, with the codestream cut short: its declared 239 bytes are
    // no longer there, so the walk stops with a count rather than reporting an end.
    let whole = fixture("tiny.jp2");
    let bytes = whole[..200].to_vec();
    assert_eq!(parse(&bytes), FORMAT_JP2);
    let lines = report();
    assert_eq!(lines[0], "jp2\t77\t200\t3\t1");
    assert_eq!(lines[3], "box\tjp2h\t45\t32");
    assert_eq!(lines[6], "ihdr\t20\t32\t3\t8\tfilter\t7");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_length_of_zero_runs_to_the_end_of_the_file_and_one_is_followed_by_a_wide_length() {
    // Self-authored: the two special forms, since no writer here produces a 4 GB JP2.
    let mut to_end = signature();
    to_end.extend_from_slice(&0u32.to_be_bytes());
    to_end.extend_from_slice(b"jp2h");
    to_end.extend_from_slice(&header(4, 6, 1));
    assert_eq!(parse(&to_end), FORMAT_JP2);
    assert_eq!(
        report(),
        vec![
            "jp2\t42\t42\t2\t0",
            "box\tjP  \t12\t0",
            "box\tjp2h\t30\t12",
            "child\tihdr\t22\t20",
            "ihdr\t4\t6\t1\t8\tfilter\t7",
            "walked\tend",
        ]
    );

    let mut wide = signature();
    wide.extend_from_slice(&1u32.to_be_bytes());
    wide.extend_from_slice(b"ftyp");
    wide.extend_from_slice(&24u64.to_be_bytes());
    wide.extend_from_slice(&[0u8; 8]);
    assert_eq!(parse(&wide), FORMAT_JP2);
    assert_eq!(
        report(),
        vec![
            "jp2\t36\t36\t2\t0",
            "box\tjP  \t12\t0",
            "box\tftyp\t24\t12",
            "walked\tend",
        ],
        "the wide length is big-endian, like every other integer in this format"
    );
}

#[test]
fn a_box_shorter_than_its_own_header_stops_the_walk() {
    let mut bytes = signature();
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(b"junk");
    assert_eq!(parse(&bytes), FORMAT_JP2);
    let lines = report();
    assert_eq!(lines[0], "jp2\t12\t20\t1\t1");
    assert_eq!(lines[1], "box\tjP  \t12\t0");
    assert_eq!(lines.len(), 2, "nothing after a broken length: {lines:?}");
}

#[test]
fn a_foreign_or_truncated_file_is_not_a_jp2_container() {
    let mut wrong = signature();
    wrong[8] = 0x00;
    assert_eq!(parse(&wrong), -2, "the signature bytes decide");
    assert_eq!(
        parse(b"jP  \x00\x00\x00\x0c\x0d\x0a\x87\x0a"),
        -2,
        "reversed header order"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no box tag");
    assert_eq!(
        parse(&signature()[..10]),
        -2,
        "too short for a signature box"
    );
}
