//! Photoshop documents, read as far as a document that never states its own length can be read.
//!
//! `test/fixtures/rgb.psd`, `grey.psd`, `rgba.psd` and `raw.psd` are written by psd-tools 1.19 - the only
//! PSD writer this lab can install - and `scripts/make-psd-fixtures.py` refuses to write its probe unless
//! **Pillow**, which is a separate implementation and cannot write these files at all, parses the same
//! header, the same `8BIM` resource ids and the same resource sizes from the same bytes. So the numbers
//! below are agreed by two programs that do not share code, and the writer's own claims are not taken on
//! trust. The RLE file's row-count sum equals its payload and the raw file's byte count equals
//! channels x height x width x depth/8, which is the whole reason either branch is worth reading: a PSD
//! has no total-length field, so the image data's arithmetic is the only self-check the format offers.
//!
//! What is deliberately not here: the layer records. psd-tools can add pixel layers, and both it and
//! ImageMagick then list those layers with correct geometry, but the file it saves declares a zero-length
//! layer section while the payload sits later in it. Writing a walker for bytes whose own header
//! mis-states where they begin would fit this reader to one library's bug, so the section is reported as a
//! span, the row says it is not decoded, and the claim is left off rather than made quietly.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_COFF, FORMAT_PSD, FORMAT_SEVENZIP};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");
const NOT_DECODED: &str =
    "layers\tnot decoded\tthe writer's own header mis-states this section, so its records are left alone";

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-psd-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_PSD, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_PSD, "kind() must agree with the return code");
    assert_eq!(name(), "psd", "the reader has to name what it walked");
    report()
}

#[test]
fn reads_the_three_shapes_that_writer_agrees_on() {
    let rgb = rows(&fixture("rgb.psd"));
    assert_eq!(
        rgb[0],
        "psd\t284\tbroken\t0\tversion\t1\treserved\t000000000000\t7x5\tchannels\t3\tdepth\t8\tmode\t3(RGB)"
    );
    assert_eq!(rgb[1], "section\tlayers\t30+0\tresources\t34+94\tcolour\t132+0\timage\t132");
    assert_eq!(rgb[2], "resource\t0\t1057(VERSION_INFO)\tsize\t81\tname\t-");
    assert_eq!(rgb[3], "image\tcompression\t1(RLE)\trows\t15\tcounts\t120\tpayload\t120\tends\tyes");
    assert_eq!(rgb[4], NOT_DECODED);
    assert_eq!(rgb[5], "walked\tend");
    assert_eq!(rgb.len(), 6, "the report grew a row nobody witnessed");

    // One channel, and the colour mode's own name: the table came out of psd-tools, not out of a memory.
    let grey = rows(&fixture("grey.psd"));
    assert_eq!(
        grey[0],
        "psd\t170\tbroken\t0\tversion\t1\treserved\t000000000000\t6x4\tchannels\t1\tdepth\t8\tmode\t1(GRAYSCALE)"
    );
    assert_eq!(grey[3], "image\tcompression\t1(RLE)\trows\t4\tcounts\t28\tpayload\t28\tends\tyes");

    // Four channels under the same colour mode: the channels column is the format's, not a side effect of
    // the mode, and the row count doubles with it.
    let rgba = rows(&fixture("rgba.psd"));
    assert_eq!(
        rgba[0],
        "psd\t294\tbroken\t0\tversion\t1\treserved\t000000000000\t5x5\tchannels\t4\tdepth\t8\tmode\t3(RGB)"
    );
    assert_eq!(rgba[3], "image\tcompression\t1(RLE)\trows\t20\tcounts\t120\tpayload\t120\tends\tyes");
}

#[test]
fn uncompressed_data_is_measured_against_the_header_rather_than_counted() {
    // No byte-count table exists in this branch, so the only number is the one the header implies:
    // 3 channels x 3 rows x 4 columns x one byte.
    let lines = rows(&fixture("raw.psd"));
    assert_eq!(
        lines[0],
        "psd\t170\tbroken\t0\tversion\t1\treserved\t000000000000\t4x3\tchannels\t3\tdepth\t8\tmode\t3(RGB)"
    );
    assert_eq!(lines[3], "image\tcompression\t0(RAW)\tbytes\t36\texpect\t36\tends\tyes");
    assert_eq!(lines[lines.len() - 1], "walked\tend");

    // Truncate one byte of pixels and the prediction stops matching - which is the whole point of the row.
    let whole = fixture("raw.psd");
    let lines = rows(&whole[..whole.len() - 1]);
    assert_eq!(lines[3], "image\tcompression\t0(RAW)\tbytes\t35\texpect\t36\tends\tno");
    assert!(lines[0].contains("\tbroken\t1\t"), "{}", lines[0]);
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
}

#[test]
fn a_file_that_cannot_hold_its_own_section_lengths_says_which_one() {
    let whole = fixture("rgb.psd");
    // 60 bytes: the header and two section lengths fit, the third does not.
    let lines = rows(&whole[..60]);
    assert_eq!(
        lines[0],
        "psd\t60\tbroken\t1\tversion\t1\treserved\t000000000000\t7x5\tchannels\t3\tdepth\t8\tmode\t3(RGB)"
    );
    assert_eq!(
        lines[1],
        "section\tlayers\t30+0\tresources\t34+94\tcolour\t128+?\timage\tunreadable"
    );
    assert_eq!(
        lines[2],
        "stopped\tbroken\t1\tcolour mode length\tdoes not fit in the file"
    );
    assert_eq!(lines.len(), 3, "a walk that stopped must not keep going");

    // 140 bytes: every section fits and the resource list is intact, but the byte-count table does not.
    let lines = rows(&whole[..140]);
    assert_eq!(lines[1], "section\tlayers\t30+0\tresources\t34+94\tcolour\t132+0\timage\t132");
    assert_eq!(lines[2], "resource\t0\t1057(VERSION_INFO)\tsize\t81\tname\t-");
    assert_eq!(lines[3], "image\tcompression\t1(RLE)\trows\t15\tcounts\t-\tpayload\t-\tends\tno");
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");

    // The six reserved bytes are specified as zero, and a header that fills them in is still a PSD.
    let mut filled = whole.clone();
    filled[6..12].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    let lines = rows(&filled);
    assert!(lines[0].contains("\treserved\t010203040506\t"), "{}", lines[0]);
    assert!(lines[0].contains("\tbroken\t1\t"), "{}", lines[0]);
}

#[test]
fn a_version_2_header_stops_after_its_own_row() {
    // Hand-built, and labelled as such: no PSB writer exists on this host, so this case exists only to pin
    // the branch - a version-2 document keeps 64-bit section lengths where this walk reads 32, and it would
    // otherwise start naming offsets that are not there.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"8BPS");
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 6]);
    bytes.extend_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(&5u32.to_be_bytes());
    bytes.extend_from_slice(&8u16.to_be_bytes());
    bytes.extend_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 20]);
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "psd\t46\tbroken\t1\tversion\t2\treserved\t000000000000\t5x4\tchannels\t3\tdepth\t8\tmode\t3(RGB)"
    );
    assert_eq!(
        lines[1],
        "note\ta version-2 document states its section lengths differently, so the walk stops here"
    );
    assert_eq!(lines[2], "stopped\tbroken\t1");
    assert_eq!(lines.len(), 3);
}

#[test]
fn the_reader_stays_out_of_its_neighbours_way() {
    // `8BPS` is a signature, so nothing else needs to fear this reader; the reverse matters too - an
    // archive and a certificate that reach the same dispatch must not be answered here.
    assert_eq!(parse(&fixture("plain.7z")), FORMAT_SEVENZIP);
    assert_eq!(parse(&fixture("answer.obj")), FORMAT_COFF);
    assert_ne!(parse(&fixture("media.wav")), FORMAT_PSD);
    assert_ne!(parse(&fixture("tiny.ttf")), FORMAT_PSD);
    // Fewer than 26 bytes is no header at all, and a file with the magic but nothing after it is not read.
    assert_ne!(parse(&fixture("rgb.psd")[..25]), FORMAT_PSD);
}
