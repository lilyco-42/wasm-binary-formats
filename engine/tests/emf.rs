//! Enhanced metafile: a record list whose header states the file's own length, and two producers that
//! disagree about what "number of records" means.
//!
//! `test/fixtures/page.emf` is written by LibreOffice (given an 8x8 PNG, through the Draw EMF export
//! filter) and `test/fixtures/gdi.emf` is written by Windows' own GDI through `CreateEnhMetaFileW`.
//! `scripts/make-emf-fixtures.py` produces both, walks them with a private mirror, and refuses to
//! write the probe JSON unless Pillow's GDI-backed opener reports each file's header bounds back as
//! the image size - which is the one claim here that leaves this repo's own arithmetic to be checked
//! against the operating system.
//!
//! The interesting disagreement is `records`: GDI's header counts the header record, LibreOffice's
//! does not. The reader therefore prints the claim and the walk side by side rather than picking a
//! winner, and it names record types by number only - type 14 closes both files, which is a fact about
//! position, not a table carried from documentation.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_EMF, FORMAT_ICC, FORMAT_STL};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-emf-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_EMF, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_EMF, "kind() must agree with the return code");
    assert_eq!(name(), "emf", "the reader has to name what it walked");
    report()
}

#[test]
fn reads_the_gdi_metafile_record_by_record() {
    assert_eq!(
        rows(&fixture("gdi.emf")),
        vec![
            "emf\t308\tbroken\t0\tversion\t1.0\tnsize\t108\trecords\t5\twalked\t5",
            "bounds\t4\t4\t72\t39\twh\t68x35",
            "frame\t63\t63\t1125\t618\tmm\t10.62x5.55",
            "device\tpx\t1920x1200\tmm\t300x190\tdpi\t162.56",
            "record\t0\ttype\t1\tsize\t108",
            "record\t1\ttype\t43\tsize\t24",
            "record\t2\ttype\t42\tsize\t24",
            "record\t3\ttype\t84\tsize\t132",
            "record\t4\ttype\t14\tsize\t20",
            "types\tcounted\t5\tdistinct\t5\tlast\t14",
            "walked\tend",
        ]
    );
}

#[test]
fn reports_the_count_a_second_writer_disagrees_about_without_choosing_a_side() {
    let lines = rows(&fixture("page.emf"));
    assert_eq!(
        lines[0], "emf\t808\tbroken\t0\tversion\t1.0\tnsize\t108\trecords\t22\twalked\t23",
        "GDI counts its header record and LibreOffice does not, so both numbers are printed"
    );
    assert_eq!(lines[1], "bounds\t0\t0\t897\t1308\twh\t897x1308");
    assert_eq!(lines[2], "frame\t0\t0\t18999\t27699\tmm\t189.99x276.99");
    assert_eq!(lines[3], "device\tpx\t898x1309\tmm\t190x277\tdpi\t120.05");
    assert_eq!(lines[4], "record\t0\ttype\t1\tsize\t108");
    assert_eq!(lines[lines.len() - 3], "record\t22\ttype\t14\tsize\t20");
    assert_eq!(
        lines[lines.len() - 2],
        "types\tcounted\t23\tdistinct\t14\tlast\t14"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn frame_is_bounds_read_through_the_resolution_the_device_pair_states() {
    // bounds is device units, frame is hundredths of a millimetre, and the pixels/mm pair implies the
    // resolution that turns one into the other. Every number in the check comes out of the file.
    let lines = rows(&fixture("gdi.emf"));
    assert_eq!(lines[1], "bounds\t4\t4\t72\t39\twh\t68x35");
    assert_eq!(lines[2], "frame\t63\t63\t1125\t618\tmm\t10.62x5.55");
    assert_eq!(lines[3], "device\tpx\t1920x1200\tmm\t300x190\tdpi\t162.56");
    // 68 device units at the resolution the device pair states is 10.62 mm, which is what frame says.
    let units = 68.0f64;
    let dpi = 1920.0 * 25.4 / 300.0;
    assert!(
        (units / dpi * 25.4 - 10.62).abs() < 0.05,
        "{units} at {dpi} dpi"
    );
}

#[test]
fn a_record_that_outruns_the_file_stops_the_walk_where_it_claims_to_end() {
    let mut bytes = fixture("gdi.emf");
    // Record one's size, at 108 + 4, becomes the whole file.
    bytes[112..116].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "emf\t308\tbroken\t1\tversion\t1.0\tnsize\t108\trecords\t5\twalked\t1"
    );
    assert_eq!(
        lines[lines.len() - 2],
        "types\tcounted\t1\tdistinct\t1\tlast\t1"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tat\t108");
}

#[test]
fn a_header_that_lies_about_the_byte_count_is_reported_beside_a_walk_that_still_finishes() {
    let mut bytes = fixture("gdi.emf");
    bytes[48..52].copy_from_slice(&400u32.to_le_bytes());
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "emf\t308\tbroken\t1\tversion\t1.0\tnsize\t108\trecords\t5\twalked\t5"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn nothing_without_the_word_at_forty_is_claimed_as_a_metafile() {
    let mut no_magic = fixture("gdi.emf");
    no_magic[40..44].copy_from_slice(b"EMF\x20");
    assert_ne!(parse(&no_magic), FORMAT_EMF, "the signature is the claim");

    let mut not_header = fixture("gdi.emf");
    not_header[0..4].copy_from_slice(&14u32.to_le_bytes());
    assert_ne!(
        parse(&not_header),
        FORMAT_EMF,
        "record zero has to be the header"
    );

    assert_eq!(parse(&[0u8; 400]), -2, "zeroes spell no metafile");
    assert_ne!(
        parse(&fixture("gdi.emf")[..90]),
        FORMAT_EMF,
        "a header shorter than the fields read here is not read at all"
    );
    assert_ne!(
        parse(&fixture("srgb.icc")),
        FORMAT_EMF,
        "a profile is not a metafile"
    );
    assert_ne!(parse(&fixture("tet.stl")), FORMAT_EMF, "nor is a mesh");
    assert_eq!(
        parse(&fixture("srgb.icc")),
        FORMAT_ICC,
        "and the profile still reaches its own reader"
    );
    assert_eq!(
        parse(&fixture("tet.stl")),
        FORMAT_STL,
        "and the mesh still reaches its own"
    );
}
