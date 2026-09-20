//! ICC colour profiles: a big-endian header whose only magic is a word sitting past its own fields.
//!
//! `test/fixtures/srgb.icc` and `xyz.icc` are written by littleCMS through Pillow
//! (`scripts/make-icc-fixtures.py`), which then walks the bytes itself and re-reads them with
//! `ImageCms` before it will write the probe file. Neither built-in profile is a copy of a file on
//! disk - `createProfile("sRGB")` assembles the values from the library's own tables - so the tag
//! offsets asserted below are the writer's arithmetic, not a transcription of a fixture.
//!
//! A profile states its total length in the first four bytes, so the header is only believed when
//! that closes; the tag table is checked against it rather than trusted, because a tag is a pointer
//! into a file that may be shorter than the pointer claims.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_ICC, FORMAT_STL};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-icc-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_ICC, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_ICC, "kind() must agree with the return code");
    assert_eq!(name(), "icc", "the reader has to name what it walked");
    report()
}

fn be32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

#[test]
fn reads_the_srgb_profile_littlecms_wrote() {
    assert_eq!(
        rows(&fixture("srgb.icc")),
        vec![
            "icc\t588\tdeclared\t588\tbroken\t0\tversion\t4.4\tcmm\tlcms",
            "profile\tclass\tmntr\tspace\tRGB\tpcs\tXYZ\tintent\tperceptual\tcreator\tlcms",
            "tag\t0\tdesc\tsig\tmluc\tat\t264\tlen\t54",
            "tag\t1\tcprt\tsig\tmluc\tat\t320\tlen\t76",
            "tag\t2\twtpt\tsig\tXYZ\tat\t396\tlen\t20",
            "tag\t3\tchad\tsig\tsf32\tat\t416\tlen\t44",
            "tag\t4\trXYZ\tsig\tXYZ\tat\t460\tlen\t20",
            "tag\t5\tbXYZ\tsig\tXYZ\tat\t480\tlen\t20",
            "tag\t6\tgXYZ\tsig\tXYZ\tat\t500\tlen\t20",
            "tag\t7\trTRC\tsig\tpara\tat\t520\tlen\t32",
            "tag\t8\tgTRC\tsig\tpara\tat\t520\tlen\t32",
            "tag\t9\tbTRC\tsig\tpara\tat\t520\tlen\t32",
            "tag\t10\tchrm\tsig\tchrm\tat\t552\tlen\t36",
            "table\ttags\t11\tlisted\t11\toutside\t0\tdata_end\t588\ttail\t0",
            "walked\tend",
        ]
    );
}

#[test]
fn three_trc_tags_sharing_one_offset_are_listed_as_written() {
    // rTRC, gTRC and bTRC in the sRGB profile all point at 520. The format allows a tag to be
    // referenced more than once, so the reader lists the pointers it found rather than deduplicating
    // them into three identical rows and calling that a shorter table.
    let lines = rows(&fixture("srgb.icc"));
    let shared: Vec<&String> = lines
        .iter()
        .filter(|line| line.ends_with("\tat\t520\tlen\t32"))
        .collect();
    assert_eq!(shared.len(), 3, "{shared:?}");
}

#[test]
fn an_identity_profile_names_the_transform_it_carries() {
    let lines = rows(&fixture("xyz.icc"));
    assert_eq!(
        lines[0],
        "icc\t484\tdeclared\t484\tbroken\t0\tversion\t4.4\tcmm\tlcms"
    );
    assert_eq!(
        lines[1],
        "profile\tclass\tabst\tspace\tXYZ\tpcs\tXYZ\tintent\tperceptual\tcreator\tlcms"
    );
    assert_eq!(lines[5], "tag\t3\tchad\tsig\tsf32\tat\t360\tlen\t44");
    assert_eq!(lines[6], "tag\t4\tA2B0\tsig\tmAB\tat\t404\tlen\t80");
    assert_eq!(
        lines[7],
        "table\ttags\t5\tlisted\t5\toutside\t0\tdata_end\t484\ttail\t0"
    );
    assert_eq!(lines[8], "walked\tend");
}

#[test]
fn a_length_that_does_not_close_is_reported_rather_than_walked_past() {
    let mut bytes = fixture("srgb.icc");
    bytes[0..4].copy_from_slice(&be32(600));
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "icc\t588\tdeclared\t600\tbroken\t1\tversion\t4.4\tcmm\tlcms"
    );
    assert_eq!(
        lines[lines.len() - 2],
        "table\ttags\t11\tlisted\t11\toutside\t0\tdata_end\t588\ttail\t12"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
}

#[test]
fn a_tag_past_the_end_is_counted_and_its_type_left_unread() {
    let mut bytes = fixture("srgb.icc");
    // Record zero: signature at 132, offset at 136, length at 140.
    bytes[136..140].copy_from_slice(&be32(4096));
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "icc\t588\tdeclared\t588\tbroken\t1\tversion\t4.4\tcmm\tlcms"
    );
    assert_eq!(lines[2], "tag\t0\tdesc\tsig\t?\tat\t4096\tlen\t54");
    // data_end stays at 588 because the other ten tags really do reach it. The wild pointer adds a
    // count and nothing else, which is also what keeps the 32-bit and 64-bit builds saying the same
    // thing about the same file.
    assert_eq!(
        lines[lines.len() - 2],
        "table\ttags\t11\tlisted\t11\toutside\t1\tdata_end\t588\ttail\t0"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
}

#[test]
fn a_tag_count_that_outruns_the_profile_is_not_believed() {
    let mut bytes = fixture("srgb.icc");
    // 40 records would need the table to reach 612, and the file stops at 588. What sits past the
    // real end is tag payload, so listing it as a directory would print numbers the profile never
    // wrote - the same reason an STL claiming 2 billion triangles in 184 bytes is turned down.
    bytes[128..132].copy_from_slice(&be32(40));
    assert_ne!(
        parse(&bytes),
        FORMAT_ICC,
        "a count with no table behind it is refused, not annotated"
    );

    bytes[128..132].copy_from_slice(&be32(2_000_000_000));
    assert_ne!(
        parse(&bytes),
        FORMAT_ICC,
        "24 GB of table is not in 588 bytes"
    );
}

#[test]
fn nothing_without_the_signature_at_thirty_six_is_claimed() {
    // The magic is not at the front, so every refusal below is a file that merely fails to spell it.
    let mut no_magic = fixture("srgb.icc");
    no_magic[36..40].copy_from_slice(b"MSFT");
    assert_ne!(parse(&no_magic), FORMAT_ICC, "acsp is the whole claim");

    assert_eq!(parse(&[0u8; 400]), -2, "zeroes spell no profile");
    assert_eq!(
        parse(b"aaaaaaaabbbbbbbb"),
        -2,
        "sixteen bytes name no profile"
    );
    assert_ne!(
        parse(&fixture("srgb.icc")[..120]),
        FORMAT_ICC,
        "below the tag table there is nothing to list"
    );
    assert_ne!(
        parse(&fixture("tet.stl")),
        FORMAT_ICC,
        "a mesh that fills 132 bytes is not a profile"
    );
    assert_eq!(
        parse(&fixture("tet.stl")),
        FORMAT_STL,
        "and the mesh still goes to its own reader"
    );
    assert_ne!(
        parse(&fixture("srgb.icc")),
        FORMAT_STL,
        "588 bytes do not divide into triangles under a header that reads as a length"
    );
}
