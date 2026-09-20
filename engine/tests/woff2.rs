//! WOFF2: the header, the table directory, and where the one compressed block ends.
//!
//! `test/fixtures/tiny.woff2` is written by fontTools from `test/fixtures/tiny.ttf`
//! (`scripts/make-woff2-fixture.py`, run with the project venv because the writer needs brotli).
//! That pair is the test: the directory lists a length per table, and every table the file stores
//! untransformed has to carry the length it has in the uncompressed font. So the rows below are not
//! checked against this repo's reading of a specification - they are checked against a second file
//! that fontTools produced independently of the reader.
//!
//! Decompression is not attempted: there is no brotli in a dependency-free crate, which is why the
//! read stops at the directory and reports where the compressed block begins and ends.

use apk_lens::containers::{
    at, count, kind, name, parse, FORMAT_WOFF, FORMAT_WOFF2, WOFF2_KNOWN_TAGS,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-woff2-fixture.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn be32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// A WOFF2 header with the given table count, compressed size and declared length, ready for a
/// directory to be appended.
fn header(tables: u16, compressed: u32, length: u32, directory: &[u8]) -> Vec<u8> {
    let mut out = b"wOF2".to_vec();
    out.extend_from_slice(&be32(0x0001_0000));
    out.extend_from_slice(&be32(length));
    out.extend_from_slice(&tables.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&be32(636));
    out.extend_from_slice(&be32(compressed));
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&be32(0));
    out.extend_from_slice(&be32(0));
    out.extend_from_slice(&be32(0));
    out.extend_from_slice(&be32(0));
    out.extend_from_slice(&be32(0));
    out.extend_from_slice(directory);
    out
}

#[test]
fn reads_the_header_and_directory_fonttools_wrote() {
    let bytes = fixture("tiny.woff2");
    assert_eq!(parse(&bytes), FORMAT_WOFF2);
    assert_eq!(
        kind(),
        FORMAT_WOFF2,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "woff2", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "woff2\t312\t312\t10\t0",
            "flavor\t10000\tsfnt\t636",
            "header\t1\t0\tcompressed\t239",
            "areas\t0\t0\t0\t0\t0",
            "table\t0\tOS/2\t96\t-1\t0",
            "table\t1\tcmap\t52\t-1\t0",
            "table\t2\tglyf\t28\t54\t0",
            "table\t3\thead\t54\t-1\t0",
            "table\t4\thhea\t36\t-1\t0",
            "table\t5\thmtx\t8\t-1\t0",
            "table\t6\tloca\t6\t0\t0",
            "table\t7\tmaxp\t32\t-1\t0",
            "table\t8\tname\t108\t-1\t0",
            "table\t9\tpost\t38\t-1\t0",
            "directory\t70\tread\t10\tbroken\t0\tdata_end\t309\tpadding\t3",
            "walked\tend",
        ]
    );
}

#[test]
fn every_untransformed_length_matches_the_ttf_this_was_made_from() {
    // The directory entries are tag index plus UIntBase128 lengths, so a wrong width anywhere in the
    // walk shifts every row after it. The uncompressed font is the witness: for a table WOFF2 stores
    // as-is, its length here and there has to be the same number.
    let ttf = fixture("tiny.ttf");
    let entries = u16::from_be_bytes([ttf[4], ttf[5]]) as usize;
    let mut sizes = Vec::new();
    for entry in 0..entries {
        let start = 12 + entry * 16;
        let tag = String::from_utf8_lossy(&ttf[start..start + 4]).into_owned();
        let size = u32::from_be_bytes(ttf[start + 12..start + 16].try_into().unwrap());
        sizes.push((tag, size));
    }
    assert_eq!(parse(&fixture("tiny.woff2")), FORMAT_WOFF2);
    let lines = report();
    let mut checked = 0;
    for line in lines.iter().filter(|line| line.starts_with("table\t")) {
        let row: Vec<&str> = line.split('\t').collect();
        if row[4] == "-1" {
            let (_, size) = sizes
                .iter()
                .find(|(tag, _)| tag == row[2])
                .unwrap_or_else(|| panic!("{} is not in tiny.ttf", row[2]));
            assert_eq!(row[3].parse::<u32>().unwrap(), *size, "{line}");
            checked += 1;
        }
    }
    assert_eq!(
        checked, 8,
        "eight of the ten tables are stored untransformed"
    );
}

#[test]
fn the_known_tag_list_matches_the_implementation_the_fixture_came_from() {
    // The 63 names are a table, and tables are what this repo keeps getting wrong from memory, so
    // the probe carries fontTools' own list and the two are compared in order.
    let text = fs::read_to_string(format!("{FIXTURES}woff2.probe.json")).expect("woff2.probe.json");
    let key = "\"known_tags\": [";
    let start = text
        .find(key)
        .expect("the probe records the known-tag list")
        + key.len();
    let rest = &text[start..];
    let body = &rest[..rest.find(']').expect("the list is closed")];
    let listed: Vec<String> = body
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect();
    assert_eq!(listed.len(), 63, "{listed:?}");
    assert_eq!(
        listed,
        WOFF2_KNOWN_TAGS
            .iter()
            .map(|tag| (*tag).to_owned())
            .collect::<Vec<_>>(),
        "the reader's table and fontTools' disagree"
    );
}

#[test]
fn a_tag_index_of_63_carries_its_name_in_the_file() {
    // Self-authored: one table with an arbitrary tag, no transform length, no compressed block, and
    // the two bytes the four-byte alignment of that block asks for.
    let mut directory = vec![0x3Fu8];
    directory.extend_from_slice(b"DSIG");
    directory.push(5);
    let mut bytes = header(1, 0, 56, &directory);
    bytes.extend_from_slice(&[0u8, 0]);
    assert_eq!(parse(&bytes), FORMAT_WOFF2);
    assert_eq!(
        report(),
        vec![
            "woff2\t56\t56\t1\t0",
            "flavor\t10000\tsfnt\t636",
            "header\t1\t0\tcompressed\t0",
            "areas\t0\t0\t0\t0\t0",
            "table\t0\tDSIG\t5\t-1\t0",
            "directory\t54\tread\t1\tbroken\t0\tdata_end\t54\tpadding\t2",
            "walked\tend",
        ]
    );
}

#[test]
fn an_overlong_length_is_a_broken_directory_not_a_huge_number() {
    // Self-authored: five continuation bytes, which UIntBase128 does not allow.
    let directory = vec![0x06u8, 0x81, 0x81, 0x81, 0x81, 0x81];
    let bytes = header(1, 0, 54, &directory);
    assert_eq!(parse(&bytes), FORMAT_WOFF2);
    let lines = report();
    assert_eq!(lines[0], "woff2\t54\t54\t1\t0");
    assert_eq!(
        lines[4],
        "directory\t49\tread\t0\tbroken\t1\tdata_end\t49\tpadding\t3"
    );
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_table_count_past_the_budget_is_counted_and_stopped() {
    // Self-authored: 257 one-byte-pair tables claimed, 256 walked.
    let mut directory = Vec::new();
    for _ in 0..257 {
        directory.extend_from_slice(&[0x00u8, 0x04]);
    }
    let length = 48 + directory.len() as u32;
    let bytes = header(257, 0, length, &directory);
    assert_eq!(parse(&bytes), FORMAT_WOFF2);
    let lines = report();
    assert_eq!(lines[0], "woff2\t562\t562\t257\t0");
    assert_eq!(lines[4], "table\t0\tcmap\t4\t-1\t0");
    assert_eq!(lines[259], "table\t255\tcmap\t4\t-1\t0");
    let directory_row = lines
        .iter()
        .find(|line| line.starts_with("directory\t"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        directory_row,
        "directory\t560\tread\t256\tbroken\t1\tdata_end\t560\tpadding\t0"
    );
    assert!(
        !lines.iter().any(|line| line == "walked\tend"),
        "a capped walk never claims the end: {lines:?}"
    );
}

#[test]
fn a_declared_length_that_does_not_match_the_file_leaves_the_end_unclaimed() {
    let mut bytes = fixture("tiny.woff2");
    let lying = 300u32.to_be_bytes();
    bytes[8..12].copy_from_slice(&lying);
    assert_eq!(parse(&bytes), FORMAT_WOFF2);
    let lines = report();
    assert_eq!(lines[0], "woff2\t300\t312\t10\t0");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn woff2_and_woff_are_different_readers_for_different_files() {
    // "wOF2" versus "wOFF": the fourth byte decides, and a reader that ignored it would walk WOFF's
    // per-table entries as if they were a directory of lengths.
    assert_eq!(parse(&fixture("tiny.woff")), FORMAT_WOFF);
    assert_eq!(
        parse(b"wOF2\x00\x00\x00\x00\x00\x00"),
        -2,
        "too short for a header"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no signature");
    let mut near = fixture("tiny.woff2");
    near[0] = b'x';
    assert_eq!(parse(&near), -2, "xOF2 is neither flavour");
}
