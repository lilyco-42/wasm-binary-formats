//! Avro object containers: the metadata map, the sync marker, and the block chain that has to add up.
//!
//! `test/fixtures/{rows,deflate,many}.avro` are written by fastavro
//! (`scripts/make-avro-fixtures.py`), which then reads each one back and compares its own record count
//! against the sum of the block counts before the file is committed. `many.avro` is written with
//! `sync_interval=1000` so that it really is five blocks: with one block only, a loop and a block that
//! happens to end at the file are the same observable thing.
//!
//! Payload bytes are counted, never decoded - the reader does not deserialise records and does not
//! inflate a compressed block - so the rows below are the container's own numbers. The sync marker is
//! random per file, which is why these tests assert its shape rather than its digits: regenerating a
//! fixture must not change any other row.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_AVRO};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-avro-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

/// zigzag(2) == 4, so a one-element block header is 0x04 and a length of 30 is 0x3c.
fn container(codec: &str, schema: &str, sync: [u8; 16], blocks: &[(i64, usize)]) -> Vec<u8> {
    let mut out = b"Obj\x01".to_vec();
    out.push(0x04);
    for (key, value) in [("avro.codec", codec), ("avro.schema", schema)] {
        out.push((key.len() * 2) as u8);
        out.extend_from_slice(key.as_bytes());
        out.push((value.len() * 2) as u8);
        out.extend_from_slice(value.as_bytes());
    }
    out.push(0x00);
    out.extend_from_slice(&sync);
    for (records, bytes) in blocks {
        out.push((*records * 2) as u8);
        out.push((*bytes as i64 * 2) as u8);
        out.extend_from_slice(&vec![0u8; *bytes]);
        out.extend_from_slice(&sync);
    }
    out
}

#[test]
fn reads_the_metadata_map_and_the_single_block_fastavro_wrote() {
    let bytes = fixture("rows.avro");
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    assert_eq!(
        kind(),
        FORMAT_AVRO,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "avro", "the reader has to name what it walked");
    let lines = report();
    assert_eq!(lines[0], "avro\t203\t203\t1\t0");
    assert_eq!(lines[1], "metadata\t2\twith_schema\t1");
    assert_eq!(lines[2], "codec\tnull");
    assert_eq!(lines[3], "schema\t116\tname\tSample");
    assert!(
        lines[4].starts_with("sync\t") && lines[4].ends_with("\tagrees\t1"),
        "{}",
        lines[4]
    );
    assert_eq!(
        lines[4].split('\t').nth(1).map(str::len),
        Some(32),
        "32 hex digits"
    );
    assert_eq!(lines[5], "block\t0\t3\t17");
    assert_eq!(lines[6], "records\t3");
    assert_eq!(lines[7], "walked\tend");
}

#[test]
fn the_codec_row_quotes_what_the_metadata_says_without_inflating_anything() {
    let bytes = fixture("deflate.avro");
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    let lines = report();
    assert_eq!(lines[2], "codec\tdeflate");
    assert_eq!(lines[0], "avro\t211\t211\t1\t0");
    assert_eq!(
        lines[5], "block\t0\t3\t22",
        "the compressed block is smaller than the null-coded one, and is still counted, not decoded"
    );
    assert_eq!(lines[6], "records\t3");
}

#[test]
fn a_five_block_chain_is_walked_and_the_records_add_up() {
    let bytes = fixture("many.avro");
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    let lines = report();
    assert_eq!(lines[0], "avro\t5094\t5094\t5\t0");
    assert_eq!(lines[5], "block\t0\t118\t1006");
    assert_eq!(lines[6], "block\t1\t100\t1000");
    assert_eq!(lines[9], "block\t4\t82\t820");
    assert_eq!(
        lines[10], "records\t500",
        "118 + 100 + 100 + 100 + 82, which is what fastavro counts when it reads this file back"
    );
    assert_eq!(lines[11], "walked\tend");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("block\t"))
            .count(),
        5
    );
}

#[test]
fn a_block_claiming_more_bytes_than_the_file_holds_stops_the_chain() {
    let sync = [0xab; 16];
    let mut bytes = container("null", "{}", sync, &[(3, 8)]);
    // The last block is varint count, varint size, that many bytes, then the marker: 1 + 1 + 8 + 16.
    let block_at = bytes.len() - 26;
    bytes[block_at + 1] = 0x7a;
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    let lines = report();
    assert!(lines[0].ends_with("\t0\t1"), "broken once: {}", lines[0]);
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
    assert_eq!(lines[lines.len() - 1], "records\t0");
}

#[test]
fn a_block_that_repeats_a_different_marker_is_reported_as_diverging() {
    let sync = [0xab; 16];
    let mut bytes = container("null", "{}", sync, &[(3, 8)]);
    let tail_start = bytes.len() - 16;
    bytes[tail_start] = 0xcd;
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    let lines = report();
    assert!(
        lines.iter().any(|line| line.ends_with("\tsync\tdiffers")),
        "{lines:?}"
    );
    assert!(lines
        .iter()
        .any(|line| line == "sync\tabababababababababababababababab\tagrees\t0"));
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_container_with_no_terminator_for_its_metadata_map_is_left_alone() {
    // One pair instead of two: the byte that should have ended the map is the first sync byte, so a
    // reader that trusted the map blindly would take its marker from the wrong place. The key is 11
    // bytes, so its length varint is 22, and the value claims 3 of the four bytes written.
    let mut bytes = b"Obj\x01".to_vec();
    bytes.push(0x02);
    bytes.push(0x16);
    bytes.extend_from_slice(b"avro.schema");
    bytes.push(0x06);
    bytes.extend_from_slice(b"null");
    bytes.extend_from_slice(&[0u8; 16]);
    assert_eq!(parse(&bytes), FORMAT_AVRO);
    let lines = report();
    assert_eq!(lines[1], "metadata\t1\twith_schema\t1");
    assert_eq!(lines[2], "codec\tabsent");
    assert_eq!(lines[3], "schema\t3\tname\tunknown");
    assert!(lines[0].ends_with("\t0\t1"), "{}", lines[0]);
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_short_or_foreign_file_is_not_an_avro_container() {
    assert_eq!(parse(b"Obj\x01\x04\x00"), -2, "no map, no marker");
    assert_eq!(
        parse(b"OBA\x01aaaaaaaaaaaaaaaa"),
        -2,
        "the magic has to be Obj\\x01"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no magic");
}
