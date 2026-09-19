//! FLV and CAB framing tests, on files ffmpeg and `makecab` produced.
//!
//! The FLV fixture is a one-second 32x24 `flv1` video: six tags, one `onMetaData` script tag and
//! five video tags, whose timestamps step by 200 ms at the 5 fps the muxer was given. Each tag is
//! followed by a back-pointer that must equal 11 + data size, so the mismatch count reaching zero
//! and the walk landing on the last byte together mean the tag lengths were read as written.
//!
//! The two cabinets come from `makecab` on this machine and were written to disagree on purpose:
//! `tiny.cab` holds two 50-byte files and `big.cab` holds six of 100 000 bytes. Both keep eight
//! bytes between the header and the file table, and in both the uncompressed offsets run
//! continuously to the total, which is what the tests assert.

use apk_lens::containers::{at, count, kind, parse, FORMAT_CAB, FORMAT_FLV};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-media-fixtures.sh: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn row(lines: &[String], prefix: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(prefix))
        .cloned()
        .unwrap_or_else(|| panic!("no row starting with {prefix} in {lines:#?}"))
}

fn split(line: &str) -> Vec<String> {
    line.split('\t').map(|part| part.to_string()).collect()
}

#[test]
fn walks_flv_tags_and_their_back_pointers() {
    let flv = fixture("media.flv");
    let length = flv.len();
    assert_eq!(parse(&flv), FORMAT_FLV);
    assert_eq!(kind(), FORMAT_FLV);
    let lines = report();
    assert_eq!(row(&lines, "version"), "version\t1");
    assert_eq!(row(&lines, "header_bytes"), "header_bytes\t9");
    assert_eq!(row(&lines, "audio_present"), "audio_present\t0");
    assert_eq!(row(&lines, "video_present"), "video_present\t1");
    assert_eq!(
        row(&lines, "tags"),
        "tags\t6\taudio\t0\tvideo\t5",
        "{lines:#?}"
    );
    assert_eq!(row(&lines, "script_tags"), "script_tags\t1");
    assert_eq!(
        row(&lines, "backpointer_mismatches"),
        "backpointer_mismatches\t0"
    );
    assert_eq!(row(&lines, "last_timestamp_ms"), "last_timestamp_ms\t800");
    assert_eq!(
        split(&row(&lines, "tag\tvideo")).pop(),
        Some("211".to_string()),
        "the first video tag sits where the script tag plus its back-pointer ends"
    );
    assert!(
        lines.contains(&"walked\tend".to_string()),
        "six tags must account for all {length} bytes: {lines:#?}"
    );
}

#[test]
fn reads_both_cabinet_file_tables() {
    let tiny = fixture("tiny.cab");
    assert_eq!(parse(&tiny), FORMAT_CAB);
    let lines = report();
    assert_eq!(row(&lines, "cabinet_bytes"), "cabinet_bytes\t158");
    assert_eq!(row(&lines, "files"), "files\t2");
    assert_eq!(row(&lines, "folders"), "folders\t1");
    assert_eq!(row(&lines, "files_listed"), "files_listed\t2");
    assert_eq!(row(&lines, "uncompressed_total"), "uncompressed_total\t100");
    assert_eq!(row(&lines, "contiguous_offsets"), "contiguous_offsets\t1");
    let names: Vec<String> = lines
        .iter()
        .filter(|entry| entry.starts_with("file\t"))
        .map(|entry| split(entry)[1].clone())
        .collect();
    assert_eq!(names, vec!["payload.txt", "second.txt"], "{lines:#?}");
    assert_eq!(row(&lines, "data_offset"), "data_offset\t99");

    let big = fixture("big.cab");
    assert_eq!(parse(&big), FORMAT_CAB);
    let lines = report();
    assert_eq!(row(&lines, "files"), "files\t6");
    assert_eq!(
        row(&lines, "uncompressed_total"),
        "uncompressed_total\t600000"
    );
    assert_eq!(row(&lines, "contiguous_offsets"), "contiguous_offsets\t1");
    assert_eq!(row(&lines, "data_offset"), "data_offset\t182");
    let sizes: Vec<i64> = lines
        .iter()
        .filter(|entry| entry.starts_with("file\t"))
        .map(|entry| split(entry)[2].parse().unwrap_or(-1))
        .collect();
    assert_eq!(sizes, vec![100_000; 6], "{lines:#?}");
}

#[test]
fn does_not_invent_cabinet_folder_semantics() {
    // The folder area is reported as bytes because its two 16-bit fields do not behave like sizes on
    // either sample (1 and 1 for a 100-byte folder, 19 and 1 for a 600 KB one), so the reader must
    // say what they are not rather than name them.
    let cab = fixture("tiny.cab");
    assert_eq!(parse(&cab), FORMAT_CAB);
    let area = row(&report(), "folder_area");
    let hex = split(&area)[1].clone();
    assert_eq!(hex.len(), 16, "eight folder bytes, printed as hex: {area}");
    assert!(
        !area.contains("cbFolder") && !area.contains("size"),
        "no field name is claimed for the folder bytes: {area}"
    );
    assert_eq!(parse(&[0u8; 60]), -2, "zeros are not a cabinet");
}
