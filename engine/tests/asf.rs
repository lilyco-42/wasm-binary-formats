//! ASF framing tests, on files ffmpeg muxed: an `.asf`, a `.wma` and a `.wmv`.
//!
//! Every number was read out of `test/fixtures/media.asf` first, and `media_asf.probe.json` is
//! ffprobe's independent reading of the same bytes (container `asf`, 0.200000 s, PCM s16le mono at
//! 8 kHz). What is asserted is the walk, not decoded fields: the header object's five children end
//! exactly where its own declared length says they must, and the two top-level objects account for
//! the file to the byte. The documented File Description field order does not hold in this file, so
//! naming those u64s would be a guess and the reader does not do it.

use apk_lens::containers::{at, count, kind, parse, FORMAT_ASF};
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

fn number(lines: &[String], named: &str, column: usize) -> i64 {
    let line = lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .cloned()
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"));
    line.split('\t')
        .nth(column)
        .unwrap_or_else(|| panic!("row {line} has no column {column}"))
        .parse()
        .unwrap_or_else(|error| panic!("row {line} is not a number: {error}"))
}

#[test]
fn walks_the_asf_objects_ffmpeg_wrote() {
    let asf = fixture("media.asf");
    let length = asf.len();
    assert_eq!(parse(&asf), FORMAT_ASF);
    assert_eq!(kind(), FORMAT_ASF, "kind() must agree with the return code");
    let lines = report();
    assert_eq!(
        lines[0], "asf\t3026b2758e66cf11a6d900aa0062ce6c\t456\t5",
        "header object: its GUID bytes, its total length, its child count: {lines:#?}"
    );
    assert_eq!(
        number(&lines, "header_children_end", 1),
        456,
        "five children must end exactly where the header object says it does: {lines:#?}"
    );
    assert_eq!(number(&lines, "header_children_end", 3), 456);
    assert_eq!(number(&lines, "objects", 1), 2, "header plus data object");
    assert_eq!(
        lines
            .iter()
            .filter(|entry| entry.starts_with("object\t"))
            .count(),
        6,
        "five header children plus the data object; the header object is row 0, not an object row: {lines:#?}"
    );
    assert!(
        lines.contains(&"walked\tend".to_string()),
        "456 + 6450 must account for all {length} bytes: {lines:#?}"
    );
}

#[test]
fn walks_the_same_asf_objects_for_a_wma_and_a_wmv() {
    // ffprobe reads both files as container `asf` (`media_wma.probe.json`: wmav2, mono at 44.1 kHz,
    // 0.231 s; `media_wmv.probe.json`: wmv2, 64x64, 0.400 s), so the two labels that look like
    // separate formats describe the framing this reader already walks. That is the whole claim: no
    // codec object is decoded, and the data object's length is deliberately not asserted because it
    // is what the encoder produced rather than a layout fact.
    for (name, header, objects) in [("media.wma", 492i64, 2i64), ("media.wmv", 587, 3)] {
        let file = fixture(name);
        assert_eq!(parse(&file), FORMAT_ASF, "{name}");
        assert_eq!(
            kind(),
            FORMAT_ASF,
            "{name}: kind() must agree with the return code"
        );
        let lines = report();
        assert_eq!(
            lines[0],
            format!("asf\t3026b2758e66cf11a6d900aa0062ce6c\t{header}\t5"),
            "{name}: the header object declares five children: {lines:#?}"
        );
        assert_eq!(
            number(&lines, "header_children_end", 1),
            header,
            "{name}: the children must end where the header says: {lines:#?}"
        );
        assert_eq!(number(&lines, "header_children_end", 3), header, "{name}");
        assert_eq!(number(&lines, "objects", 1), objects, "{name}: {lines:#?}");
        assert!(
            lines
                .iter()
                .any(|entry| entry.starts_with("object\t3626b2758e66cf11a6d900aa0062ce6c")),
            "{name}: no data object at the top level: {lines:#?}"
        );
        assert!(
            lines.contains(&"walked\tend".to_string()),
            "{name}: the objects must account for all {} bytes: {lines:#?}",
            file.len()
        );
    }
}

#[test]
fn does_not_claim_an_end_for_objects_that_do_not_tile() {
    // Right GUID, a child whose length runs off the file: the walk must report where it stopped
    // rather than pretend the objects covered the buffer.
    let mut bogus = vec![
        0x30u8, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce,
        0x6c,
    ];
    bogus.extend_from_slice(&48u64.to_le_bytes());
    bogus.extend_from_slice(&1u32.to_le_bytes());
    bogus.extend_from_slice(&[0x01, 0x02]);
    bogus.extend_from_slice(&4096u64.to_le_bytes());
    bogus.extend_from_slice(&[0u8; 32]);
    assert_eq!(parse(&bogus), FORMAT_ASF);
    let lines = report();
    assert!(
        !lines.contains(&"walked\tend".to_string()),
        "objects that overshoot the file must not report an end: {lines:#?}"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "4096 zero bytes carry no GUID");
}
