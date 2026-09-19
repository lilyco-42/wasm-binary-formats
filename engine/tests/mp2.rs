//! MPEG Layer II (`.mp2`) on the frame walk that Layer III already used.
//!
//! `test/fixtures/media.mp2` and `test/fixtures/media-192k.mp2` are muxed by ffmpeg's native `mp2`
//! encoder (see `scripts/make-media-fixtures.sh`), and `media_mp2.probe.json` /
//! `media-192k_mp2.probe.json` are ffprobe's independent reading of the same bytes: 1.018750 s,
//! 44100 Hz, mono, 128 000 and 192 000 bit/s. Two bitrates exist because a single file cannot tell a
//! bitrate table that was looked up from a stride that was hardcoded, which is the only real risk in
//! sharing one walker between two layers.

use apk_lens::audio::{at, count, kind, name, parse, FORMAT_MP2, FORMAT_MP3};
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
fn walks_the_layer_ii_frames_ffmpeg_wrote() {
    for (file, index, kilobits) in [("media.mp2", 8i64, 128i64), ("media-192k.mp2", 10, 192)] {
        let bytes = fixture(file);
        assert_eq!(parse(&bytes), FORMAT_MP2, "{file}");
        assert_eq!(kind(), FORMAT_MP2, "{file}: kind() must agree");
        assert_eq!(name(), "mp2", "{file}: the reader must name its own layer");
        let lines = report();
        assert_eq!(number(&lines, "layer", 1), 2, "{file}: {lines:#?}");
        assert_eq!(number(&lines, "sample_rate", 1), 44100, "{file}");
        assert_eq!(number(&lines, "frames", 1), 39, "{file}: {lines:#?}");
        // 39 frames x 1152 samples at 44.1 kHz is the 1.018750 s ffprobe reports for both files.
        assert_eq!(number(&lines, "samples", 1), 44_928, "{file}");
        assert_eq!(number(&lines, "duration_ms", 1), 1019, "{file}");
        assert_eq!(
            number(&lines, "rate_switches", 1),
            0,
            "{file}: one rate throughout"
        );
        let bitrate = lines
            .iter()
            .find(|entry| entry.starts_with("bitrate\t"))
            .cloned()
            .unwrap_or_else(|| panic!("{file} reported no bitrate: {lines:#?}"));
        assert_eq!(
            bitrate,
            format!("bitrate\t{index}\t{kilobits}\t39"),
            "{file}: the table entry has to be the one the frames used"
        );
        assert_eq!(
            number(&lines, "bytes_after_frames", 1),
            bytes.len() as i64,
            "{file}: the chain must account for every byte"
        );
    }
}

#[test]
fn a_layer_ii_file_is_not_called_layer_iii_and_vice_versa() {
    // The two layers share a sync word and a stride formula, so the layer bits are what separates
    // them; reading one as the other would report a bitrate the encoder never used.
    let mp3 = fixture("media.mp3");
    assert_eq!(parse(&mp3), FORMAT_MP3);
    assert_eq!(name(), "mpeg-audio");
    let lines = report();
    assert_eq!(number(&lines, "layer", 1), 3);
    // The discriminating claim is the tiling: fed the Layer II table, this file's walk finds no
    // frame at all and stops at byte 44, so a chain that accounts for every byte can only have come
    // from the Layer III table.
    assert_eq!(number(&lines, "frames", 1), 10);
    assert_eq!(number(&lines, "bytes_after_frames", 1), mp3.len() as i64);
}
