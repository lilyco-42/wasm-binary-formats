//! Media container tests: ISO base media (mp4), EBML (Matroska and WebM), and the audio headers
//! FLAC, MPEG audio, Ogg and WAVE.
//!
//! Every fixture here was written by ffmpeg - a muxer we do not control - and `ffprobe` ran over
//! each one afterwards, which is the independent reading the expectations come from. Where a number
//! is only visible in the bytes themselves (box sizes, element ids, block lengths) it was taken from
//! the committed file rather than from the specification, in the same way the stream tests were.
//! The probe JSON lives beside the fixture so the pairing can be re-checked by hand.
//!
//! `reports_every_media_fixture` prints every report the engine gives, green or not: when a field is
//! wrong the CI log then shows the whole report instead of one assertion failure at a time.

use apk_lens::audio::{
    at as audio_at, count as audio_count, kind as audio_kind, parse as parse_audio, FORMAT_FLAC,
    FORMAT_MP3, FORMAT_OGG, FORMAT_WAVE,
};
use apk_lens::containers::{
    at as container_at, count as container_count, kind as container_kind, parse as parse_container,
    FORMAT_BMFF, FORMAT_EBML, FORMAT_RIFF,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-media-fixtures.sh: {error}")
    })
}

/// Field rows for whichever reader ran last; the engine keeps one report per thread.
fn audio_fields() -> Vec<String> {
    (0..audio_count()).filter_map(audio_at).collect()
}

fn container_fields() -> Vec<String> {
    (0..container_count()).filter_map(container_at).collect()
}

fn number(lines: &[String], named: &str, column: usize) -> i64 {
    let line = lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"));
    line.split('\t')
        .nth(column)
        .unwrap_or_else(|| panic!("row {line} has no column {column}"))
        .parse()
        .unwrap_or_else(|error| panic!("row {line} is not a number: {error}"))
}

fn rows_starting(lines: &[String], prefix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|entry| entry.starts_with(prefix))
        .cloned()
        .collect()
}

#[test]
fn walks_the_mp4_boxes_ffmpeg_wrote() {
    let mp4 = fixture("media.mp4");
    let length = mp4.len();
    assert_eq!(parse_container(&mp4), FORMAT_BMFF);
    assert_eq!(container_kind(), FORMAT_BMFF, "kind() must agree");
    let lines = container_fields();
    assert!(
        lines[0].starts_with("ftyp\tisom"),
        "first box should advertise the isom brand, got {}",
        lines[0]
    );
    // Sizes read out of the committed file with xxd; their sum is the file length, which is what
    // makes this a walk rather than a guess.
    assert_eq!(
        rows_starting(&lines, "box\t"),
        vec![
            format!("box\tftyp\t32\t0"),
            "box\tfree\t8\t32".to_string(),
            "box\tmdat\t2977\t40".to_string(),
            "box\tmoov\t949\t3017".to_string(),
        ],
        "top-level box list, all lines: {lines:#?}"
    );
    assert!(
        lines.contains(&"walked\tend".to_string()),
        "the box walk must consume the whole {length}-byte file: {lines:#?}"
    );
    assert_eq!(
        number(&lines, "duration", 1),
        1000,
        "mvhd timescale, from ffprobe's 1.000000s duration"
    );
    assert_eq!(number(&lines, "duration", 2), 1000);
    assert_eq!(
        number(&lines, "duration", 3),
        1000,
        "duration in milliseconds"
    );
    assert_eq!(
        rows_starting(&lines, "child\t").len(),
        3,
        "moov holds mvhd, trak and udta: {lines:#?}"
    );
    assert_eq!(
        rows_starting(&lines, "brand\t").len(),
        4,
        "isom, iso2, avc1, mp41: {lines:#?}"
    );
}

#[test]
fn reads_matroska_and_webm_as_the_same_ebml_tree() {
    for (name, doctype, version) in [("media.mkv", "matroska", 4), ("media.webm", "webm", 2)] {
        let file = fixture(name);
        assert_eq!(parse_container(&file), FORMAT_EBML, "{name}");
        assert_eq!(container_kind(), FORMAT_EBML, "{name}");
        let lines = container_fields();
        assert_eq!(
            lines[0],
            format!("header\t{doctype}\t1\t{version}\t2"),
            "EBML header of {name}: {lines:#?}"
        );
        assert!(
            number(&lines, "segment", 1) > 0,
            "the ffmpeg Segment element carries a real size: {lines:#?}"
        );
        let elements = rows_starting(&lines, "elem\t");
        assert!(
            elements.len() >= 3,
            "{name} should list several top-level Segment children, got {elements:#?}"
        );
        assert!(
            elements
                .iter()
                .any(|row| row.starts_with("elem\t0x114d9b74")),
            "Cues is present in both files: {elements:#?}"
        );
        if name == "media.mkv" {
            let duration = lines
                .iter()
                .find(|row| row.starts_with("duration_ms"))
                .unwrap_or_else(|| panic!("ffmpeg writes a Duration into Info: {lines:#?}"));
            let millis: f64 = duration
                .split('\t')
                .nth(1)
                .unwrap_or_default()
                .parse()
                .unwrap_or_else(|error| panic!("unparsable duration {duration}: {error}"));
            assert!(
                (900.0..=1100.0).contains(&millis),
                "ffprobe says 1.000000s for {name}, the header says {millis}"
            );
        }
    }
}

#[test]
fn reads_the_flac_streaminfo_block_ffmpeg_wrote() {
    let flac = fixture("media.flac");
    let length = flac.len();
    assert_eq!(parse_audio(&flac), FORMAT_FLAC);
    assert_eq!(audio_kind(), FORMAT_FLAC);
    let lines = audio_fields();
    assert_eq!(number(&lines, "sample_rate", 1), 44100, "{lines:#?}");
    assert_eq!(number(&lines, "channels", 1), 1);
    assert_eq!(number(&lines, "bits_per_sample", 1), 16);
    assert_eq!(
        number(&lines, "total_samples", 1),
        8820,
        "the source was -t 0.2 at 44100 Hz"
    );
    assert_eq!(number(&lines, "duration_ms", 1), 200);
    assert!(number(&lines, "min_block", 1) > 0);
    assert!(
        number(&lines, "max_block", 1) >= number(&lines, "min_block", 1),
        "{lines:#?}"
    );
    // The metadata blocks are walked by their own declared lengths and the last is flagged, so the
    // walk has to stop exactly where the frame area begins. Their sizes differ per encode (this one
    // ends with an 8 KiB padding block), which is why the assertion is about the sync code rather
    // than a fixed offset.
    let blocks = rows_starting(&lines, "block\t");
    assert!(
        blocks.len() >= 2,
        "STREAMINFO plus a vendor comment: {lines:#?}"
    );
    assert!(
        blocks.last().unwrap().ends_with("\t1"),
        "the final block must carry the last-metadata-block flag: {blocks:#?}"
    );
    let start = number(&lines, "frames_start", 1) as usize;
    assert!(
        (42..length).contains(&start),
        "the frame area starts after the metadata: {lines:#?}"
    );
    assert_eq!(
        &flac[start..start + 2],
        [0xff, 0xf8],
        "a FLAC frame header starts with the 14-bit sync code and a fixed block size"
    );
}

#[test]
fn survives_the_unknown_sizes_and_truncations_live_streams_use() {
    // An EBML element may declare "unknown size", which Matroska and WebM streams use for the
    // Segment, and a reader that derives a length mask from the size width can shift past the end
    // of a byte. Both are inputs here: the goal is that they report, not that they panic.
    let mkv = fixture("media.mkv");
    let at = mkv
        .windows(4)
        .position(|window| window == [0x18, 0x53, 0x80, 0x67])
        .expect("the Segment element id");
    let width = (0..8)
        .find(|shift| (mkv[at + 4] >> (7 - shift)) & 1 == 1)
        .expect("a leading size byte")
        + 1;
    let mut unknown = mkv.clone();
    unknown.splice(
        at + 4..at + 4 + width,
        [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert_eq!(parse_container(&unknown), FORMAT_EBML);
    let lines = container_fields();
    assert_eq!(
        number(&lines, "segment", 1),
        -1,
        "an unknown-length Segment must be reported as such: {lines:#?}"
    );
    assert!(
        rows_starting(&lines, "elem\t").len() >= 3,
        "the walk continues past it: {lines:#?}"
    );
    for cut in [8, 20, 40, 60, 120, 900] {
        let code = parse_container(&mkv[..cut]);
        // Either the EBML tree is recognised or the buffer is refused with an error code. What may
        // not happen is a panic, and what may not happen either is a prefix being reported as some
        // other container - the shortest header any reader uses is eight bytes, so these prefixes
        // do reach the dispatch rather than being turned away by a length gate.
        assert!(
            code == FORMAT_EBML || code == -1 || code == -2,
            "a {cut}-byte prefix reported {code}"
        );
    }
}

#[test]
fn walks_the_mp3_frame_chain_and_finds_the_bitrate_the_frames_use() {
    let mp3 = fixture("media.mp3");
    let length = mp3.len();
    assert_eq!(parse_audio(&mp3), FORMAT_MP3);
    assert_eq!(audio_kind(), FORMAT_MP3);
    let lines = audio_fields();
    assert_eq!(number(&lines, "sample_rate", 1), 44100, "{lines:#?}");
    assert_eq!(number(&lines, "mpeg_version", 1), 3, "MPEG 1 Layer III");
    assert_eq!(number(&lines, "layer", 1), 3);
    assert_eq!(number(&lines, "rate_switches", 1), 0, "one rate throughout");
    let frames = number(&lines, "frames", 1);
    assert!((5..200).contains(&frames), "{frames} frames: {lines:#?}");
    // ffprobe reports a 32 kbps stream. The frames have to agree, and they are counted from the
    // walk rather than from the first header: LAME writes a first frame whose bitrate index differs
    // from every frame after it, so frame zero is not the file's bitrate.
    let rates = rows_starting(&lines, "bitrate\t");
    let counted: i64 = rates
        .iter()
        .map(|row| {
            row.split('\t')
                .nth(3)
                .unwrap_or_default()
                .parse::<i64>()
                .unwrap_or_default()
        })
        .sum();
    assert_eq!(counted, frames, "every frame reports a bitrate index");
    let loudest = rates
        .iter()
        .map(|row| {
            let parts: Vec<&str> = row.split('\t').collect();
            (
                parts.get(2).unwrap_or(&"0").parse::<i64>().unwrap_or(0),
                parts.get(3).unwrap_or(&"0").parse::<i64>().unwrap_or(0),
            )
        })
        .max_by_key(|(_kilo, seen)| *seen)
        .unwrap();
    assert_eq!(loudest, (32, frames - 1), "majority bitrate, {rates:#?}");
    let duration = number(&lines, "duration_ms", 1);
    assert!(
        (150..=350).contains(&duration),
        "the source was -t 0.2, the frames say {duration} ms: {lines:#?}"
    );
    assert!(
        length as i64 - number(&lines, "bytes_after_frames", 1) <= 4,
        "the frame chain should reach EOF: {lines:#?}"
    );
}

#[test]
fn walks_ogg_pages_and_reads_the_vorbis_identification_header() {
    let ogg = fixture("media.ogg");
    let length = ogg.len();
    assert_eq!(parse_audio(&ogg), FORMAT_OGG);
    assert_eq!(audio_kind(), FORMAT_OGG);
    let lines = audio_fields();
    assert_eq!(number(&lines, "version", 1), 0, "{lines:#?}");
    assert_eq!(number(&lines, "first_header_type", 1), 2, "bootstrap page");
    assert_eq!(number(&lines, "channels", 1), 1);
    assert_eq!(number(&lines, "sample_rate", 1), 44100);
    assert_eq!(
        number(&lines, "bitrate_nominal", 1),
        60000,
        "ffprobe reports 60000 for this stream"
    );
    assert_eq!(
        number(&lines, "sequence_gaps", 1),
        0,
        "page numbers run 0..n"
    );
    assert_eq!(
        number(&lines, "last_granule", 1),
        8820,
        "granule position is the sample count for Vorbis, and -t 0.2 at 44100 is 8820"
    );
    assert!(number(&lines, "pages", 1) >= 2, "{lines:#?}");
    assert_eq!(
        number(&lines, "bytes_after_pages", 1),
        length as i64,
        "the page walk should tile the file: {lines:#?}"
    );
}

#[test]
fn reads_a_wave_written_by_ffmpeg_as_pcm() {
    let wav = fixture("media.wav");
    assert_eq!(parse_audio(&wav), FORMAT_WAVE);
    assert_eq!(audio_kind(), FORMAT_WAVE);
    let lines = audio_fields();
    assert_eq!(number(&lines, "format", 1), 1, "PCM");
    assert_eq!(number(&lines, "channels", 1), 1);
    assert_eq!(number(&lines, "sample_rate", 1), 8000, "-ar 8000");
    assert_eq!(number(&lines, "bits_per_sample", 1), 16);
    assert_eq!(number(&lines, "block_align", 1), 2);
    assert_eq!(number(&lines, "data_bytes", 1), 3200, "0.2s at 8 kHz s16");
    assert_eq!(number(&lines, "duration_ms", 1), 200);
    assert_eq!(number(&lines, "declared", 1), wav.len() as i64);
}

#[test]
fn walks_an_avif_that_libsvtav1_muxed() {
    // The same ISO base media reader that handles mp4 is what covers AVIF: the file starts with
    // `ftyp` and the brand, so the box walk needs no new code. ffprobe reads the same file as
    // major_brand=avif with compatible brands avif, mif1, miaf, MA1B, which is what the two
    // assertions on the brand list are checking against.
    let avif = fixture("tiny.avif");
    let length = avif.len();
    assert_eq!(parse_container(&avif), FORMAT_BMFF);
    let lines = container_fields();
    assert_eq!(
        lines[0], "ftyp\tavif\t0",
        "brand and minor version: {lines:#?}"
    );
    assert_eq!(
        rows_starting(&lines, "box\t"),
        vec![
            "box\tftyp\t32\t0".to_string(),
            "box\tmeta\t249\t32".to_string(),
            "box\tmdat\t290\t281".to_string(),
        ],
        "AVIF carries no moov, so this is the whole top level: {lines:#?}"
    );
    assert_eq!(
        rows_starting(&lines, "brand\t").len(),
        4,
        "avif, mif1, miaf, MA1B: {lines:#?}"
    );
    assert!(
        !lines.iter().any(|row| row.starts_with("duration")),
        "without a mvhd there is no duration to report: {lines:#?}"
    );
    assert!(
        lines.contains(&"walked\tend".to_string()),
        "the three boxes must account for all {length} bytes: {lines:#?}"
    );
}

#[test]
fn walks_a_3gp_and_reports_its_duration_as_well_as_the_mp4() {
    // 3GP is the same ISO base media framing under another brand, so no new reader code is
    // involved - what it needed was its own fixture (ffmpeg muxes it via libx264) and its own
    // assertions. The 1000/1000 pair is the muxer's timescale and duration for a one-second source.
    let gp = fixture("media.3gp");
    let length = gp.len();
    assert_eq!(parse_container(&gp), FORMAT_BMFF);
    assert_eq!(container_kind(), FORMAT_BMFF);
    let lines = container_fields();
    assert_eq!(
        lines[0], "ftyp\t3gp6\t256",
        "brand and minor version: {lines:#?}"
    );
    assert_eq!(
        rows_starting(&lines, "box\t"),
        vec![
            "box\tftyp\t32\t0".to_string(),
            "box\tfree\t8\t32".to_string(),
            "box\tmdat\t1337\t40".to_string(),
            "box\tmoov\t761\t1377".to_string(),
        ],
        "top-level boxes of a 3GP file: {lines:#?}"
    );
    assert_eq!(
        rows_starting(&lines, "brand\t").len(),
        4,
        "3gp6, isom, iso2, avc1"
    );
    assert_eq!(number(&lines, "duration", 1), 1000, "timescale");
    assert_eq!(number(&lines, "duration", 2), 1000, "duration units");
    assert_eq!(
        number(&lines, "duration", 3),
        1000,
        "milliseconds, from the one-second source ffmpeg was given"
    );
    assert!(
        lines.contains(&"walked\tend".to_string()),
        "the boxes must account for all {length} bytes: {lines:#?}"
    );
}

#[test]
fn refuses_media_readers_on_bytes_that_are_not_those_formats() {
    // A png is RIFF-free and holds no fLaC, OggS or MPEG sync at the offsets these readers probe.
    let png = fixture("tiny.png");
    assert_eq!(parse_audio(&png), -2, "a png is not audio");
    assert_eq!(audio_kind(), 0, "a rejected parse must clear the kind");
    assert_eq!(
        parse_container(&png),
        -2,
        "a png is not one of these containers"
    );
    assert_eq!(container_kind(), 0);
    assert!(parse_audio(b"short") < 0, "too small to identify anything");
    assert!(parse_container(&png[..8].to_vec()) < 0);
}

#[test]
fn walks_an_avi_with_the_same_riff_reader_that_handles_webp() {
    let avi = fixture("media.avi");
    let length = avi.len();
    assert_eq!(parse_container(&avi), FORMAT_RIFF);
    let lines = container_fields();
    assert!(
        lines[0].starts_with("form\tAVI "),
        "the RIFF form type is AVI , got {}",
        lines[0]
    );
    assert_eq!(
        number(&lines, "form", 2),
        length as i64,
        "the declared length plus the 8-byte header is the file size: {lines:#?}"
    );
    assert!(
        rows_starting(&lines, "LIST\t").len() >= 1,
        "an AVI holds hdrl and movi LIST chunks: {lines:#?}"
    );
    assert!(
        lines.iter().any(|row| row.starts_with("idx1\t")),
        "ffmpeg writes the index chunk last: {lines:#?}"
    );
}

#[test]
fn reports_every_media_fixture() {
    for name in [
        "media.mp4",
        "media.mkv",
        "media.webm",
        "media.flac",
        "media.mp3",
        "media.ogg",
        "media.wav",
    ] {
        let file = fixture(name);
        let audio = parse_audio(&file);
        if audio > 0 {
            println!("{name} audio kind {audio}");
            for line in audio_fields() {
                println!("  {line}");
            }
        }
        let container = parse_container(&file);
        if container > 0 {
            println!("{name} container kind {container}");
            for line in container_fields() {
                println!("  {line}");
            }
        }
    }
}
