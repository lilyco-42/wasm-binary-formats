//! MPEG-2 transport stream: the packet grid, and the program map followed from PAT to PMT.
//!
//! `test/fixtures/media.ts` is muxed by ffmpeg (`scripts/make-media-fixtures.sh` writes it and keeps
//! `media_ts.probe.json`, ffprobe's independent reading: one program, `mpeg2video`, 0.400 s). Every
//! row below was read out of those bytes first; the stream repeats each table four times, which is
//! what makes the deduplication observable.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_TS};
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

#[test]
fn walks_the_packets_and_maps_the_program_ffmpeg_muxed() {
    let ts = fixture("media.ts");
    assert_eq!(parse(&ts), FORMAT_TS);
    assert_eq!(kind(), FORMAT_TS, "kind() must agree with the return code");
    assert_eq!(name(), "mpegts", "the reader has to name what it walked");
    // The whole report, not a few fields: 27 packets of 188 bytes with no sync failure, one program
    // (number 1) whose PMT rides PID 4096, that PMT naming PID 256 as both its PCR and its only
    // elementary stream with stream type 0x02 (H.262) - and the four repeats of both tables folded
    // into one row each.
    assert_eq!(
        report(),
        vec![
            "ts\t188\t27\t0",
            "pat\t1\t1\t4096",
            "es\t1\t0x2\t256",
            "pmt\t1\t0\t256\t1",
            "pid\t17\t1",
            "pid\t0\t4",
            "pid\t4096\t4",
            "pid\t256\t18",
            "pusi\t13\tcc_gaps\t0",
            "trailer_bytes\t0",
            "partial_sections\t4",
            "walked\tend",
        ]
    );
}

#[test]
fn counts_the_sections_that_do_not_fit_one_packet() {
    // Four of the thirteen payload-unit-start packets open a table that the packet cannot hold -
    // video access units continuing across packets - and the reader says so instead of half-decoding
    // them. Nothing here claims a reassembled section, so nothing can be wrong about one.
    let ts = fixture("media.ts");
    assert_eq!(parse(&ts), FORMAT_TS);
    let lines = report();
    let pusi = lines
        .iter()
        .find(|entry| entry.starts_with("pusi\t"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(pusi, "pusi\t13\tcc_gaps\t0");
    assert_eq!(
        lines
            .iter()
            .filter(|entry| entry.starts_with("partial_sections\t"))
            .count(),
        1
    );
}

#[test]
fn says_so_when_the_tail_is_not_a_packet() {
    // Ten bytes cut off the end: the grid still holds for 26 packets, but the walk cannot claim it
    // covered the file, so `walked end` has to go and the remainder has to be named.
    let mut ts = fixture("media.ts");
    let original = ts.len();
    ts.truncate(original - 10);
    assert_eq!(parse(&ts), FORMAT_TS);
    let lines = report();
    assert_eq!(lines[0], "ts\t188\t26\t0", "{lines:#?}");
    assert_eq!(
        lines
            .iter()
            .find(|entry| entry.starts_with("trailer_bytes\t"))
            .cloned()
            .unwrap_or_default(),
        "trailer_bytes\t178"
    );
    assert!(
        !lines.iter().any(|entry| entry == "walked\tend"),
        "a short tail must not report a completed walk: {lines:#?}"
    );
}

#[test]
fn a_single_sync_byte_is_not_a_transport_stream() {
    // One 188-byte packet that starts with 0x47 is not enough: the grid is only established by a
    // second packet landing on the same stride.
    let mut one = vec![0x47u8];
    one.extend_from_slice(&[0u8; 187]);
    assert_eq!(parse(&one), -2, "one packet is not a grid");
    let mut two = one.clone();
    two.extend_from_slice(&[0x48u8; 188]);
    assert_eq!(parse(&two), -2, "the second packet has to sync");
    assert_eq!(
        parse(&[0x47; 7]),
        -1,
        "and anything under eight bytes is refused before any reader runs"
    );
}
