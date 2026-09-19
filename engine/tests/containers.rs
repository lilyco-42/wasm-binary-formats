//! Container reader tests.
//!
//! The tar and WAV cases read files produced by Python's own `tarfile` and `wave` modules rather
//! than bytes assembled here, so the reader is checked against an independent implementation of the
//! format instead of against the same assumptions that wrote the fixture.

use apk_lens::containers::{
    at, count, kind, parse, FORMAT_AR, FORMAT_RIFF, FORMAT_TAR, FORMAT_TIFF,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}{}", FIXTURES, name);
    fs::read(&path).unwrap_or_else(|error| panic!("{path} missing: {error}"))
}

fn entries() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn octal(size: i64) -> String {
    format!("{:011o} ", size)
}

#[test]
fn lists_tar_members_written_by_python() {
    let tar = fixture("tiny.tar");
    assert_eq!(parse(&tar), FORMAT_TAR, "kind should be tar");
    let lines = entries();
    assert!(
        lines.iter().any(|line| line.starts_with("hello.txt\t5\t0")),
        "first member: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("dir/note.txt\t14\t0")),
        "nested member: {lines:?}"
    );
}

#[test]
fn walks_riff_chunks_written_by_python() {
    let wav = fixture("tiny.wav");
    assert_eq!(parse(&wav), FORMAT_RIFF);
    let lines = entries();
    assert_eq!(
        lines[0], "form\tWAVE\t108",
        "declared total = payload size field + 8: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.starts_with("fmt\t")),
        "fmt chunk present: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.starts_with("data\t")),
        "data chunk present: {lines:?}"
    );
}

#[test]
fn reads_an_ar_member_table() {
    let mut bytes = b"!<arch>\n".to_vec();
    for (name, body) in [("hello.o", &[0u8; 4][..]), ("world.o", &[1u8; 6][..])] {
        let mut header = [b' '; 60];
        header[0..name.len()].copy_from_slice(name.as_bytes());
        header[16..28].copy_from_slice(b"1700000000  ");
        header[28..34].copy_from_slice(b"0     ");
        header[34..40].copy_from_slice(b"0     ");
        header[40..48].copy_from_slice(b"100644  ");
        let size = octal(body.len() as i64);
        header[48..58].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        if body.len() % 2 == 1 {
            bytes.push(b'\n');
        }
    }
    assert_eq!(parse(&bytes), FORMAT_AR);
    let lines = entries();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], "hello.o\t4\t0     ");
    assert_eq!(lines[1], "world.o\t6\t0     ");
}

#[test]
fn walks_a_tiff_ifd_in_both_byte_orders() {
    // II, 42, first IFD at 8: count 2, two 12-byte entries, then a null next-IFD pointer.
    let mut le = vec![0u8; 8 + 2 + 24 + 4];
    le[0..2].copy_from_slice(b"II");
    le[2..4].copy_from_slice(&42u16.to_le_bytes());
    le[4..8].copy_from_slice(&8u32.to_le_bytes());
    le[8..10].copy_from_slice(&2u16.to_le_bytes());
    for (index, (tag, field_type)) in [(256u16, 3u16), (257u16, 4u16)].iter().enumerate() {
        let at = 10 + index * 12;
        le[at..at + 2].copy_from_slice(&tag.to_le_bytes());
        le[at + 2..at + 4].copy_from_slice(&field_type.to_le_bytes());
        le[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    }

    assert_eq!(parse(&le), FORMAT_TIFF);
    let lines = entries();
    assert_eq!(lines[0], "ifd0\t256\t3\t1", "ImageWidth: {lines:?}");
    assert_eq!(lines[1], "ifd0\t257\t4\t1", "ImageHeight: {lines:?}");

    let mut be = vec![0u8; le.len()];
    be[0..2].copy_from_slice(b"MM");
    be[2..4].copy_from_slice(&42u16.to_be_bytes());
    be[4..8].copy_from_slice(&8u32.to_be_bytes());
    be[8..10].copy_from_slice(&2u16.to_be_bytes());
    for (index, (tag, field_type)) in [(256u16, 3u16), (257u16, 4u16)].iter().enumerate() {
        let at = 10 + index * 12;
        be[at..at + 2].copy_from_slice(&tag.to_be_bytes());
        be[at + 2..at + 4].copy_from_slice(&field_type.to_be_bytes());
        be[at + 4..at + 8].copy_from_slice(&1u32.to_be_bytes());
    }
    assert_eq!(
        parse(&be),
        FORMAT_TIFF,
        "big-endian IFD must read the same tags"
    );
    assert_eq!(entries()[0], "ifd0\t256\t3\t1");
}

#[test]
fn refuses_truncated_and_unknown_inputs_without_panicking() {
    assert_eq!(parse(b"small"), -1, "shorter than any header");
    assert_eq!(parse(&vec![0u8; 64]), -2, "no container signature");

    let mut broken_wav = fixture("tiny.wav");
    broken_wav[4] = 0xff; // declared length far past the end of the buffer
    assert_eq!(parse(&broken_wav), FORMAT_RIFF, "the header is still valid");
    assert!(
        count() >= 2,
        "chunk walk stops at the truncation instead of running off"
    );

    let mut tar_with_bad_size = fixture("tiny.tar");
    tar_with_bad_size[124..136].copy_from_slice(b"ZZZZZZZZZZZ ");
    assert_eq!(
        parse(&tar_with_bad_size),
        FORMAT_TAR,
        "a bad member size must not condemn the archive"
    );
    let survived = entries();
    assert_eq!(
        survived.len(),
        1,
        "only the readable member is listed: {survived:?}"
    );
    assert!(survived[0].starts_with("dir/note.txt	14	"), "{survived:?}")
}
