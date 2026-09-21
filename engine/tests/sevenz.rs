//! 7z, read as an envelope: what the archive says about itself, and whether its own bytes agree.
//!
//! `test/fixtures/encoded.7z` and `test/fixtures/plain.7z` are written by py7zr 1.1.3 with a COPY
//! filter, the second with `set_encoded_header_mode(False)`; `test/fixtures/libarchive.7z` is written by
//! the `bsdtar` 3.8.4 that ships with Windows. `scripts/make-7z-fixtures.py` lists the members back out
//! of each archive - including the one py7zr did not write - and refuses to write its probe unless both
//! CRCs recompute: the start header's over bytes 12..32 and the header block's over the bytes the offset
//! points at. Every number below is one of those two recomputations, so the two `ok` states are the
//! archive agreeing with itself rather than this reader's opinion about it.
//!
//! What the reader does not do is the point of the second fixture. File names live inside the header's
//! property tree, and in the default shape that tree is itself a compressed stream; in the plain shape
//! it is in the open, but `FilesInfo` sits behind a `MainStreamsInfo` whose contents are raw numbers
//! rather than property ids, so skipping it takes the folder and coder grammar. Neither is here, so
//! neither is claimed - and the note row says which of the two cases a given file is.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_COFF, FORMAT_DER, FORMAT_SEVENZIP};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-7z-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_SEVENZIP, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_SEVENZIP, "kind() must agree with the return code");
    assert_eq!(name(), "sevenzip", "the reader has to name what it walked");
    report()
}

#[test]
fn reads_the_envelope_py7zr_wrote_and_verified() {
    let encoded = rows(&fixture("encoded.7z"));
    assert_eq!(
        encoded[0],
        "7z\t215\tbroken\t0\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tencoded"
    );
    assert_eq!(encoded[1], "crc\tstart\tc104601b\tok\theader\tee42b910\tok");
    assert_eq!(
        encoded[2],
        "note\tthe header is itself a compressed stream, so only the envelope is read"
    );
    assert_eq!(encoded[3], "walked\tend");
    assert_eq!(encoded.len(), 4, "the envelope report grew a row nobody asked for");

    let plain = rows(&fixture("plain.7z"));
    assert_eq!(
        plain[0],
        "7z\t191\tbroken\t0\tversion\t0.4\tpacked\t80\theader\tat\t112\tlen\t79\tkind\tplain"
    );
    assert_eq!(plain[1], "crc\tstart\t3d002d1f\tok\theader\tca020180\tok");
    assert_eq!(
        plain[2],
        "note\tthe header is a property tree, and reaching its names needs the streams-info walk"
    );
    assert_eq!(plain[3], "walked\tend");

    // The third archive is not from py7zr at all: `bsdtar` 3.8.4 writes version 0.3 and packs the same
    // two members into a different envelope, so the rows above are checked against a second producer.
    let bsd = rows(&fixture("libarchive.7z"));
    assert_eq!(
        bsd[0],
        "7z\t252\tbroken\t0\tversion\t0.3\tpacked\t186\theader\tat\t218\tlen\t34\tkind\tencoded"
    );
    assert_eq!(bsd[1], "crc\tstart\t18a8e7ca\tok\theader\t5e4b942e\tok");
    assert_eq!(bsd[3], "walked\tend");
}

#[test]
fn a_header_the_file_cannot_hold_is_reported_rather_than_reached() {
    // Cut 24 bytes off the end: the declared block is 20 bytes at 195, and the file now stops at 191.
    let whole = fixture("encoded.7z");
    let lines = rows(&whole[..whole.len() - 24]);
    assert_eq!(
        lines[0],
        "7z\t191\tbroken\t1\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tunreadable"
    );
    assert_eq!(lines[1], "crc\tstart\tc104601b\tok\theader\tee42b910\tunreachable");
    assert_eq!(
        lines[2],
        "note\tthe header block is past the end of the file, so its CRC cannot be checked"
    );
    assert_eq!(lines[3], "stopped\tbroken\t1");

    // The start header on its own is a complete envelope claim: the offset in it points outside the
    // bytes, which is a fact about the file rather than a reason to say nothing.
    let lines = rows(&whole[..32]);
    assert_eq!(
        lines[0],
        "7z\t32\tbroken\t1\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tunreadable"
    );
    // One byte shorter and there is no header block CRC field left to read, so the reader stays out of
    // the way instead of guessing at a version from six bytes.
    assert_ne!(parse(&whole[..31]), FORMAT_SEVENZIP);
}

#[test]
fn an_offset_from_a_file_that_is_lying_cannot_walk_off_the_end() {
    // Both halves of `packed + 32` come from the buffer, and a forged one big enough to overflow u64 is
    // reachable with eight bytes of edits, so the arithmetic has to be checked before it is trusted:
    // the answer here is a broken count and an unreachable header, not a panic.
    let mut bytes = fixture("encoded.7z");
    bytes[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    let lines = rows(&bytes);
    assert!(lines[0].contains("\tbroken\t2\t"), "{}", lines[0]);
    assert!(lines[0].ends_with("\tkind\tunreadable"), "{}", lines[0]);
    assert!(lines[1].ends_with("\tunreachable"), "{}", lines[1]);
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t2");

    // A bad start CRC and a bad header CRC are two separate claims about two separate spans, so each is
    // printed as the number the file states next to the word for whether the bytes underneath agree.
    // Byte 8 is inside the stated start CRC and byte 120 is inside the header block, which leaves the
    // offset alone (so the block is still reachable) and the tree's first byte alone (so the kind is
    // still `plain`): two breaks, nothing else moved.
    let mut twice = fixture("plain.7z");
    twice[8] ^= 0xFF;
    twice[120] ^= 0xFF;
    let lines = rows(&twice);
    assert!(lines[0].contains("\tbroken\t2\t"), "{}", lines[0]);
    assert!(lines[0].ends_with("\tkind\tplain"), "{}", lines[0]);
    assert!(lines[1].contains("\tbad\theader\t"), "{}", lines[1]);
    assert!(lines[1].ends_with("\tbad"), "{}", lines[1]);
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t2");
}

#[test]
fn the_envelope_stays_out_of_its_neighbours_way() {
    // This reader is dispatched just before COFF, so the two files whose claim to be read is weakest -
    // an object file with no magic at all, and a certificate that is only a length - have to still answer
    // with their own codes.
    assert_eq!(parse(&fixture("answer.obj")), FORMAT_COFF);
    assert_eq!(parse(&fixture("rsa.crt")), FORMAT_DER);
    // Two archives that are not this one, so a reader that only looked at six bytes would be caught
    // here rather than by somebody opening a CAB in a 7z tool and finding nothing inside.
    assert_ne!(parse(&fixture("tiny.cab")), FORMAT_SEVENZIP);
    assert_ne!(parse(&fixture("rows.arrow")), FORMAT_SEVENZIP);
    assert_ne!(kind(), FORMAT_SEVENZIP, "kind() has to follow the reader that answered");
}
