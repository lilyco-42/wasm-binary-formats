//! Apple icon files: the icon directory and the pixel size each embedded PNG really carries.
//!
//! `test/fixtures/tiny.icns` is compiled by Pillow's ICNS writer from a flat 64x64 RGBA image
//! (`scripts/make-icon-fixtures.py`), and `tiny_icns.probe.json` is Pillow decoding the finished
//! file entry by entry. That cross-check is the reason this reader exists in this shape: the icon
//! type tags are usually described by a remembered size table, and Pillow writes `ic13`/`ic14` at
//! 256 and 512 image pixels rather than the point sizes those names imply. So the dimensions come
//! from the payload's own PNG header, and the probe is what says the two agree.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_ICNS};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-icon-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

#[test]
fn reads_the_icon_directory_pillow_wrote() {
    let bytes = fixture("tiny.icns");
    assert_eq!(parse(&bytes), FORMAT_ICNS);
    assert_eq!(
        kind(),
        FORMAT_ICNS,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "icns", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "icns\t13452\t13452\t9\t0",
            "icon\tTOC \t72\tother",
            "icon\tic07\t402\tpng",
            "px\tic07\t128\t128",
            "icon\tic08\t867\tpng",
            "px\tic08\t256\t256",
            "icon\tic09\t2211\tpng",
            "px\tic09\t512\t512",
            "icon\tic10\t6501\tpng",
            "px\tic10\t1024\t1024",
            "icon\tic11\t120\tpng",
            "px\tic11\t32\t32",
            "icon\tic12\t193\tpng",
            "px\tic12\t64\t64",
            "icon\tic13\t867\tpng",
            "px\tic13\t256\t256",
            "icon\tic14\t2211\tpng",
            "px\tic14\t512\t512",
            "toc_lists\t8",
            "entries_end\t13452\tuncovered\t0",
            "walked\tend",
        ]
    );
}

#[test]
fn the_sizes_come_from_the_payload_not_from_a_table() {
    // The `TOC ` entry lists the eight images the file then carries, and the count derived from its
    // length agrees with the icons walked. If the directory had been read at the wrong width, both
    // this and the whole-report assertion could not hold.
    let bytes = fixture("tiny.icns");
    assert_eq!(parse(&bytes), FORMAT_ICNS);
    let lines = report();
    let icons = lines
        .iter()
        .filter(|entry| entry.starts_with("px\t"))
        .count() as i64;
    assert_eq!(icons, 8);
    assert_eq!(
        lines
            .iter()
            .find(|entry| entry.starts_with("toc_lists\t"))
            .cloned()
            .unwrap_or_default(),
        "toc_lists\t8"
    );
    // Every image is a square, and the smallest is the one a 64-pixel source can keep lossless.
    for line in lines.iter().filter(|entry| entry.starts_with("px\t")) {
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols[2], cols[3], "{line}");
    }
}

#[test]
fn an_entry_shorter_than_its_own_header_is_counted_not_walked() {
    // Self-authored: one entry that declares four bytes inside an eight-byte record. Walking it
    // would read the next icon tag out of the middle of nowhere.
    let mut bytes = b"icns".to_vec();
    bytes.extend_from_slice(&16u32.to_be_bytes());
    bytes.extend_from_slice(b"ic07");
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 4]);
    assert_eq!(parse(&bytes), FORMAT_ICNS);
    let lines = report();
    assert_eq!(lines[0], "icns\t16\t20\t0\t1", "{lines:#?}");
    assert_eq!(lines[1], "toc_lists\t0");
    assert_eq!(lines[2], "entries_end\t8\tuncovered\t12");
    assert!(
        !lines.iter().any(|entry| entry == "walked\tend"),
        "{lines:#?}"
    );
}

#[test]
fn an_entry_that_runs_past_the_file_is_refused() {
    let mut bytes = b"icns".to_vec();
    bytes.extend_from_slice(&200u32.to_be_bytes());
    bytes.extend_from_slice(b"ic09");
    bytes.extend_from_slice(&100u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 8]);
    assert_eq!(parse(&bytes), FORMAT_ICNS);
    let lines = report();
    assert_eq!(lines[0], "icns\t200\t24\t0\t1", "{lines:#?}");
    assert_eq!(
        lines
            .iter()
            .find(|entry| entry.starts_with("entries_end\t"))
            .cloned()
            .unwrap_or_default(),
        "entries_end\t8\tuncovered\t16"
    );
}

#[test]
fn a_short_or_foreign_file_is_not_an_icon_file() {
    assert_eq!(
        parse(b"icns\x00\x00\x10"),
        -1,
        "seven bytes is below the shared gate"
    );
    let mut near = b"icnX".to_vec();
    near.extend_from_slice(&[0u8; 24]);
    assert_eq!(parse(&near), -2);
}
