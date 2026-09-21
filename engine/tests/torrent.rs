//! `.torrent`: bencode, read as the lengths the file states for itself.
//!
//! `scripts/make-torrent-fixtures.py` writes both fixtures with `bencode.py`, which is also the witness:
//! the probe records that the library re-encodes the file to identical bytes and what it decodes back -
//! its root keys, the size of the tree those keys hold, how deep it goes, the length of `pieces` - so
//! `keys 6`, `nodes 15`, `pieces 40` and `files 2` are another implementation's numbers, not this repo's
//! own. `bencode.py` is producer and witness of the same encoding rather than two independent ones (as
//! FreeType and psd-tools are elsewhere), so the claim stays inside what those counts can carry.
//! The format has no magic, so what makes a file a torrent here is that a walk of exact lengths lands on
//! the last byte *and* finds an `info` dictionary on the way; `tools/torrent-sim.py` is the shadow whose
//! rows these assertions were taken from.
//!
//! `pieces` is where the second self-check lives: it is a flat string of 20-byte SHA-1 hashes, so its
//! length has to divide by 20 - the one field whose arithmetic a file can get wrong while still being
//! valid bencode, which is why the row states the division rather than assuming it.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_TORRENT};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-torrent-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(named))
        .cloned()
        .unwrap_or_else(|| panic!("no row starting {named:?} in {lines:#?}"))
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(
        parse(bytes),
        FORMAT_TORRENT,
        "the file has to be accepted first"
    );
    assert_eq!(
        kind(),
        FORMAT_TORRENT,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "torrent");
    report()
}

#[test]
fn the_walk_tiles_the_file_and_the_info_dictionary_says_which_shape_it_is() {
    let lines = read(&fixture("lab.torrent"));
    assert_eq!(
        lines,
        vec![
            "bencode\tkeys\t6\tnodes\t15\tdepth\t4\tbytes\t378\tends\tyes",
            "sorted\tyes\tunsorted\t0",
            "info\tsingle\tpieces\t40\tpieces_x20\tyes\tpiece_length\t16384",
            "length\t4096",
            "announce\tudp://tracker.example.invalid:1337/announce",
            "broken\t0",
        ]
    );
    // The multi-file shape has no `length` of its own; the per-file lengths live inside `files`, and
    // reading those as the torrent's would be the easiest wrong number to print here.
    let many = read(&fixture("lab-multi.torrent"));
    assert_eq!(
        many,
        vec![
            "bencode\tkeys\t3\tnodes\t18\tdepth\t6\tbytes\t261\tends\tyes",
            "sorted\tyes\tunsorted\t0",
            "info\tmulti\tpieces\t20\tpieces_x20\tyes\tpiece_length\t16384",
            "files\t2",
            "announce\tudp://tracker.example.invalid:1337/announce",
            "broken\t0",
        ]
    );
    let record = String::from_utf8(fixture("torrent.probe.json")).unwrap();
    // The whole first row of each reading, field by field: `bencode.py` decoded the file into a Python
    // tree and counted it there (`scripts/make-torrent-fixtures.py`'s `measure`), so these are not this
    // repo's walk agreeing with itself. `keys` is the root dictionary's size, `nodes` every value it
    // holds at any depth, `depth` how far down the last one sits.
    for field in [
        "\"keys\": 6",
        "\"nodes\": 15",
        "\"depth\": 4",
        "\"bytes\": 378",
        "\"keys\": 3",
        "\"nodes\": 18",
        "\"depth\": 6",
        "\"bytes\": 261",
        "\"pieces\": 40",
        "\"files\": 2",
    ] {
        assert!(record.contains(field), "the probe does not record {field}");
    }
}

#[test]
fn key_order_is_reported_rather_than_demanded_and_a_tiling_that_fails_is_refused() {
    // Hand-built, because these are the shapes a real writer does not produce. The root dictionary puts
    // `info` before `announce`, which is against BEP-3's byte order, and the file is still readable:
    // the row says `sorted no` and counts the dictionaries that did it rather than refusing.
    let unsorted = read(
        b"d4:infod6:lengthi1e12:piece lengthi1e6:pieces20:aaaaaaaaaaaaaaaaaaaae8:announce7:trackere",
    );
    assert_eq!(row(&unsorted, "sorted"), "sorted\tno\tunsorted\t1");
    assert_eq!(row(&unsorted, "length"), "length\t1");
    assert_eq!(
        row(&unsorted, "info"),
        "info\tsingle\tpieces\t20\tpieces_x20\tyes\tpiece_length\t1"
    );
    assert_eq!(row(&unsorted, "broken"), "broken\t0");

    // A pieces string that is not a whole number of SHA-1 hashes: read, and named.
    let odd = read(b"d4:infod6:pieces21:aaaaaaaaaaaaaaaaaaaaaee");
    assert_eq!(
        row(&odd, "info"),
        "info\tmulti\tpieces\t21\tpieces_x20\tno\tpiece_length\t-"
    );
    assert_eq!(row(&odd, "files"), "files\t-");

    // Four refusals, each a different reason: bencode that is not a torrent, a value whose stated
    // length runs off the end, a dictionary that never closes, and a tree whose root is a list. Each is
    // asked for the code -2 ("nothing here is a container we know"), which is only reachable past the
    // eight-byte floor that every reader in this module shares, so the floor gets its own case below.
    let refusals: Vec<(&str, &[u8])> = vec![
        ("no info", b"d8:announce7:trackeree".as_slice()),
        ("length past the end", b"d4:name99:abce".as_slice()),
        ("never closed", b"d4:infod6:lengthi1e".as_slice()),
        ("root is a list", b"li1ei2ei3ei4ei5e1:ae".as_slice()),
    ];
    for (label, bytes) in refusals {
        assert_eq!(
            parse(bytes),
            -2,
            "{label} was read as a torrent: {:?}",
            report()
        );
        assert_eq!(count(), 0, "{label} left rows behind");
    }
    // A bare integer is well-formed bencode and far too small to carry any container's header, so the
    // answer is the size floor rather than a rejection: -1 says "too short to say", not "not a torrent".
    assert_eq!(parse(b"i42e"), -1, "four bytes cannot hold a header");
    assert_eq!(count(), 0, "the too-small answer left rows behind");
}
