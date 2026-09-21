//! `lab.pdb`: an MSF 7.00 program database, read as the table the file keeps for itself.
//!
//! `scripts/make-pdb-fixtures.py` compiles a small C file with `clang -gcodeview`, links it with
//! `lld-link /DEBUG`, and then asks `llvm-pdbutil dump --summary --streams --stream-blocks
//! --type-stats` about the result. That output is the witness, and the script refuses to write
//! `test/fixtures/pdb.probe.json` unless its own walk of the bytes agrees with it: page size, block
//! count, every stream's size and block list, the labels llvm attaches to the reserved indices, the
//! PDB stream's version, signature and age, and the record bytes the TPI header declares - which
//! llvm counts independently as `Total: 10 entries (212 bytes)`.
//!
//! Two things are deliberately not claimed. The feature word is printed as a word: llvm's
//! `Has Types / Has IDs / Has Debug Info` answers turned out to be about which streams the directory
//! holds - which is what the `has` rows say, checked against the witness by the same script - and not
//! names for its bits, which an earlier draft assumed and the witness refused. And the GUID is the
//! sixteen bytes as they lie in the stream rather than a reformatted UUID, because its first word
//! repeats the signature and the rest of the ordering would be a claim with nothing behind it.
//!
//! The type records *inside* the TPI stream are not decoded here: that leaf reader lives in the
//! analysis module, next to the names and strings it works with, and is reached by a different row.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_PDB};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-pdb-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_PDB, "the file has to be accepted first");
    assert_eq!(kind(), FORMAT_PDB, "kind() must agree with the return code");
    assert_eq!(name(), "pdb");
    report()
}

/// The whole container, row by row: eighteen pages of 4 096 bytes, fifteen streams, and the two
/// header streams the directory reaches. A 73 728-byte file whose last byte is the end of its
/// directory page is the arithmetic every offset below comes out of.
#[test]
fn a_linked_pdb_lists_the_streams_its_own_directory_holds() {
    let lines = read(&fixture("lab.pdb"));
    assert_eq!(
        lines,
        vec![
            "container\tpdb\t7.00\tblock\t4096\tpages\t18\tfree\t2\tstreams\t15\tdir\t116@17",
            "stream\t0\tsize\t0\tblocks\t0\tname\told-msf-directory",
            "stream\t1\tsize\t93\tblocks\t1\tname\tpdb",
            "stream\t2\tsize\t268\tblocks\t1\tname\ttpi",
            "stream\t3\tsize\t693\tblocks\t1\tname\tdbi",
            "stream\t4\tsize\t1912\tblocks\t1\tname\tipi",
            "stream\t5\tsize\t0\tblocks\t0",
            "stream\t6\tsize\t580\tblocks\t1",
            "stream\t7\tsize\t608\tblocks\t1",
            "stream\t8\tsize\t144\tblocks\t1",
            "stream\t9\tsize\t48\tblocks\t1",
            "stream\t10\tsize\t160\tblocks\t1",
            "stream\t11\tsize\t600\tblocks\t1",
            "stream\t12\tsize\t464\tblocks\t1",
            "stream\t13\tsize\t66\tblocks\t1",
            "stream\t14\tsize\t52\tblocks\t1",
            "has\tpdb\tyes",
            "has\ttpi\tyes",
            "has\tdbi\tyes",
            "has\tipi\tyes",
            "header\tpdb\tversion\t20000404\tsignature\t1921718505\tage\t1",
            "guid\te9188b72e8e4010b4c4c44205044422e",
            "features\t0x11",
            "tpi\tversion\t20040203\theader\t56\ttypes\t0x1000..0x100a\tbytes\t212",
        ]
    );
}

/// The same table the generator wrote, so the fixture and the probe cannot drift apart: the probe
/// holds the rows this reader is expected to produce, escaped as JSON text.
#[test]
fn the_probe_and_the_fixture_describe_the_same_file() {
    let probe = String::from_utf8(fixture("pdb.probe.json")).expect("the probe is UTF-8");
    for want in [
        "container\\tpdb\\t7.00\\tblock\\t4096\\tpages\\t18",
        "stream\\t2\\tsize\\t268\\tblocks\\t1\\tname\\ttpi",
        "header\\tpdb\\tversion\\t20000404\\tsignature\\t1921718505\\tage\\t1",
        "tpi\\tversion\\t20040203\\theader\\t56\\ttypes\\t0x1000..0x100a\\tbytes\\t212",
    ] {
        assert!(probe.contains(want), "the probe lost {want:?}");
    }
    // llvm's own words, frozen with it: ten records covering 212 bytes, which is what the TPI
    // header's `bytes` field above claims for itself.
    assert!(
        probe.contains("10 entries") && probe.contains("212"),
        "the witness no longer counts the records the header declares"
    );
}

/// A file that only has the magic is not a container: nothing after byte 32 has been read yet, and
/// a page size of zero would make every later offset a division by it.
#[test]
fn a_header_without_a_container_is_refused() {
    assert_eq!(parse(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"), -2);
    assert_eq!(count(), 0, "a refusal leaves no rows behind");

    // Page size zero, and a page size the file cannot hold a page of.
    let mut zero = fixture("lab.pdb");
    zero[32..36].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(parse(&zero), -2, "a zero page size is arithmetic on nothing");

    let mut huge = fixture("lab.pdb");
    huge[32..36].copy_from_slice(&(1u32 << 30).to_le_bytes());
    assert_eq!(parse(&huge), -2, "no file this size holds a page that wide");

    let mut odd = fixture("lab.pdb");
    odd[32..36].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(parse(&odd), -2, "MSF pages are powers of two");

    // A directory size that cannot be made of whole pages of the stream count it declares.
    let mut lying = fixture("lab.pdb");
    lying[44..48].copy_from_slice(&8u32.to_le_bytes());
    assert!(
        parse(&lying) == -2 || report().iter().all(|each| !each.starts_with("stream\t15")),
        "a nine-byte directory cannot list fifteen streams: {:#?}",
        report()
    );
}

/// Losing the last page loses the directory itself, which is where every offset comes from: that is
/// a refusal, not a partial report.
#[test]
fn a_pdb_without_its_directory_page_is_not_read_at_all() {
    let full = fixture("lab.pdb");
    let cut = full.get(..full.len() - 4096).expect("the fixture has pages");
    assert_eq!(parse(cut), -2, "the directory page is gone with it");
    assert_eq!(count(), 0);
}

/// A directory that names a page the file does not hold still describes its own contents, so the
/// table stands; what cannot be reached is the bodies, and those rows say so instead of printing
/// numbers read out of nothing.
#[test]
fn a_stream_pointed_off_the_end_is_reported_as_unreachable() {
    let mut broken = fixture("lab.pdb");
    let dir = 17 * 4096;
    // Stream 0 is empty, so the first block entry in the directory is stream 1's, and the next
    // stream 2's: the PDB header stream and the type stream.
    for at in [dir + 64, dir + 68] {
        broken[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    let lines = read(&broken);
    assert!(
        lines[0].starts_with("container\tpdb\t7.00"),
        "the superblock still reads: {}",
        lines[0]
    );
    assert!(
        lines
            .iter()
            .any(|each| each == "stream\t1\tsize\t93\tblocks\t1\tname\tpdb"),
        "the table is the file's own claim: {lines:#?}"
    );
    assert!(
        lines.iter().any(|each| each == "header\tpdb\tunreadable"),
        "its body is not: {lines:#?}"
    );
    assert!(
        lines.iter().any(|each| each == "tpi\tunreadable"),
        "neither is the type stream's: {lines:#?}"
    );
    assert!(
        !lines.iter().any(|each| each.starts_with("guid\t")),
        "an unreadable stream cannot have a GUID: {lines:#?}"
    );
}
