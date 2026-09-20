//! Apple binary property lists: the trailer, the offset table, every object, and the references
//! between them.
//!
//! `test/fixtures/{tiny,keyed,empty}.bplist` are written by CPython's `plistlib`
//! (`scripts/make-plist-fixtures.py`) - the only independent producer of this format on a machine
//! with no macOS in sight of it - and `plist.probe.json` records what a separate decoder read off
//! those bytes. The walk itself was mirrored in `tools/plist-sim.py` and checked against
//! `plistlib.loads` of the same files before a single row here was asserted, because the two
//! things most easily got wrong are the two widths the trailer carries: byte 6 is how wide the
//! *offset table* entries are and byte 7 is how wide the *references inside an object* are, and a
//! file can use one without the other. `tiny.bplist` does exactly that: 2-byte offsets, 1-byte
//! references.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_BPLIST};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-plist-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

/// The one row starting with `prefix`, panicking with a slice of the report rather than all 113
/// rows of it.
fn row(lines: &[String], prefix: &str) -> String {
    let want = format!("{prefix}\t");
    lines
        .iter()
        .find(|line| line.starts_with(&want))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no row starting with {prefix} among {} rows; first rows: {:?}",
                lines.len(),
                &lines[..lines.len().min(6)]
            )
        })
}

/// Lay objects out from offset 8, then write the offset table and the trailer. `number` may claim
/// more objects than were given, which is how a file that lies about its own size is built.
fn plist_with(
    objects: &[&[u8]],
    offset_size: usize,
    ref_size: usize,
    number: u64,
    top: u64,
) -> Vec<u8> {
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for object in objects {
        offsets.push(out.len() as u64);
        out.extend_from_slice(object);
    }
    let table_at = out.len() as u64;
    for index in 0..number {
        let value = offsets.get(index as usize).copied().unwrap_or(0);
        for shift in (0..offset_size).rev() {
            out.push((value >> (8 * shift)) as u8);
        }
    }
    out.extend_from_slice(&[0u8; 6]);
    out.push(offset_size as u8);
    out.push(ref_size as u8);
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&top.to_be_bytes());
    out.extend_from_slice(&table_at.to_be_bytes());
    out
}

#[test]
fn reads_every_object_cpython_wrote_and_the_graph_between_them() {
    let bytes = fixture("tiny.bplist");
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    assert_eq!(
        kind(),
        FORMAT_BPLIST,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "bplist", "the reader has to name what it walked");
    let lines = report();
    assert_eq!(
        lines.len(),
        113,
        "header, trailer, 52 objects, 54 references and four summary rows"
    );
    assert_eq!(lines[0], "bplist\t406\t406\t52\t0", "{:?}", &lines[0]);
    assert_eq!(
        lines[1], "trailer\t2\t1\t270\t374",
        "2-byte offsets and 1-byte references are different numbers"
    );
    // One row per marker class, each value read out of the bytes plistlib laid down.
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tdict\t14\tnarrow");
    assert_eq!(row(&lines, "obj\t7"), "obj\t7\tascii\t3\tneg");
    assert_eq!(row(&lines, "obj\t15"), "obj\t15\tdata\t8\tpng");
    assert_eq!(row(&lines, "obj\t16"), "obj\t16\tint\t42\t1");
    assert_eq!(row(&lines, "obj\t17"), "obj\t17\tint\t8589934592\t8");
    assert_eq!(row(&lines, "obj\t24"), "obj\t24\tint\t-7\t8");
    assert_eq!(
        row(&lines, "obj\t18"),
        "obj\t18\tdate\t2026-09-20\t02:47:12"
    );
    assert_eq!(
        row(&lines, "obj\t51"),
        "obj\t51\tdate\t2001-01-01\t00:00:00"
    );
    assert_eq!(row(&lines, "obj\t28"), "obj\t28\tbool\ttrue");
    assert_eq!(row(&lines, "obj\t29"), "obj\t29\tbool\tfalse");
    assert_eq!(row(&lines, "obj\t30"), "obj\t30\tarray\t20\twide");
    assert_eq!(row(&lines, "obj\t49"), "obj\t49\treal\t0.5");
    assert_eq!(row(&lines, "obj\t50"), "obj\t50\tutf16\t7\théllo世界");
    // The dictionary's slots split into keys then values at its own count, which is the one layout
    // claim this whole read rests on: slot 13 is still a key, slot 14 is the first value.
    assert_eq!(row(&lines, "child\t0\t13"), "child\t0\t13\t14\tkey");
    assert_eq!(row(&lines, "child\t0\t14"), "child\t0\t14\t15\tvalue");
    assert_eq!(row(&lines, "child\t30\t19"), "child\t30\t19\t48\telement");
    assert_eq!(row(&lines, "edges"), "edges\t54\tunresolved\t0");
    assert_eq!(row(&lines, "reach"), "reach\t52\tdepth\t4\tcycles\t0");
    assert_eq!(
        row(&lines, "offsets"),
        "offsets\t52\tstrictly_increasing\t1"
    );
    assert_eq!(row(&lines, "stopped"), "stopped\t0");
    assert_eq!(
        lines.last().map(String::as_str),
        Some("walked\tend"),
        "270 + 52*2 + 32 is the file, to the byte"
    );
}

#[test]
fn follows_uid_references_through_a_keyed_archiver_graph() {
    let bytes = fixture("keyed.bplist");
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(lines[0], "bplist\t213\t213\t23\t0");
    assert_eq!(lines[1], "trailer\t1\t1\t158\t181");
    assert_eq!(row(&lines, "obj\t6"), "obj\t6\tarray\t5\tnarrow");
    assert_eq!(row(&lines, "obj\t7"), "obj\t7\tnull");
    assert_eq!(row(&lines, "obj\t11"), "obj\t11\tuid\t4");
    assert_eq!(row(&lines, "obj\t12"), "obj\t12\tdata\t4\tbytes");
    assert_eq!(row(&lines, "obj\t22"), "obj\t22\tint\t100000\t4");
    assert_eq!(row(&lines, "child\t19"), "child\t19\t0\t20\tkey");
    assert_eq!(row(&lines, "child\t9\t1"), "child\t9\t1\t11\tvalue");
    assert_eq!(row(&lines, "edges"), "edges\t22\tunresolved\t0");
    assert_eq!(
        row(&lines, "reach"),
        "reach\t23\tdepth\t5\tcycles\t0",
        "every object is reachable from $top, five levels deep"
    );
    assert_eq!(lines.last().map(String::as_str), Some("walked\tend"));
}

#[test]
fn a_file_holding_only_an_empty_dictionary_still_tiles() {
    let bytes = fixture("empty.bplist");
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    assert_eq!(
        report(),
        vec![
            "bplist\t42\t42\t1\t0",
            "trailer\t1\t1\t9\t10",
            "obj\t0\tdict\t0\tnarrow",
            "edges\t0\tunresolved\t0",
            "reach\t1\tdepth\t1\tcycles\t0",
            "offsets\t1\tstrictly_increasing\t1",
            "stopped\t0",
            "walked\tend",
        ]
    );
}

#[test]
fn an_object_pointing_outside_the_object_area_is_counted_not_followed() {
    // Self-authored: two objects, and the table's second entry aims past the trailer.
    let mut bytes = plist_with(&[b"\x52hi", b"\x52yo"], 1, 1, 2, 0);
    let table_at = bytes.len() - 34;
    bytes[table_at + 1] = 20;
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(lines[0], "bplist\t48\t48\t2\t0");
    assert_eq!(lines[1], "trailer\t1\t1\t14\t16");
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tascii\t2\thi");
    assert_eq!(row(&lines, "obj\t1"), "obj\t1\tbad\toffset");
    assert_eq!(row(&lines, "offsets"), "offsets\t1\tstrictly_increasing\t1");
    assert_eq!(row(&lines, "reach"), "reach\t1\tdepth\t1\tcycles\t0");
}

#[test]
fn a_reference_beyond_the_object_count_is_reported_as_broken() {
    // Self-authored: a one-pair dictionary whose value names object 99 in a three-object file.
    let bytes = plist_with(&[&[0xd1u8, 0x01, 0x63], b"\x51k", b"\x51v"], 1, 1, 3, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(lines[0], "bplist\t50\t50\t3\t0");
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tdict\t1\tnarrow");
    assert_eq!(row(&lines, "obj\t0\tbad"), "obj\t0\tbad\trefs\t1");
    assert_eq!(row(&lines, "child\t0"), "child\t0\t0\t1\tkey");
    assert_eq!(row(&lines, "edges"), "edges\t1\tunresolved\t0");
    assert_eq!(row(&lines, "reach"), "reach\t2\tdepth\t2\tcycles\t0");
}

#[test]
fn a_reference_back_up_the_graph_is_a_cycle_and_says_so() {
    // Self-authored: a dictionary whose value is the dictionary itself.
    let bytes = plist_with(&[&[0xd1u8, 0x01, 0x00], b"\x51k"], 1, 1, 2, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(row(&lines, "edges"), "edges\t2\tunresolved\t0");
    assert_eq!(
        row(&lines, "reach"),
        "reach\t2\tdepth\t2\tcycles\t1",
        "sharing is not a cycle, but this is"
    );
}

#[test]
fn a_wide_count_must_actually_be_an_integer() {
    // Self-authored: 0xAF says "the count follows", and what follows is a string marker.
    let bytes = plist_with(&[&[0xafu8, 0x51, 0x00]], 1, 1, 1, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(lines[0], "bplist\t44\t44\t1\t0");
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tbad\tcount");
    assert_eq!(row(&lines, "edges"), "edges\t0\tunresolved\t0");
}

#[test]
fn a_count_beyond_the_walk_budget_is_still_reported_as_claimed() {
    // Self-authored: a wide array that claims a hundred thousand elements. The claim is a fact
    // about the file, so it is printed; the references are not walked, so none are printed.
    let mut object = vec![0xafu8, 0x13];
    object.extend_from_slice(&100_000u64.to_be_bytes());
    let bytes = plist_with(&[&object], 1, 1, 1, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tarray\t100000\twide");
    assert_eq!(row(&lines, "edges"), "edges\t0\tunresolved\t0");
    assert_eq!(row(&lines, "reach"), "reach\t1\tdepth\t1\tcycles\t0");
    assert_eq!(row(&lines, "stopped"), "stopped\t0");
}

#[test]
fn a_payload_running_into_the_trailer_is_refused() {
    // Self-authored: a UTF-16 string of 100 characters in a file that has 3 bytes of object area.
    let bytes = plist_with(&[&[0x6fu8, 0x10, 100u8]], 1, 1, 1, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tbad\tshort");
    assert_eq!(row(&lines, "stopped"), "stopped\t0");
}

#[test]
fn a_marker_no_writer_produces_is_named_by_its_byte_only() {
    // Sets and ordered sets have no fixture, so the reader must not invent a name for the nibble:
    // the byte is the only claim it can make.
    let bytes = plist_with(&[b"\xb0", b"\xc0", b"\x70", b"\x05"], 1, 1, 4, 0);
    assert_eq!(parse(&bytes), FORMAT_BPLIST);
    let lines = report();
    assert_eq!(row(&lines, "obj\t0"), "obj\t0\tmarker\t0xb0");
    assert_eq!(row(&lines, "obj\t1"), "obj\t1\tmarker\t0xc0");
    assert_eq!(row(&lines, "obj\t2"), "obj\t2\tmarker\t0x70");
    assert_eq!(row(&lines, "obj\t3"), "obj\t3\tmarker\t0x05");
    assert!(!lines.iter().any(|line| line.starts_with("obj\t0\tset")));
}

#[test]
fn a_file_whose_trailer_sizes_are_unusable_is_not_claimed() {
    // Byte 6 zero is not an offset width, so there is nothing to walk and nothing to name.
    let bytes = plist_with(&[b"\x51hi"], 0, 1, 1, 0);
    assert_eq!(parse(&bytes), -2, "an unusable trailer is not a read");
    let swapped = plist_with(&[b"\x51hi"], 1, 30, 1, 0);
    assert_eq!(parse(&swapped), -2, "30 is not a reference width either");
    assert_eq!(
        parse(b"bplist00truncated short"),
        -2,
        "no room for a trailer"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no plist magic");
}
