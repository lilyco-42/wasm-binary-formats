//! `lab.gpx` and `hand.gpx`: a GPS exchange file, read as the tree it is.
//!
//! `scripts/make-gpx-fixtures.py` writes `lab.gpx` with `gpxpy` (MIT) and then has two other
//! implementations say something about it: `gpxpy` reads its own file back and reports the waypoint,
//! route, track, segment and point counts, and `xml.etree.ElementTree` walks the same bytes with a
//! parser nobody in this chain wrote and has to agree on every element, attribute spelling and decoded
//! text. The script refuses to write `test/fixtures/gpx.probe.json` unless the two agree, so the rows
//! below are their answer about the file, not this reader's.
//!
//! `hand.gpx` is authored in that script and labelled as such, because gpxpy will not write the shapes
//! it holds: GPX 1.0 without a namespace declaration, a self-closing point, an attribute order of its
//! own, and a latitude spelled `47.60` where gpxpy would write `47.6`. The last one is the point of it:
//! the rows carry the file's own spelling, so a reader that ran the number through a float and back
//! would print `47.6` and disagree with the witness.
//!
//! What is not claimed. A coordinate is reported as text and only *checked* as a number - a document
//! whose point says `NaN`, `INF` or an exponent is refused whole, because the bounds row compares those
//! four values and no file here shows what a reader should make of them. A `<![CDATA[` or a
//! `<!DOCTYPE` is refused for the same reason: the first hides text behind a construct this reader does
//! not have, the second points at a definition the file did not carry with it.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_GPX};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-gpx-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_GPX, "the file has to be accepted first");
    assert_eq!(kind(), FORMAT_GPX, "kind() must agree with the return code");
    assert_eq!(name(), "gpx");
    report()
}

/// The log gpxpy wrote: two waypoints (one named with both entities, one bare), a route, a track of
/// two segments, and bounds that reach out to the route point and back.
#[test]
fn a_track_log_lists_the_points_its_writer_put_in_it() {
    assert_eq!(
        read(&fixture("lab.gpx")),
        vec![
            "gpx\tversion\t1.1\tcreator\tlab\twpt\t2\trte\t1\trtept\t1\ttrk\t1\ttrkseg\t2\ttrkpt\t4\tlat\t47.5\tlon\t-122.5\tmaxlat\t47.7\tmaxlon\t-122.3\tbytes\t809",
            "wpt\t0\tlat\t47.6\tlon\t-122.3\tele\t4.0\tname\tHome & base's",
            "wpt\t1\tlat\t47.5\tlon\t-122.5\tele\tnone\tname\tnone",
            "rte\t0\tname\tThere\tpts\t1",
            "trk\t0\tname\tRound\tsegs\t2\tpts\t4",
            "seg\t0\t0\tpts\t3",
            "seg\t0\t1\tpts\t1",
        ],
        "the rows are the two readers' answer about this file"
    );
}

/// The hand-written one, where everything the other file could not show is different: GPX 1.0, a
/// self-closing `rtept`, a track with no name at all, and the extremes spelled the way the file spells
/// them - `47.60` and `-122.30` are not what a float formatter would print.
#[test]
fn a_hand_written_log_keeps_its_own_spellings() {
    assert_eq!(
        read(&fixture("hand.gpx")),
        vec![
            "gpx\tversion\t1.0\tcreator\thand-written\twpt\t0\trte\t1\trtept\t2\ttrk\t1\ttrkseg\t1\ttrkpt\t1\tlat\t46.5\tlon\t-122.4\tmaxlat\t47.60\tmaxlon\t-122.30\tbytes\t280",
            "rte\t0\tname\tA <road> & a stop\tpts\t2",
            "trk\t0\tname\tnone\tsegs\t1\tpts\t1",
            "seg\t0\t0\tpts\t1",
        ]
    );
}

/// The refusals, one per rule the reader lives by: the file has to be an XML tree that closes, its root
/// has to be `gpx`, that root has to state a version, its coordinates have to be numbers this reader is
/// willing to compare, and a construct it does not read ends the walk rather than a row.
#[test]
fn a_document_that_is_not_a_closed_gpx_tree_is_not_read_as_one() {
    assert_eq!(parse(&fixture("broken.gpx")), -2, "an element that never closes");
    for (label, body) in [
        (
            "the root is not gpx",
            "<?xml version=\"1.0\"?>\n<kml version=\"1.0\"><Placemark/></kml>\n\n",
        ),
        (
            "no version on the root",
            "<?xml version=\"1.0\"?>\n<gpx><wpt lat=\"1.0\" lon=\"2.0\"/></gpx>\n\n",
        ),
        (
            "a close tag that does not match",
            "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><wpt lat=\"1.0\" lon=\"2.0\"></wptt></gpx>\n",
        ),
        (
            "an attribute with no quoted value",
            "<?xml version=\"1.0\"?>\n<gpx version=1.1><wpt lat=\"1.0\" lon=\"2.0\"/></gpx>\n\n",
        ),
        ("NaN as a coordinate", "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><wpt lat=\"NaN\" lon=\"2.0\"/></gpx>\n\n"),
        (
            "an exponent nobody wrote here",
            "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><wpt lat=\"1e2\" lon=\"2.0\"/></gpx>\n\n",
        ),
        (
            "a CDATA section",
            "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><name><![CDATA[a point]]></name><wpt lat=\"1\" lon=\"2\"/></gpx>",
        ),
        (
            "a document type",
            "<?xml version=\"1.0\"?>\n<!DOCTYPE gpx SYSTEM \"gpx.dtd\">\n<gpx version=\"1.1\"><wpt lat=\"1\" lon=\"2\"/></gpx>",
        ),
        (
            "an unknown entity",
            "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><name>&deg;</name><wpt lat=\"1\" lon=\"2\"/></gpx>\n",
        ),
        (
            "text after the root closes",
            "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\"><wpt lat=\"1\" lon=\"2\"/></gpx>trailing\n",
        ),
        ("no point at all", "<?xml version=\"1.0\"?>\n<gpx version=\"1.1\" creator=\"empty\"><metadata/></gpx>\n\n"),
    ] {
        assert_eq!(parse(body.as_bytes()), -2, "{label} was read as a GPX log");
    }
}

/// A log of more waypoints than the report lists is cut, and the counts on the summary stay the file's
/// own: the cap bounds what is printed, never what was measured.
#[test]
fn a_long_log_is_listed_up_to_a_cap_and_the_counts_stay_the_files() {
    let mut body = String::from("<?xml version=\"1.0\"?>\n<gpx version=\"1.1\" creator=\"long\">\n");
    for index in 0..70 {
        body.push_str(&format!("  <wpt lat=\"47.{index:02}\" lon=\"-122.5\"/>\n"));
    }
    body.push_str("  <trk><trkseg><trkpt lat=\"1\" lon=\"2\"/></trkseg></trk>\n</gpx>\n");
    let lines = read(body.as_bytes());
    assert!(lines[0].starts_with("gpx\tversion\t1.1\tcreator\tlong\twpt\t70\trte\t0\trtept\t0\ttrk\t1\ttrkseg\t1\ttrkpt\t1\tlat\t"), "{}", lines[0]);
    assert_eq!(lines[1], "wpt\t0\tlat\t47.00\tlon\t-122.5\tele\tnone\tname\tnone");
    assert_eq!(lines[64], "wpt\t63\tlat\t47.63\tlon\t-122.5\tele\tnone\tname\tnone");
    assert_eq!(lines.last().unwrap(), "cut\twpt\t70", "the stop is said, not hidden");
    assert_eq!(lines.len(), 68, "a summary, 64 waypoints, a track, its segment, the cut");
}
