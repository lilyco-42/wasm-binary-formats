//! `lab.jsonc`: a JSON document that a strict parser refuses, read as the tree it holds.
//!
//! `scripts/make-jsonc-fixtures.py` writes the fixture itself - a text format has no producer to ask
//! - and then checks every claim against Microsoft's `jsonc-parser`, the parser VS Code uses for its
//! own settings: the comment count comes from what its scanner reports, the member rows and their
//! depths from the tree it builds, the trailing-comma count from the bytes between a container's last
//! member and its bracket at the offsets that tree names, and `strict no` from `json.loads` refusing
//! the very same file. The script refuses to write `test/fixtures/jsonc.probe.json` unless all four
//! agree, so the rows below are the witness's, not a reading of the fixture by hand.
//!
//! Two things are deliberately not claimed. The scalars are echoed as the file spells them, which the
//! generator verifies is what the parser's value would print as - a fixture whose number came out
//! differently (an exponent, a leading zero) is refused rather than reformatted. And a document whose
//! root is not an object is not read here at all: `members` counts the root's own, which is a fact
//! about the settings file the label describes.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_JSONC};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-jsonc-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_JSONC, "the file has to be accepted first");
    assert_eq!(kind(), FORMAT_JSONC, "kind() must agree with the return code");
    assert_eq!(name(), "jsonc");
    report()
}

/// The settings document, row by row: three line comments, one block comment, four trailing commas,
/// eleven members two levels deep, and every value spelled the way the file spells it. The paths are
/// dotted for object members and bracketed for array items because that is how the witness's tree
/// nests, and a `//` that only lives inside a URL string is the reason the comment count is not
/// higher.
#[test]
fn a_commented_settings_file_lists_the_tree_the_parser_builds() {
    let lines = read(&fixture("lab.jsonc"));
    assert_eq!(
        lines,
        vec![
            "jsonc\tmembers\t11\tline\t3\tblock\t1\ttrailing\t4\tstrict\tno\tdepth\t2\tbytes\t725",
            "key\teditor.formatOnSave\t1\tboolean\ttrue",
            "key\teditor.tabSize\t1\tnumber\t4",
            "key\twindow.title\t1\tstring\t\"${activeEditorShort}${separator}my workspace\"",
            "key\tdocs.homepage\t1\tstring\t\"https://example.test/docs\"",
            "key\tfiles.exclude\t1\tobject\t2",
            "key\tfiles.exclude.**/tmp\t2\tboolean\ttrue",
            "key\tfiles.exclude.**/*.log\t2\tboolean\tfalse",
            "key\tsearch.exclude\t1\tarray\t2",
            "key\tsearch.exclude[0]\t2\tstring\t\"out\"",
            "key\tsearch.exclude[1]\t2\tstring\t\"dist\"",
            "key\teditor.rulers\t1\tarray\t3",
            "key\teditor.rulers[0]\t2\tnumber\t80",
            "key\teditor.rulers[1]\t2\tnumber\t100",
            "key\teditor.rulers[2]\t2\tnumber\t120",
            "key\tworkbench.colorCustomizations\t1\tobject\t1",
            "key\tworkbench.colorCustomizations.editor.background\t2\tstring\t\"#1e1e1e\"",
            "key\tpreview.opacity\t1\tnumber\t0.75",
            "key\tpreview.indent\t1\tnumber\t-1",
            "key\tpreview.theme\t1\tnull\tnull",
        ],
        "the report is the tree, in the file's own order"
    );
}

/// A file with no comment at all is still not strict JSON if a container closes on a comma, and the
/// reader has to say so with the same shape: zero of each comment kind, one trailing comma, no
/// container to walk into.
#[test]
fn a_trailing_comma_alone_makes_the_file_jsonc() {
    assert_eq!(
        read(&fixture("trailing.jsonc")),
        vec![
            "jsonc\tmembers\t2\tline\t0\tblock\t0\ttrailing\t1\tstrict\tno\tdepth\t1\tbytes\t51",
            "key\tname\t1\tstring\t\"trailing-comma-only\"",
            "key\tcount\t1\tnumber\t3",
        ]
    );
}

/// The three ways this reader says no: a comment that never closes, a document that is strict JSON
/// after all, and a number the grammar does not allow. The first is the fixture's own case - the
/// witness reports `UnexpectedEndOfComment` for it and lists no rows, so a reader that finished the
/// comment by guessing would report a tree no parser builds.
#[test]
fn a_file_that_does_not_finish_what_it_starts_is_not_read() {
    assert_eq!(parse(&fixture("broken.jsonc")), -2, "an open comment");
    assert_eq!(parse(b"{\n  \"a\": 1\n}"), -2, "strict JSON is the json label");
    assert_eq!(parse(b"{\"a\": 1}\nx"), -2, "text after the document");
    assert_eq!(parse(b"[\n  \"a\",\n  \"b\"\n// c\n]"), -2, "an array root is not a settings document");
    assert_eq!(
        parse(b"{\"a\\tb\": 1,\n// c\n}"),
        -2,
        "a key that spells itself with an escape is not decoded into a path"
    );
    for bad in [
        "{\"a\": 01,\n// c\n}",
        "{\"a\": +1,\n// c\n}",
        "{\"a\": 1e,\n// c\n}",
        "{\"a\": -,\n// c\n}",
        "{\"a\": 1.,\n// c\n}",
    ] {
        assert_eq!(parse(bad.as_bytes()), -2, "{bad} holds a number no JSON parser accepts");
    }
    // A document with no members at all is still a document: the comment is the fact the row reports,
    // and `depth` falls back to zero because no member row exists to take a maximum from.
    assert_eq!(
        read(b"{\n// c\n}"),
        vec!["jsonc\tmembers\t0\tline\t1\tblock\t0\ttrailing\t0\tstrict\tno\tdepth\t0\tbytes\t8"]
    );
    // The same members the loop above refuses, written well, and the file is read: the refusal there
    // is about the number and nothing else.
    assert_eq!(read(b"{\"a\": 1,\n// c\n}").len(), 2, "summary plus one member");
}

/// A document with more members than the report lists is reported as cut, and the count it names is
/// the file's own - the cap bounds the rows, never the measurement. Depth keeps the summary honest
/// too: the members are all one level in.
#[test]
fn a_wide_document_is_listed_up_to_a_cap_and_no_further() {
    let mut text = String::from("{\n  // many members, one report\n");
    for index in 0..70 {
        text.push_str(&format!("  \"k{index}\": {index},\n"));
    }
    text.push_str("  \"z\": {\"inner\": 1}\n}\n");
    let lines = read(text.as_bytes());
    assert_eq!(lines.len(), 66, "a summary, the first 64 rows, then the cut");
    assert_eq!(
        lines[0],
        format!("jsonc\tmembers\t71\tline\t1\tblock\t0\ttrailing\t0\tstrict\tno\tdepth\t2\tbytes\t{}", text.len())
    );
    assert_eq!(lines[1], "key\tk0\t1\tnumber\t0");
    assert_eq!(lines[64], "key\tk63\t1\tnumber\t63");
    assert_eq!(lines[65], "cut\tkeys\t72", "71 members plus the nested object's row");
    assert!(!lines.iter().any(|row| row.contains("k64")), "the cap is a stop, not a filter");
}
