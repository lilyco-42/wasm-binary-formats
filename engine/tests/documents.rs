//! Document-container tests: PDF with a classic cross-reference table.
//!
//! `test/fixtures/tiny.pdf` is written by Pillow's PDF driver (see
//! `scripts/make-media-fixtures.sh`), so the offsets asserted here are another implementation's
//! output, read back out of the committed bytes rather than recalled from the specification. The
//! strongest assertion is `verified`: every live xref row has to point at an object header that
//! says the same object number, which cannot hold if the table is read at the wrong width.

use apk_lens::containers::{at, count, kind, parse, FORMAT_PDF};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-media-fixtures.sh: {error}")
    })
}

fn lines() -> Vec<String> {
    (0..count()).filter_map(at).collect()
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

#[test]
fn reads_the_cross_reference_table_pillow_wrote() {
    let pdf = fixture("tiny.pdf");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    assert_eq!(kind(), FORMAT_PDF, "kind() must agree with the return code");
    let report = lines();
    assert_eq!(report[0], "pdf\t1.4", "the header version, {report:#?}");
    assert_eq!(
        number(&report, "startxref", 1),
        1289,
        "the entry point the file advertises"
    );
    assert_eq!(
        number(&report, "rows", 1),
        7,
        "the subsection header says 0 7: {report:#?}"
    );
    assert_eq!(number(&report, "rows", 3), 6, "six live objects");
    assert_eq!(number(&report, "rows", 5), 1, "the free slot at object 0");
    assert_eq!(
        number(&report, "verified", 1),
        6,
        "every live row points at its own object header: {report:#?}"
    );
    assert_eq!(number(&report, "verified", 3), 6);
    // Offsets Pillow chose, visible in the committed file: object 1 is the image stream at 144 and
    // the page tree sits at 40, so the table is read in file order rather than object order.
    let row = report
        .iter()
        .find(|entry| entry.starts_with("xref\t1\t"))
        .unwrap_or_else(|| panic!("object 1 should be listed: {report:#?}"));
    assert_eq!(row, "xref\t1\t144\t0\tn");
    assert!(report.iter().any(|entry| entry == "xref\t0\t0\t65536\tf"));
    assert!(
        report.iter().any(|entry| entry == "ref\tRoot\t4\t0"),
        "the trailer's /Root reference: {report:#?}"
    );
    assert!(
        report.iter().any(|entry| entry == "ref\tInfo\t6\t0"),
        "the trailer's /Info reference: {report:#?}"
    );
    assert!(
        !report.iter().any(|entry| entry.starts_with("ref\tSize")),
        "/Size is a number, not a reference: {report:#?}"
    );
}

#[test]
fn names_an_xref_stream_instead_of_guessing_at_it() {
    // PDF 1.5 keeps its cross-reference data in a compressed stream. Handing back offsets from a
    // table that is not there would be worse than saying the section is unsupported, so this file
    // is identified and the walk stops.
    let mut pdf = b"%PDF-1.7\n% padding padding padding padding padding padding padding\n".to_vec();
    pdf.extend_from_slice(b"2 0 obj\n<< /Type/XRef /W [1 4 0] >>\nstream\nx\nendstream\nendobj\n");
    pdf.extend_from_slice(b"trailer\n<< /Root 2 0 R /Size 3 >>\nstartxref\n9\n%%EOF\n");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(report[0], "pdf\t1.7");
    assert_eq!(number(&report, "startxref", 1), 9);
    assert_eq!(
        number(&report, "xref_stream", 1),
        1,
        "reported as a stream, not walked: {report:#?}"
    );
    assert!(
        !report.iter().any(|entry| entry.starts_with("rows")),
        "no table rows can be claimed without decoding the stream: {report:#?}"
    );
}
