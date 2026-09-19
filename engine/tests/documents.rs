//! Document-container tests: PDF with a classic cross-reference table, walked down to its pages.
//!
//! `test/fixtures/tiny.pdf` and `test/fixtures/pillow-3p.pdf` are written by Pillow's PDF driver,
//! `test/fixtures/chromium.pdf` and `chromium-2p.pdf` by the PDF writer in Chromium's headless print
//! path (see `scripts/make-pdf-fixtures.sh`), so the offsets, object numbers and page boxes
//! asserted here are two independent implementations' output read back out of the committed bytes,
//! not recalled from the specification. The strongest assertion is `verified`: every live xref row
//! has to point at an object header that says the same object number, which cannot hold if the table
//! is read at the wrong width.
//!
//! The nested-tree and cycle cases are hand-written rather than produced, because neither writer
//! emits a multi-level page tree for a document this small. They cover the walk's arithmetic and
//! its caps, not a producer's layout.

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

fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"))
        .clone()
}

fn count_rows(lines: &[String], prefix: &str) -> i64 {
    lines
        .iter()
        .filter(|entry| entry.starts_with(prefix))
        .count() as i64
}

/// A classic-xref PDF built from object bodies, with the table written from the offsets the builder
/// actually used. Object numbers are 1-based in the order given.
const PROLOGUE: &[u8] = b"%PDF-1.4\n% hand-written for a page tree this small\n";

fn build_pdf(objects: &[&str]) -> Vec<u8> {
    let mut out = PROLOGUE.to_vec();
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }
    let start = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65536 f \n");
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Root 1 0 R /Size {} >>\nstartxref\n{start}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
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
    let first = report
        .iter()
        .find(|entry| entry.starts_with("xref\t1\t"))
        .unwrap_or_else(|| panic!("object 1 should be listed: {report:#?}"));
    assert_eq!(first, "xref\t1\t144\t0\tn");
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
fn follows_the_trailer_to_the_page_pillow_wrote() {
    let pdf = fixture("tiny.pdf");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    // Both references land on the object header their own xref row claims, which is what makes the
    // rows below a walk through the file rather than a text search.
    assert_eq!(row(&report, "resolves"), "resolves\tRoot\t4\t40\t1");
    assert_eq!(
        count_rows(&report, "resolves\t"),
        2,
        "the trailer lists /Root and /Info: {report:#?}"
    );
    assert!(
        report
            .iter()
            .any(|entry| entry == "resolves\tInfo\t6\t1187\t1"),
        "{report:#?}"
    );
    assert_eq!(row(&report, "catalog"), "catalog\t4\tpages\t5");
    assert_eq!(row(&report, "pages"), "pages\t5\tcount\t1\tkids\t1");
    assert_eq!(row(&report, "page"), "page\t2\tmedia\t5\t3");
    assert_eq!(
        row(&report, "leaves"),
        "leaves\t1\tvisited\t1\ttruncated\t0"
    );
}

#[test]
fn reads_the_letter_page_skia_wrote_for_one_sheet() {
    let pdf = fixture("chromium.pdf");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(
        report[0], "pdf\t1.4",
        "Chromium still writes a classic table: {report:#?}"
    );
    assert_eq!(
        number(&report, "verified", 1),
        number(&report, "verified", 3),
        "every live row in a 27-object file: {report:#?}"
    );
    // The trailer reference and the catalog disagree with Pillow's numbering, so nothing here is
    // shared with the fixture above beyond the shape of the rows.
    assert!(
        report
            .iter()
            .any(|entry| entry == "resolves\tRoot\t13\t1328\t1"),
        "{report:#?}"
    );
    assert_eq!(row(&report, "catalog"), "catalog\t13\tpages\t6");
    assert_eq!(row(&report, "pages"), "pages\t6\tcount\t1\tkids\t1");
    // US Letter at 72 points to the inch, which is what Chrome prints to by default.
    assert_eq!(row(&report, "page"), "page\t2\tmedia\t612\t792");
    assert_eq!(
        row(&report, "leaves"),
        "leaves\t1\tvisited\t1\ttruncated\t0"
    );
}

#[test]
fn reads_both_a4_pages_skia_wrote_and_keeps_their_decimal_box() {
    let pdf = fixture("chromium-2p.pdf");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(row(&report, "pages"), "pages\t9\tcount\t2\tkids\t2");
    assert_eq!(count_rows(&report, "page\t"), 2, "{report:#?}");
    assert_eq!(
        number(&report, "leaves", 1),
        2,
        "both kids are leaves of the tree"
    );
    // A4 is 210mm wide, and the writer rounds that to 594.95996 points rather than to a whole
    // number, so the page size has to survive a decimal rather than be truncated.
    let sizes: Vec<&String> = report
        .iter()
        .filter(|entry| entry.starts_with("page\t"))
        .collect();
    assert_eq!(sizes.len(), 2);
    assert!(
        sizes[0].ends_with("\tmedia\t594.95996\t841.91998"),
        "the box as written: {}",
        sizes[0]
    );
    assert!(
        sizes[1].ends_with("\tmedia\t594.95996\t841.91998"),
        "the box as written: {}",
        sizes[1]
    );
}

#[test]
fn walks_every_page_pillow_appended() {
    let pdf = fixture("pillow-3p.pdf");
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(
        number(&report, "verified", 1),
        12,
        "twelve live rows: {report:#?}"
    );
    assert_eq!(row(&report, "catalog"), "catalog\t10\tpages\t11");
    assert_eq!(row(&report, "pages"), "pages\t11\tcount\t3\tkids\t3");
    assert_eq!(count_rows(&report, "page\t"), 3, "{report:#?}");
    assert_eq!(
        row(&report, "leaves"),
        "leaves\t3\tvisited\t3\ttruncated\t0"
    );
    // The three images were 5x3, 7x4 and 2x9 pixels at Pillow's 72 dpi, so each page is that many
    // points wide: the sizes are read per page, not once from the first one.
    assert!(
        report.iter().any(|entry| entry == "page\t2\tmedia\t5\t3"),
        "{report:#?}"
    );
    assert!(
        report.iter().any(|entry| entry == "page\t5\tmedia\t7\t4"),
        "{report:#?}"
    );
    assert!(
        report.iter().any(|entry| entry == "page\t8\tmedia\t2\t9"),
        "{report:#?}"
    );
}

#[test]
fn reaches_leaves_through_a_branch_and_reports_what_the_file_claimed() {
    // Object 2's /Count says three; the tree only carries two pages, and one of them is reached
    // through object 3. The reader reports both numbers instead of picking one, and the width of
    // object 4's box comes from subtracting its origin, which is not at zero.
    let pdf = build_pdf(&[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [ 3 0 R 4 0 R 99 0 R ] /Count 3 >>",
        "<< /Type /Pages /Parent 2 0 R /Kids [ 5 0 R ] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [ 10 10 210 310 ] >>",
        "<< /Type /Page /Parent 3 0 R /MediaBox [ 0 0 72 72 ] >>",
    ]);
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(
        row(&report, "resolves"),
        format!("resolves\tRoot\t1\t{}\t1", PROLOGUE.len())
    );
    assert_eq!(row(&report, "catalog"), "catalog\t1\tpages\t2");
    assert_eq!(row(&report, "pages"), "pages\t2\tcount\t3\tkids\t3");
    assert_eq!(row(&report, "branch"), "branch\t3\tkids\t1");
    assert!(
        report.iter().any(|entry| entry == "page\t5\tmedia\t72\t72"),
        "{report:#?}"
    );
    assert!(
        report
            .iter()
            .any(|entry| entry == "page\t4\tmedia\t200\t300"),
        "a box away from the origin: {report:#?}"
    );
    assert!(
        report.iter().any(|entry| entry == "unresolved\t99"),
        "a kid the table has no row for: {report:#?}"
    );
    assert_eq!(
        number(&report, "leaves", 1),
        2,
        "two pages found, whatever /Count said"
    );
    assert_eq!(number(&report, "leaves", 5), 0, "no cap was hit");
}

#[test]
fn stops_a_page_tree_that_points_back_at_itself() {
    // A cycle is legal enough for a broken writer to produce: /Kids naming the node that names it
    // back. The depth cap ends the walk, and the report says so instead of looping.
    let pdf = build_pdf(&[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
        "<< /Type /Pages /Kids [ 3 0 R ] >>",
    ]);
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(row(&report, "pages"), "pages\t2\tcount\t1\tkids\t1");
    assert_eq!(number(&report, "leaves", 1), 0, "nothing here is a page");
    assert_eq!(
        number(&report, "leaves", 5),
        1,
        "the walk reports that it stopped"
    );
    assert!(
        count_rows(&report, "branch\t") <= 40,
        "bounded by the depth cap: {report:#?}"
    );
}

#[test]
fn keeps_what_it_read_when_the_page_tree_does_not_resolve() {
    // A catalog whose `/Pages` is an object the table has no row for. Dropping the identification
    // would throw away the true rows above it, so the walk stops where the file stops being
    // explorable and the report keeps the header, the table and the reference it did verify.
    let pdf = build_pdf(&[
        "<< /Type /Catalog /Pages 99 0 R >>",
        "<< /Type /Page /MediaBox [ 0 0 612 792 ] >>",
    ]);
    assert_eq!(parse(&pdf), FORMAT_PDF);
    let report = lines();
    assert_eq!(
        number(&report, "resolves", 4),
        1,
        "the trailer's own /Root did resolve"
    );
    assert_eq!(row(&report, "catalog"), "catalog\t1\tpages\t99");
    assert!(
        !report.iter().any(|entry| entry.starts_with("pages\t")),
        "no page tree was reached: {report:#?}"
    );
    assert!(
        !report.iter().any(|entry| entry.starts_with("leaves")),
        "and no walk to summarise: {report:#?}"
    );
    assert!(
        !report.iter().any(|entry| entry.starts_with("page\t")),
        "the one real page object is not in a tree, so it is not a page: {report:#?}"
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
