use apk_lens::documents::{
    at, count, kind, parse, DOC_DOCX, DOC_DOTX, DOC_EPUB, DOC_ODP, DOC_ODS, DOC_ODT, DOC_PPTX,
    DOC_XLSX,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-document-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .cloned()
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"))
}

fn number(lines: &[String], named: &str, column: usize) -> i64 {
    let line = row(lines, named);
    let value = line
        .split('\t')
        .nth(column)
        .unwrap_or_else(|| panic!("row {line} has no column {column}"));
    value
        .parse()
        .unwrap_or_else(|error| panic!("row {line} is not a number: {error}"))
}

/// What every package must report: its family, a main part with bytes in it, a manifest of some
/// kind, and the archive's own length. Sizes are measured from the committed fixtures, so they are
/// observations rather than guesses (python-docx writes a 1602-byte word/document.xml across 17
/// parts; the hand-built packages carry 44 to 100 bytes in their main part).
fn check(name: &str, code: i32, label: &str) {
    let bytes = fixture(name);
    assert_eq!(parse(&bytes), code, "{name}");
    assert_eq!(
        kind(),
        code,
        "kind() must agree with the return code for {name}"
    );
    let lines = report();
    let document = row(&lines, "document");
    assert!(
        document.starts_with(&format!("document\t{label}\t")),
        "{name} reported {document}"
    );
    assert!(
        number(&lines, "document", 2) > 0,
        "the main part has bytes on disk: {document}"
    );
    assert_eq!(number(&lines, "has_manifest", 1), 1, "{name}: {lines:#?}");
    assert!(number(&lines, "entries", 1) >= 3, "{name}: {lines:#?}");
    assert_eq!(number(&lines, "archive_bytes", 1), bytes.len() as i64);
}

#[test]
fn identifies_the_ooxml_families_by_their_part_prefix() {
    check("tiny.docx", DOC_DOCX, "docx");
    check("tiny.xlsx", DOC_XLSX, "xlsx");
    check("tiny.pptx", DOC_PPTX, "pptx");
    assert_eq!(parse(&fixture("tiny.docx")), DOC_DOCX);
    let lines = report();
    assert!(
        row(&lines, "main_part").starts_with("main_part\tword/"),
        "python-docx writes the document under word/: {lines:#?}"
    );
    assert!(
        number(&lines, "entries", 1) > 10,
        "a real writer's package carries its relationships and styles: {lines:#?}"
    );
    assert!(
        number(&lines, "document", 2) > 1000,
        "word/document.xml from python-docx is a kilobyte and a half: {lines:#?}"
    );
}

#[test]
fn tells_a_word_template_from_a_word_document_only_by_what_the_package_says() {
    // `lab-fixture.dotx` is LibreOffice's `Office Open XML Text Template` export of a python-docx
    // document, so both files in this test came from real writers, and `scripts/make-dotx-fixture.py`
    // refuses to write its probe unless the manifest of the source says `document.main+xml` and the
    // manifest of the template says `template.main+xml` for the same part name.
    check("lab-fixture.dotx", DOC_DOTX, "dotx");
    let lines = report();
    assert_eq!(
        row(&lines, "main_part"),
        "main_part\tword/document.xml\tcontent\twordprocessingml.template.main+xml"
    );
    assert_eq!(number(&lines, "entries", 1), 15, "the probe lists fifteen parts");
    assert_eq!(number(&lines, "document", 2), 1740, "word/document.xml's own size");
    assert_eq!(number(&lines, "has_manifest", 1), 1);

    // The other half of the claim: a document that differs only by that one word still reads as a
    // document, with no content column invented for it.
    assert_eq!(parse(&fixture("tiny.docx")), DOC_DOCX);
    let plain = report();
    assert_eq!(row(&plain, "main_part"), "main_part\tword/document.xml");
    assert_ne!(kind(), DOC_DOTX, "the two must not share a code");
}

#[test]
fn identifies_opendocument_from_the_mimetype_string() {
    check("tiny.odt", DOC_ODT, "odt");
    check("tiny.ods", DOC_ODS, "ods");
    check("tiny.odp", DOC_ODP, "odp");
    assert_eq!(parse(&fixture("tiny.odt")), DOC_ODT);
    assert_eq!(
        row(&report(), "mimetype"),
        "mimetype\tapplication/vnd.oasis.opendocument.text",
        "the ODF kind comes from the mimetype text, not from a filename"
    );
}

#[test]
fn follows_the_epub_container_to_its_package_document() {
    check("tiny.epub", DOC_EPUB, "epub");
    assert_eq!(parse(&fixture("tiny.epub")), DOC_EPUB);
    assert_eq!(
        row(&report(), "rootfile"),
        "rootfile\tOEBPS/content.opf",
        "read out of META-INF/container.xml's full-path attribute"
    );
}

#[test]
fn refuses_archives_that_are_not_one_of_these_packages() {
    // A real APK is a zip with none of the document markers, and a PNG is not a zip at all: the two
    // ways this reader can be handed something it must not claim.
    let apk = fixture("lab-fixture.apk");
    assert_eq!(
        parse(&apk),
        -2,
        "a zip without document parts is no package"
    );
    assert_eq!(kind(), 0, "a rejected parse must clear the kind");
    assert_eq!(parse(&fixture("tiny.png")), -1, "not a zip container");
    assert_eq!(parse(b"PK not really an archive"), -1);
}
