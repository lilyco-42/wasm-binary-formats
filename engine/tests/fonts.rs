//! Font containers: the sfnt table directory, and the WOFF wrapper around it.
//!
//! `scripts/make-font-fixtures.py` compiles the TrueType and WOFF fixtures with fontTools - a two-glyph
//! font built from nothing, so no third-party outline is committed and the bytes still come from an
//! implementation this repo does not control. `test/fixtures/tiny_ttf.probe.json` and
//! `tiny_woff.probe.json` are that same library's reading of the finished files, and every number
//! asserted here was taken from them or from the bytes.
//!
//! `lab.otf` is the third case and the one with a second implementation behind it: fontTools writes a
//! CFF-flavoured font and FreeType, reached through Pillow, reads the family, the advance and the
//! metrics back out of the bytes (see `test/fixtures/otf.probe.json`). fontTools re-reading its own
//! output would prove only that one library agrees with itself.
//!
//! The interesting property is not the table list but the *dependency*: `units_per_em`, `ascender`,
//! `num_glyphs` and `name_records` are read at offsets the directory gave for `head`, `hhea`, `maxp`
//! and `name`. A walk that miscounted the directory entries could not land on four different tables
//! and still print the numbers fontTools wrote.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_OTF, FORMAT_TTF, FORMAT_WOFF};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-font-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

/// Rows are found by prefix, not by index: this reader's row list grows as it learns to check more of
/// a file, and a positional assertion goes stale on the commit that adds a row.
fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(named))
        .cloned()
        .unwrap_or_else(|| panic!("no row starting {named:?} in {lines:#?}"))
}

#[test]
fn reads_the_table_directory_fonttools_compiled() {
    let bytes = fixture("tiny.ttf");
    assert_eq!(parse(&bytes), FORMAT_TTF);
    assert_eq!(kind(), FORMAT_TTF, "kind() must agree with the return code");
    assert_eq!(name(), "ttf", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "sfnt\t1.0\t10\t0",
            "table\tOS/2\t296\t96",
            "table\tcmap\t400\t52",
            "table\tglyf\t460\t26",
            "table\thead\t172\t54",
            "table\thhea\t228\t36",
            "table\thmtx\t392\t8",
            "table\tloca\t452\t6",
            "table\tmaxp\t264\t32",
            "table\tname\t488\t108",
            "table\tpost\t596\t38",
            "units_per_em\t1000",
            "ascender\t800\tdescender\t-200",
            "num_glyphs\t2",
            "name_records\t4",
            "tables_end\t634\tuncovered\t2",
            "outlines\tglyf\tflavour\t1.0\tagrees\tyes",
        ]
    );
}

#[test]
fn a_cff_flavoured_font_is_named_by_the_outline_table_it_carries() {
    // `lab.otf` comes from `scripts/make-otf-fixtures.py`: fontTools writes it and FreeType, which
    // shares no code with the writer, reads the family name, the advance and the metrics back
    // (`test/fixtures/otf.probe.json` holds both readings). The point of the row below is that the
    // label does not come from the four-byte flavour tag alone: the directory has to name a `CFF `
    // table, and the tag and the table have to agree.
    let bytes = fixture("lab.otf");
    assert_eq!(parse(&bytes), FORMAT_OTF);
    assert_eq!(kind(), FORMAT_OTF, "kind() must agree with the return code");
    assert_eq!(name(), "otf");
    let lines = report();
    assert_eq!(lines[0], "sfnt\tOTTO\t9\t0", "{lines:#?}");
    assert_eq!(
        row(&lines, "table\tCFF "),
        "table\tCFF \t520\t118",
        "the tag keeps the trailing space that is part of its four bytes: {lines:#?}"
    );
    assert_eq!(row(&lines, "units_per_em"), "units_per_em\t1000");
    assert_eq!(row(&lines, "num_glyphs"), "num_glyphs\t3");
    assert_eq!(
        row(&lines, "tables_end"),
        "tables_end\t648\tuncovered\t0",
        "the directory accounts for every byte of this font"
    );
    assert_eq!(
        row(&lines, "outlines"),
        "outlines\tcff\tflavour\tOTTO\tagrees\tyes"
    );

    // The same reader on the TrueType control keeps its older label, and says which table it saw.
    assert_eq!(parse(&fixture("tiny.ttf")), FORMAT_TTF);
    assert_eq!(name(), "ttf");
    assert_eq!(
        row(&report(), "outlines"),
        "outlines\tglyf\tflavour\t1.0\tagrees\tyes"
    );

    // Self-authored contradiction: a `glyf` font retagged OTTO. Writing CFF outlines by hand to make
    // the lie convincing is not the point - the point is that a flavour tag on its own does not earn
    // the `otf` name, so the label stays where the evidence is and the disagreement is printed.
    let mut lied = fixture("tiny.ttf");
    lied[..4].copy_from_slice(b"OTTO");
    assert_eq!(parse(&lied), FORMAT_TTF, "a tag is not an outline format");
    assert_eq!(
        row(&report(), "outlines"),
        "outlines\tglyf\tflavour\tOTTO\tagrees\tno"
    );
}

#[test]
fn reads_the_woff_directory_and_its_compressed_lengths() {
    let bytes = fixture("tiny.woff");
    assert_eq!(parse(&bytes), FORMAT_WOFF);
    assert_eq!(name(), "woff");
    let lines = report();
    // The header's own length field has to equal the file, and `totalSfntSize` has to equal the
    // uncompressed font - which is the size of the other fixture in this same test file.
    assert_eq!(lines[0], "woff\t1.0\t604\t604\t10\t636", "{lines:#?}");
    assert_eq!(
        lines[1], "table\tOS/2\t356\t46\t96",
        "compressed length before original: {lines:#?}"
    );
    assert_eq!(
        lines[11], "compressed_bytes\t343\toriginal_bytes\t456",
        "{lines:#?}"
    );
    assert_eq!(
        lines[12], "tables_end\t603\tuncovered\t1",
        "the last table is padded out to the file: {lines:#?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|entry| entry.starts_with("table\t"))
            .count(),
        10
    );
}

#[test]
fn a_directory_longer_than_the_file_is_said_so() {
    // Self-authored: a header that claims 40 tables in a buffer that cannot hold them. The reader
    // reports the count it was given and flags it, instead of walking off the end inventing tags.
    let mut bytes = vec![0x00u8, 0x01, 0x00, 0x00, 0x00, 0x28, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(&[0u8; 40]);
    assert_eq!(parse(&bytes), FORMAT_TTF);
    let lines = report();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0], "sfnt\t1.0\t40\t1");
}

#[test]
fn a_collection_is_not_read_as_a_single_font() {
    // TrueType Collections start 'ttcf' and hold several sfnts; reading one as the other would
    // report the second font's tables as garbage rows, so it is refused.
    let mut bytes = b"ttcf".to_vec();
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        parse(&bytes),
        -2,
        "a collection is not this reader's format"
    );
}
