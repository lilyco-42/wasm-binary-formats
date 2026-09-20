//! Parquet: the Thrift-compact footer, which is the only place the file says what it holds.
//!
//! `test/fixtures/*.parquet` are written by pyarrow by `scripts/make-parquet-fixtures.py`. That script
//! decodes each footer with its own Thrift-compact reader *and* asks pyarrow's C++ metadata reader the
//! same questions, and it refuses to write `parquet.probe.json` unless the footer's stored length
//! equals `FileMetaData.serialized_size`, the walk consumes the footer down to its last byte, and every
//! row count, column path, page offset, size and null count agrees. The codec and physical-type names
//! in the report are checked the same way: they are the names pyarrow gives the values it wrote when
//! told which codec or arrow type to use - which is how `ZSTD` was found to be ordinal 6 rather than
//! the 5 a recollection would have produced.
//!
//! Pages are located, not decoded: the reader reports where each column's dictionary and data pages
//! begin and how large the chunks are, and never inflates a page.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_PARQUET};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-parquet-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert_eq!(parse(&bytes), FORMAT_PARQUET, "{file} has to be claimed");
    assert_eq!(
        kind(),
        FORMAT_PARQUET,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "parquet", "the reader has to name what it walked");
    report()
}

fn chunk_rows(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("chunk\t"))
        .collect()
}

fn find(lines: &[String], prefix: &str) -> String {
    lines
        .iter()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no row starting with {prefix}: {lines:?}"))
        .clone()
}

/// A Thrift-compact field header: the nibble pair carrying the delta from the previous id and the
/// value's type.
fn header(delta: u8, kind: u8) -> Vec<u8> {
    vec![(delta << 4) | kind]
}

fn varint(mut raw: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (raw & 0x7F) as u8;
        raw >>= 7;
        if raw != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if raw == 0 {
            return out;
        }
    }
}

/// zigzag(1) is 2 and zigzag(2) is 4: the protocol's only signed integer form.
fn zigzag(value: i64) -> Vec<u8> {
    varint(((value << 1) ^ (value >> 63)) as u64)
}

/// `binary` carries an unsigned length, which is not the same encoding as an integer field.
fn text(value: &str) -> Vec<u8> {
    let mut out = varint(value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

/// A minimal FileMetaData: version, one INT32 column, one row, a writer string - and optionally a
/// trailing field this reader has never heard of, which is what the skip-by-type path is for.
fn hand_written(extra: bool, closing: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&header(1, 5));
    body.extend_from_slice(&zigzag(2));
    // schema: a list of one struct
    body.extend_from_slice(&header(1, 9));
    body.extend_from_slice(&[(1 << 4) | 12]);
    body.extend_from_slice(&header(1, 5));
    body.extend_from_slice(&zigzag(1));
    body.extend_from_slice(&header(2, 5));
    body.extend_from_slice(&zigzag(1));
    body.extend_from_slice(&header(1, 8));
    body.extend_from_slice(&text("x"));
    body.push(0);
    // num_rows
    body.extend_from_slice(&header(1, 6));
    body.extend_from_slice(&zigzag(1));
    // created_by
    body.extend_from_slice(&header(3, 8));
    body.extend_from_slice(&text("test writer"));
    if extra {
        body.extend_from_slice(&header(1, 8));
        body.extend_from_slice(&text("future"));
    }
    if closing {
        body.push(0);
    }

    let mut out = b"PAR1".to_vec();
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&body);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(b"PAR1");
    out
}

#[test]
fn reads_the_footer_pyarrow_wrote() {
    assert_eq!(
        rows("rows.parquet"),
        vec![
            "parquet\t703\tfooter\t174\tbytes\t521\tgroups\t1",
            "version\t2\trows\t3\tschema\t3\tcolumns\t2",
            "created\tparquet-cpp-arrow version 25.0.1",
            "column\t0\tschema\trep\t0\tchildren\t2",
            "column\t1\tid\ttype\t1\tname\tint32\trep\t1",
            "column\t2\tname\ttype\t6\tname\tbyte_array\trep\t1\tconverted\t0",
            "group\t0\trows\t3\tbytes\t163\tcolumns\t2",
            "chunk\t0\tpath\tid\tgroup\t0\trows\t3\ttype\t1\tname\tint32\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t83\tcompressed\t87\tencodings\t0,3,8\tdata\t32\tdict\t4",
            "stats\t0\tnull\t0\tmin\t01000000\tmax\t03000000",
            "chunk\t1\tpath\tname\tgroup\t0\trows\t3\ttype\t6\tname\tbyte_array\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t80\tcompressed\t83\tencodings\t0,3,8\tdata\t129\tdict\t91",
            "stats\t1\tnull\t0\tmin\t6f6e65\tmax\t74776f",
            "walked\tend",
        ]
    );
}

#[test]
fn the_statistics_are_the_values_that_were_written() {
    let lines = rows("rows.parquet");
    assert_eq!(
        find(&lines, "stats\t0"),
        "stats\t0\tnull\t0\tmin\t01000000\tmax\t03000000",
        "1 and 3 as little-endian int32, which is what the fixture holds"
    );
    assert_eq!(
        find(&lines, "stats\t1"),
        "stats\t1\tnull\t0\tmin\t6f6e65\tmax\t74776f",
        "one and two: byte order puts two above three"
    );
    assert_eq!(
        String::from_utf8(vec![0x74, 0x77, 0x6f]).unwrap(),
        "two",
        "the hex in the row above decodes to the max pyarrow reports for the string column"
    );
}

#[test]
fn every_physical_type_the_fixtures_carry_is_named_from_a_writer_option() {
    assert_eq!(
        rows("typed.parquet"),
        vec![
            "parquet\t1938\tfooter\t599\tbytes\t1331\tgroups\t1",
            "version\t2\trows\t3\tschema\t8\tcolumns\t7",
            "created\tparquet-cpp-arrow version 25.0.1",
            "column\t0\tschema\trep\t0\tchildren\t7",
            "column\t1\tflag\ttype\t0\tname\tboolean\trep\t1",
            "column\t2\ti32\ttype\t1\tname\tint32\trep\t1",
            "column\t3\ti64\ttype\t2\tname\tint64\trep\t1",
            "column\t4\tf32\ttype\t4\tname\tfloat\trep\t1",
            "column\t5\tf64\ttype\t5\tname\tdouble\trep\t1",
            "column\t6\ttext\ttype\t6\tname\tbyte_array\trep\t1\tconverted\t0",
            "column\t7\tblob\ttype\t6\tname\tbyte_array\trep\t1",
            "group\t0\trows\t3\tbytes\t576\tcolumns\t7",
            "chunk\t0\tpath\tflag\tgroup\t0\trows\t3\ttype\t0\tname\tboolean\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t42\tcompressed\t44\tencodings\t3,0\tdata\t4",
            "stats\t0\tnull\t0\tmin\t00\tmax\t01",
            "chunk\t1\tpath\ti32\tgroup\t0\trows\t3\ttype\t1\tname\tint32\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t83\tcompressed\t87\tencodings\t0,3,8\tdata\t76\tdict\t48",
            "stats\t1\tnull\t0\tmin\t01000000\tmax\t03000000",
            "chunk\t2\tpath\ti64\tgroup\t0\trows\t3\ttype\t2\tname\tint64\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t111\tcompressed\t112\tencodings\t0,3,8\tdata\t172\tdict\t135",
            "stats\t2\tnull\t0\tmin\t0a00000000000000\tmax\t1e00000000000000",
            "chunk\t3\tpath\tf32\tgroup\t0\trows\t3\ttype\t4\tname\tfloat\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t83\tcompressed\t87\tencodings\t0,3,8\tdata\t275\tdict\t247",
            "stats\t3\tnull\t0\tmin\t0000c03f\tmax\t00006040",
            "chunk\t4\tpath\tf64\tgroup\t0\trows\t3\ttype\t5\tname\tdouble\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t111\tcompressed\t111\tencodings\t0,3,8\tdata\t370\tdict\t334",
            "stats\t4\tnull\t0\tmin\t000000000000f83f\tmax\t0000000000000c40",
            "chunk\t5\tpath\ttext\tgroup\t0\trows\t3\ttype\t6\tname\tbyte_array\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t73\tcompressed\t77\tencodings\t0,3,8\tdata\t479\tdict\t445",
            "stats\t5\tnull\t0\tmin\t78\tmax\t7a7a7a",
            "chunk\t6\tpath\tblob\tgroup\t0\trows\t3\ttype\t6\tname\tbyte_array\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t73\tcompressed\t77\tencodings\t0,3,8\tdata\t556\tdict\t522",
            "stats\t6\tnull\t0\tmin\t61\tmax\t636363",
            "walked\tend",
        ],
        "string and binary share one physical type; only `converted` separates them"
    );
}

#[test]
fn a_row_group_boundary_shows_up_in_each_groups_statistics() {
    let lines = rows("groups.parquet");
    assert_eq!(
        lines[0],
        "parquet\t2256\tfooter\t939\tbytes\t1309\tgroups\t3"
    );
    assert_eq!(lines[1], "version\t2\trows\t12\tschema\t4\tcolumns\t3");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("group\t"))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        "group\t0\trows\t4\tbytes\t317\tcolumns\t3\n\
         group\t1\trows\t4\tbytes\t317\tcolumns\t3\n\
         group\t2\trows\t4\tbytes\t320\tcolumns\t3"
    );
    assert_eq!(
        find(&lines, "stats\t0"),
        "stats\t0\tnull\t0\tmin\t0000000000000000\tmax\t0300000000000000"
    );
    assert_eq!(
        find(&lines, "stats\t3"),
        "stats\t3\tnull\t0\tmin\t0400000000000000\tmax\t0700000000000000"
    );
    assert_eq!(
        find(&lines, "stats\t6"),
        "stats\t6\tnull\t0\tmin\t0800000000000000\tmax\t0b00000000000000"
    );
    assert_eq!(
        chunk_rows(&lines).len(),
        9,
        "three groups of three columns, numbered across the file rather than per group"
    );
}

#[test]
fn null_values_are_counted_and_the_extremes_ignore_them() {
    let lines = rows("nulls.parquet");
    assert_eq!(lines[1], "version\t2\trows\t4\tschema\t3\tcolumns\t2");
    assert_eq!(
        find(&lines, "stats\t0"),
        "stats\t0\tnull\t2\tmin\t07000000\tmax\t09000000",
        "7 and 9 are the two values that survived"
    );
    assert_eq!(
        find(&lines, "stats\t1"),
        "stats\t1\tnull\t1\tmin\t61\tmax\t63"
    );
    assert_eq!(
        find(&lines, "chunk\t0"),
        "chunk\t0\tpath\tvalue\tgroup\t0\trows\t4\ttype\t1\tname\tint32\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t78\tcompressed\t82\tencodings\t0,3,8\tdata\t28\tdict\t4"
    );
}

#[test]
fn three_codecs_of_the_same_table_differ_only_in_the_compressed_size() {
    let plain = rows("plain.parquet");
    let zstd = rows("zstd.parquet");
    let gzip = rows("gzip.parquet");
    assert!(
        chunk_rows(&plain)[0].contains("codec\t0\tcodec_name\tuncompressed")
            && chunk_rows(&plain)[0].contains("uncompressed\t83\tcompressed\t83"),
        "{plain:?}"
    );
    assert!(
        chunk_rows(&zstd)[0].contains("codec\t6\tcodec_name\tzstd")
            && chunk_rows(&zstd)[0].contains("uncompressed\t83\tcompressed\t101"),
        "zstd is ordinal 6, which is what the fixtures - not a recollection - say: {zstd:?}"
    );
    assert!(
        chunk_rows(&gzip)[0].contains("codec\t2\tcodec_name\tgzip")
            && chunk_rows(&gzip)[0].contains("uncompressed\t83\tcompressed\t120"),
        "{gzip:?}"
    );
    assert!(
        find(&zstd, "column\t1").contains("name\tint32"),
        "the column types are the same in all three: {zstd:?}"
    );
}

#[test]
fn a_column_written_without_a_dictionary_page_has_no_offset_for_one() {
    let without = rows("nodict.parquet");
    let with = rows("rows.parquet");
    let line = chunk_rows(&without)[0].clone();
    assert!(
        !line.contains("\tdict\t"),
        "no dictionary page was written: {line}"
    );
    assert!(line.ends_with("\tencodings\t3,0\tdata\t4"), "{line}");
    assert!(
        chunk_rows(&with)[0].contains("\tdict\t4"),
        "and the same table with dictionaries does carry one: {with:?}"
    );
    assert_eq!(
        without[0],
        "parquet\t640\tfooter\t134\tbytes\t498\tgroups\t1"
    );
}

#[test]
fn an_unknown_footer_field_is_skipped_by_type_and_changes_nothing() {
    assert_eq!(parse(&hand_written(false, true)), FORMAT_PARQUET);
    let plain = report();
    assert_eq!(parse(&hand_written(true, true)), FORMAT_PARQUET);
    let grown = report();
    assert_eq!(
        plain[1..],
        [
            "version\t2\trows\t1\tschema\t1\tcolumns\t1",
            "created\ttest writer",
            "column\t0\tx\ttype\t1\tname\tint32\trep\t1",
            "walked\tend",
        ]
    );
    assert_eq!(
        &plain[1..],
        &grown[1..],
        "one extra field this reader has never seen, same report"
    );
    assert!(plain[0].ends_with("\tgroups\t0"), "{}", plain[0]);
}

#[test]
fn a_footer_that_does_not_add_up_is_left_alone() {
    // Both magics intact but the stated footer size reaches past the file.
    let mut bytes = fixture("rows.parquet");
    let tail = bytes.len();
    bytes[tail - 8..tail - 4].copy_from_slice(&2_000u32.to_le_bytes());
    assert_eq!(parse(&bytes), -2, "a footer larger than the file");

    let mut tiny = fixture("rows.parquet");
    tiny.truncate(274);
    assert_eq!(parse(&tiny), -2, "the tail is what locates the footer");

    assert_eq!(
        parse(b"PAR1aaaaPAR1"),
        -2,
        "magic, and a length that is data"
    );

    let mut hollow = b"PAR1".to_vec();
    hollow.extend_from_slice(&[0u8; 8]);
    hollow.extend_from_slice(&8u32.to_le_bytes());
    hollow.extend_from_slice(b"PAR1");
    assert_eq!(
        parse(&hollow),
        -2,
        "a footer of eight zero bytes names no schema"
    );

    assert_eq!(
        parse(&hand_written(false, false)),
        -2,
        "a struct that never closes its last field is refused, not half-read"
    );
}

#[test]
fn short_buffers_are_refused_before_any_reader_runs() {
    assert_eq!(parse(b"PAR1\x01\x02\x03"), -1);
    assert_eq!(parse(&[0u8; 7]), -1);
}
