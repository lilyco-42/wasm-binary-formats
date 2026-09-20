//! Arrow IPC: the encapsulated message envelope, the flatbuffer fields inside it, and the block
//! index the file format hides behind its trailing length.
//!
//! `test/fixtures/{rows,batches,dict,lz4,zstd}.arrow` are streams and `file.arrow` /
//! `file_dict.arrow` are the file framing, all written by pyarrow by
//! `scripts/make-arrow-fixtures.py`. That script walks each file once with its own flatbuffer reader
//! and once through `pyarrow.ipc.read_message`, and refuses to write `arrow.probe.json` unless the two
//! agree on every metadata length, body length, metadata version, header kind, row count, column name
//! and block offset. So the rows below are checked against a second reader this repo does not control,
//! not against this repo's reading of a specification.
//!
//! Two shapes are worth the fixtures that exist for them. A message's body length lives *inside* its
//! metadata flatbuffer, so a walk that skips only the metadata desynchronises at the first record
//! batch - `batches.arrow`, with three of them, cannot survive that. And a footer `Block` gives the
//! envelope position plus a metadata size that already includes the 8-byte prefix, which `file.arrow`
//! pins row for row.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_ARROW};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-arrow-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert_eq!(parse(&bytes), FORMAT_ARROW, "{file} has to be claimed");
    assert_eq!(
        kind(),
        FORMAT_ARROW,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "arrow", "the reader has to name what it walked");
    report()
}

fn u32_le(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// One complete encapsulated message carrying a hand-built flatbuffer, so a test can put a version,
/// a header kind and a body length anywhere without a flatbuffer compiler.
///
/// Layout: the 8-byte prefix, then a 40-byte metadata region holding a root offset (16), a vtable
/// whose four slots are 6, 5, 8 and 12, and a 24-byte table. The `header` slot points 8 bytes
/// forward, which is inside the table itself: nothing reads past it in these cases.
fn envelope(version: i16, head: u8, body: i64) -> Vec<u8> {
    let mut out = u32_le(0xFFFF_FFFF);
    out.extend_from_slice(&u32_le(40));
    out.extend_from_slice(&u32_le(16));
    out.extend_from_slice(&12u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    for slot in [6u16, 5, 8, 12] {
        out.extend_from_slice(&slot.to_le_bytes());
    }
    out.extend_from_slice(&12i32.to_le_bytes());
    out.extend_from_slice(&[0u8, head]);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&body.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out
}

/// An end-of-stream marker: a continuation with a zero metadata length.
fn end_of_stream() -> Vec<u8> {
    let mut out = u32_le(0xFFFF_FFFF);
    out.extend_from_slice(&u32_le(0));
    out
}

#[test]
fn reads_the_schema_and_batch_pyarrow_wrote() {
    assert_eq!(
        rows("rows.arrow"),
        vec![
            "arrow\t440\t2\t0\tframing\tstream",
            "message\t0\thead\tSchema\tmeta\t168\tbody\t0\tversion\t4",
            "schema\tfields\t2\tendianness\t0",
            "field\t0\tid\tnullable\t1\ttype\t2",
            "field\t1\tname\tnullable\t1\ttype\t5",
            "message\t1\thead\tRecordBatch\tmeta\t200\tbody\t48\tversion\t4",
            "batch\t0\trows\t3\tnodes\t2\tbuffers\t5",
            "eos\t1",
            "walked\tend",
        ]
    );
}

#[test]
fn every_batch_advances_the_walk_by_its_own_body_length() {
    let lines = rows("batches.arrow");
    assert_eq!(
        lines[0], "arrow\t904\t4\t0\tframing\tstream",
        "four messages, nothing broken"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("batch\t"))
            .collect::<Vec<_>>(),
        vec![
            "batch\t0\trows\t2\tnodes\t2\tbuffers\t5",
            "batch\t1\trows\t1\tnodes\t2\tbuffers\t5",
            "batch\t2\trows\t3\tnodes\t2\tbuffers\t5",
        ],
        "the row counts are what pyarrow reads back from the same bytes"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("message\t"))
            .count(),
        4,
        "a walk that skipped only the metadata would lose the second and third batches"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn a_dictionary_batch_is_kept_apart_from_the_batch_that_uses_it() {
    assert_eq!(
        rows("dict.arrow"),
        vec![
            "arrow\t520\t3\t0\tframing\tstream",
            "message\t0\thead\tSchema\tmeta\t144\tbody\t0\tversion\t4",
            "schema\tfields\t1\tendianness\t0",
            "field\t0\tcolor\tnullable\t1\ttype\t5",
            "message\t1\thead\tDictionaryBatch\tmeta\t168\tbody\t32\tversion\t4",
            "dict\t0\tid\t0\trows\t3\tbuffers\t3\tdelta\t0",
            "message\t2\thead\tRecordBatch\tmeta\t136\tbody\t8\tversion\t4",
            "batch\t0\trows\t4\tnodes\t1\tbuffers\t2",
            "eos\t1",
            "walked\tend",
        ],
        "three dictionary values feed four rows: two counts from two different tables"
    );
}

#[test]
fn the_footer_index_points_at_envelopes_not_bodies() {
    assert_eq!(
        rows("file.arrow"),
        vec![
            "arrow\t922\t3\t0\tframing\tfile",
            "message\t0\thead\tSchema\tmeta\t168\tbody\t0\tversion\t4",
            "schema\tfields\t2\tendianness\t0",
            "field\t0\tid\tnullable\t1\ttype\t2",
            "field\t1\tname\tnullable\t1\ttype\t5",
            "message\t1\thead\tRecordBatch\tmeta\t200\tbody\t48\tversion\t4",
            "batch\t0\trows\t3\tnodes\t2\tbuffers\t5",
            "message\t2\thead\tRecordBatch\tmeta\t200\tbody\t24\tversion\t4",
            "batch\t1\trows\t1\tnodes\t2\tbuffers\t5",
            "footer\t680\tbytes\t232\tenvelope\t912\tversion\t4\tbatches\t2\tdicts\t0\tmagic\t1",
            "block\t0\tenvelope\t184\tmeta\t208\tbody\t48",
            "block\t1\tenvelope\t440\tmeta\t208\tbody\t24",
            "eos\t1",
            "walked\tend",
        ],
        "block 0 says the batch begins at 184 and its metadata is 208 wide: 184+208 is the body, so \
         the 208 includes the 8-byte prefix"
    );
}

#[test]
fn a_file_with_a_dictionary_indexes_it_separately() {
    let lines = rows("file_dict.arrow");
    assert_eq!(
        lines[0], "arrow\t930\t4\t0\tframing\tfile",
        "schema, dictionary, two batches"
    );
    assert_eq!(
        *lines
            .iter()
            .find(|line| line.starts_with("footer\t"))
            .unwrap(),
        "footer\t680\tbytes\t240\tenvelope\t920\tversion\t4\tbatches\t2\tdicts\t1\tmagic\t1",
        "the footer's own length is what locates it behind the trailing magic"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("block\t"))
            .collect::<Vec<_>>()
            .join("\n"),
        "block\t0\tenvelope\t368\tmeta\t144\tbody\t8\nblock\t1\tenvelope\t520\tmeta\t144\tbody\t8"
    );
}

#[test]
fn a_compressed_batch_names_its_codec_by_what_the_writer_had_to_write() {
    let plain = rows("lz4.arrow");
    let other = rows("zstd.arrow");
    assert_eq!(
        plain
            .iter()
            .find(|line| line.starts_with("batch\t"))
            .unwrap(),
        "batch\t0\trows\t3\tnodes\t2\tbuffers\t5\tcodec\t0",
        "lz4_frame is the enum's zero, so pyarrow omits the field and an absent slot is a default"
    );
    assert_eq!(
        other
            .iter()
            .find(|line| line.starts_with("batch\t"))
            .unwrap(),
        "batch\t0\trows\t3\tnodes\t2\tbuffers\t5\tcodec\t1",
        "zstd is not a default, so it has to appear in the bytes: that pair is what orders the two"
    );
    assert_eq!(
        plain[5],
        "message\t1\thead\tRecordBatch\tmeta\t216\tbody\t120\tversion\t4"
    );
    assert_eq!(
        other[5], "message\t1\thead\tRecordBatch\tmeta\t224\tbody\t104\tversion\t4",
        "same three rows, different codecs, different body sizes"
    );
}

#[test]
fn a_stream_cut_before_a_body_still_lists_the_message_it_started() {
    // rows.arrow cut at 384: the second message's metadata is complete, its 48-byte body is gone.
    let mut bytes = fixture("rows.arrow");
    bytes.truncate(384);
    assert_eq!(parse(&bytes), FORMAT_ARROW);
    let lines = report();
    assert_eq!(lines[0], "arrow\t384\t2\t0\tframing\tstream");
    assert_eq!(
        lines[5], "message\t1\thead\tRecordBatch\tmeta\t200\tbody\t48\tversion\t4",
        "the message is still what it says it is, even though its bytes are not there"
    );
    assert_eq!(lines[lines.len() - 1], "eos\t0");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_message_that_does_not_begin_the_next_is_counted_as_broken() {
    // batches.arrow, with the second envelope's continuation spoiled: the first message walks, the
    // second does not start, and the file cannot be claimed as fully read.
    let mut bytes = fixture("batches.arrow");
    bytes[176] = 0x7f;
    assert_eq!(parse(&bytes), FORMAT_ARROW);
    let lines = report();
    assert_eq!(lines[0], "arrow\t904\t1\t1\tframing\tstream");
    assert_eq!(lines[lines.len() - 1], "eos\t0");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_body_length_that_overruns_the_file_ends_the_walk_without_an_end_marker() {
    // rows.arrow's RecordBatch body length, which sits at vtable slot 3 twelve bytes into its table
    // at 204, raised to more than the file holds.
    let mut bytes = fixture("rows.arrow");
    bytes[216..224].copy_from_slice(&9_000i64.to_le_bytes());
    assert_eq!(parse(&bytes), FORMAT_ARROW);
    let lines = report();
    assert_eq!(lines[0], "arrow\t440\t2\t0\tframing\tstream");
    assert_eq!(
        lines[6], "batch\t0\trows\t3\tnodes\t2\tbuffers\t5",
        "the batch's own fields are still readable - only its span is a lie"
    );
    assert_eq!(lines[lines.len() - 1], "eos\t0");
    assert!(!lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_stream_with_no_end_marker_is_walked_but_not_finished() {
    let bytes = envelope(4, 1, 0);
    assert_eq!(parse(&bytes), FORMAT_ARROW);
    assert_eq!(
        report(),
        vec![
            "arrow\t48\t1\t0\tframing\tstream",
            "message\t0\thead\tSchema\tmeta\t40\tbody\t0\tversion\t4",
            "schema\tfields\t0\tendianness\t0",
            "eos\t0",
        ],
        "a truncated-but-legal opening is reported as far as it goes"
    );
}

#[test]
fn a_stream_that_does_not_open_with_a_schema_is_left_to_other_readers() {
    assert_eq!(
        parse(&envelope(4, 3, 8)),
        -2,
        "the framing is right but a RecordBatch first is not a stream"
    );
    assert_eq!(parse(&envelope(9, 1, 0)), -2, "a version nobody writes");
    let mut nothing = u32_le(0xFFFF_FFFF);
    nothing.extend_from_slice(&u32_le(16));
    nothing.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        parse(&nothing),
        -2,
        "a continuation with no table behind it"
    );
    assert_eq!(
        parse(&end_of_stream()),
        -2,
        "an end marker alone is not a stream"
    );
    assert_eq!(parse(&[0xFFu8; 64]), -2, "a block of 0xFF is not a stream");
}

#[test]
fn a_lone_arrow1_header_is_not_an_arrow_file() {
    let mut bytes = b"ARROW1\0\0".to_vec();
    bytes.extend_from_slice(&[0u8; 8]);
    assert_eq!(parse(&bytes), -2, "no footer means nothing was indexed");
    let mut stub = b"ARROW1\0\0".to_vec();
    stub.extend_from_slice(&[0u8; 6]);
    assert_eq!(parse(&stub), -2, "the trailing magic alone is not a footer");
}

#[test]
fn short_buffers_are_refused_before_any_reader_runs() {
    assert_eq!(parse(b"\xff\xff\xff\xff\x00\x00\x00"), -1);
    assert_eq!(parse(&[0u8; 7]), -1);
    assert_eq!(
        parse(b"ARROW1\0\0"),
        -2,
        "eight bytes, so a reader does look"
    );
}
