//! ONNX: one protobuf message that describes a model, read level by level.
//!
//! `test/fixtures/{add,symbolic,types}.onnx` are written by the `onnx` package by
//! `scripts/make-onnx-fixtures.py`. That script reads each file back with `onnx.load`, runs the
//! library's own shape inference over it (`check_model(full_check=True)`), and refuses to write
//! `onnx.probe.json` unless every region this reader calls a node, tensor, input or output is the
//! *exact bytes* onnx serializes for that object, and unless its walk consumes the whole file with
//! `ModelProto.ByteSize()` agreeing that nothing was left over. Field numbers are therefore not a
//! recollection: `producer_name` is 2 and `graph` is 7, and a tensor's payload fields are 4, 5, 6, 7 -
//! which is not the numbering a memory for the .proto file supplies, and getting it wrong would print
//! an int32 tensor as a float one.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_ONNX};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-onnx-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert_eq!(parse(&bytes), FORMAT_ONNX, "{file} has to be claimed");
    assert_eq!(
        kind(),
        FORMAT_ONNX,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "onnx", "the reader has to name what it walked");
    report()
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

fn tag(field: u64, wire: u64) -> Vec<u8> {
    varint((field << 3) | wire)
}

fn number(field: u64, value: i64) -> Vec<u8> {
    let mut out = tag(field, 0);
    out.extend_from_slice(&varint(value as u64));
    out
}

fn region(field: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = tag(field, 2);
    out.extend_from_slice(&varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// A whole model assembled from tags: an ir_version, one graph holding one node, one opset import.
fn hand_built() -> Vec<u8> {
    let mut node = Vec::new();
    node.extend_from_slice(&region(1, b"x"));
    node.extend_from_slice(&region(2, b"y"));
    node.extend_from_slice(&region(3, b"n0"));
    node.extend_from_slice(&region(4, b"Add"));
    let mut graph = Vec::new();
    graph.extend_from_slice(&region(1, &node));
    let mut opset = Vec::new();
    opset.extend_from_slice(&region(1, b""));
    opset.extend_from_slice(&number(2, 17));
    let mut out = number(1, 14);
    out.extend_from_slice(&region(7, &graph));
    out.extend_from_slice(&region(8, &opset));
    out
}

/// Enough unknown-but-legal fields to reach the length the dispatcher hands to any reader.
fn pad(bytes: &mut Vec<u8>) {
    let mut field = 20u64;
    while bytes.len() < 20 {
        bytes.extend_from_slice(&number(field, 1));
        field += 1;
    }
}

#[test]
fn reads_the_model_onnx_wrote() {
    assert_eq!(
        rows("add.onnx"),
        vec![
            "onnx\t116\tnodes\t1\ttensors\t1\topsets\t1\tbad\t0",
            "ir\t14\topset\t-\tversion\t17",
            "producer\t-\tdoc\tadds a vector",
            "opset\t0\tdomain\t-\tversion\t17",
            "graph\tadd_graph\tnodes\t1\tinputs\t1\toutputs\t1\ttensors\t1",
            "node\t0\top\tAdd\tname\tadd_0\tinputs\t2\toutputs\t1",
            "input\t0\tx\ttype\t1\ttype_name\tfloat\tdims\td3",
            "output\t0\ty\ttype\t1\ttype_name\tfloat\tdims\td3",
            "tensor\t0\tb\ttype\t1\ttype_name\tfloat\tdims\t3\tfloat\t3\traw\t0",
            "walked\tend",
        ],
        "the default opset writes an empty domain, which reads as -"
    );
}

#[test]
fn a_symbolic_axis_a_named_axis_and_an_unknown_one_are_three_different_answers() {
    assert_eq!(
        rows("symbolic.onnx"),
        vec![
            "onnx\t220\tnodes\t2\ttensors\t0\topsets\t2\tbad\t0",
            "ir\t14\topset\t-\tversion\t17",
            "producer\tonnx-fixture-generator\tversion\t1.2.3\tdomain\tlab.test\tmodel_version\t42\tdoc\tbatch axis is symbolic, one axis is unknown",
            "opset\t0\tdomain\t-\tversion\t17",
            "opset\t1\tdomain\tai.onnx.ml\tversion\t3",
            "graph\tsymbolic_graph\tnodes\t2\tinputs\t1\toutputs\t1\ttensors\t0",
            "node\t0\top\tRelu\tname\trelu_0\tinputs\t1\toutputs\t1",
            "node\t1\top\tNeg\tname\tneg_0\tinputs\t1\toutputs\t1",
            "input\t0\tx\ttype\t1\ttype_name\tfloat\tdims\tpN,d3,u",
            "output\t0\ty\ttype\t1\ttype_name\tfloat\tdims\tpN,d3,u",
            "walked\tend",
        ],
        "`u` is an axis the file leaves unset: printing 0 there would invent a rank"
    );
}

#[test]
fn each_element_type_is_named_only_where_a_fixture_witnesses_it() {
    let lines = rows("types.onnx");
    assert_eq!(
        lines[0],
        "onnx\t324\tnodes\t1\ttensors\t11\topsets\t1\tbad\t0"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("tensor\t"))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        [
            "tensor\t0\tf32\ttype\t1\ttype_name\tfloat\tdims\t2\tfloat\t2\traw\t0",
            "tensor\t1\ti32\ttype\t6\ttype_name\tint32\tdims\t3\tint32\t3\traw\t0",
            "tensor\t2\ti64\ttype\t7\ttype_name\tint64\tdims\t2\tint64\t2\traw\t0",
            "tensor\t3\tf64\ttype\t11\ttype_name\tdouble\tdims\t2\tdouble\t2\traw\t0",
            "tensor\t4\tflag\ttype\t9\ttype_name\tbool\tdims\t2\tint32\t2\traw\t0",
            "tensor\t5\tu8\ttype\t2\ttype_name\tuint8\tdims\t3\tint32\t3\traw\t0",
            "tensor\t6\ti8\ttype\t3\ttype_name\tint8\tdims\t2\tint32\t2\traw\t0",
            "tensor\t7\th\ttype\t10\ttype_name\tfloat16\tdims\t2\tint32\t2\traw\t0",
            "tensor\t8\twords\ttype\t8\ttype_name\tstring\tdims\t2\tbytes\t2\traw\t0",
            "tensor\t9\twide\ttype\t1\ttype_name\tfloat\tdims\t2x3\tfloat\t6\traw\t0",
            "tensor\t10\traw\ttype\t1\ttype_name\tfloat\tdims\t3\traw\t12",
        ]
        .join("\n"),
        "bool, uint8, int8 and float16 all live in int32_data; string payloads are one region each"
    );
    assert_eq!(
        *lines
            .iter()
            .find(|line| line.starts_with("tensor\t9"))
            .unwrap(),
        "tensor\t9\twide\ttype\t1\ttype_name\tfloat\tdims\t2x3\tfloat\t6\traw\t0",
        "a 2x3 tensor reports six values over two axes, which is the arithmetic the file states"
    );
}

#[test]
fn a_model_built_from_tags_is_read_by_the_same_rules() {
    let bytes = hand_built();
    assert_eq!(parse(&bytes), FORMAT_ONNX, "{} bytes", bytes.len());
    assert_eq!(
        report(),
        vec![
            format!(
                "onnx\t{}\tnodes\t1\ttensors\t0\topsets\t1\tbad\t0",
                bytes.len()
            ),
            "ir\t14\topset\t-\tversion\t17".to_owned(),
            "producer\t-".to_owned(),
            "opset\t0\tdomain\t-\tversion\t17".to_owned(),
            "graph\t-\tnodes\t1\tinputs\t0\toutputs\t0\ttensors\t0".to_owned(),
            "node\t0\top\tAdd\tname\tn0\tinputs\t1\toutputs\t1".to_owned(),
            "walked\tend".to_owned(),
        ]
    );
}

#[test]
fn a_message_that_does_not_look_like_a_model_is_not_claimed() {
    // Parses cleanly as protobuf - every field is skipped by wire type - but states no ir_version, so
    // structure alone cannot call this ONNX.
    let mut no_ir = number(5, 1);
    pad(&mut no_ir);
    assert_eq!(parse(&no_ir), -2, "no version, no graph, no claim");

    // An obsolete group: the walk cannot get past it.
    let mut grouped = number(1, 14);
    grouped.extend_from_slice(&tag(2, 3));
    pad(&mut grouped);
    assert_eq!(parse(&grouped), -2, "wire types 3 and 4 are not followed");

    // A length that reaches past the buffer.
    let mut lying = number(1, 14);
    lying.extend_from_slice(&tag(7, 2));
    lying.extend_from_slice(&varint(9_000));
    lying.extend_from_slice(&[0x28; 24]);
    assert_eq!(parse(&lying), -2, "a region cannot be longer than the file");

    assert_eq!(parse(&[0u8; 32]), -2, "field zero is not a field");
    assert_eq!(
        parse(&[0xFFu8; 32]),
        -2,
        "a run of 0xFF never closes a varint"
    );

    // A graph with neither nodes nor declared inputs describes no model.
    let mut graph = Vec::new();
    graph.extend_from_slice(&region(2, b"quiet_graph_without_any_nodes"));
    let mut bare = number(1, 14);
    bare.extend_from_slice(&region(7, &graph));
    bare.extend_from_slice(&region(8, &number(2, 17)));
    assert_eq!(
        parse(&bare),
        -2,
        "ir_version and an opset alone are not enough"
    );
}

#[test]
fn a_truncated_model_is_refused_rather_than_half_read() {
    // Every top-level field of types.onnx is 1, 7 or 8, and cutting the tail makes the graph region
    // reach past the end - so the prefix is well-formed protobuf that simply stops early.
    for cut in [1usize, 3, 8, 40, 60] {
        let bytes = fixture("types.onnx");
        let head = &bytes[..bytes.len() - cut];
        assert_eq!(parse(head), -2, "a {cut}-byte tail cut must not be claimed");
    }
    assert_eq!(parse(&fixture("types.onnx")), FORMAT_ONNX);
}

#[test]
fn short_buffers_are_refused_before_any_reader_runs() {
    assert_eq!(parse(&[0x08, 0x0e, 0x3a, 0x00]), -1);
    assert_eq!(parse(&[0u8; 7]), -1);
}
