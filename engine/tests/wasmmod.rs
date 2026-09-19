//! WebAssembly module sections, read from a module LLVM produced.
//!
//! The fixture is the artifact this repository builds: `engine.yml` compiles the engine to
//! `wasm32-unknown-unknown` *before* the host tests, and this test walks that file. Where the file is
//! absent - a local run that has not built the wasm target - the test says so and passes, because
//! inventing a module by hand would only check the reader against itself. The hand-written cases
//! below are the ones no build produces: a section that runs past the end, and an id the spec does
//! not define. They are labelled as self-authored, and they test the walk's arithmetic, not a
//! producer's layout.
//!
//! `tools/wasm-sim.py` is the python mirror these rows were derived from; run it over any module to
//! see the same report outside Rust.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_WASM};
use std::fs;

const ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/wasm32-unknown-unknown/release/apk_lens.wasm"
);

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(&format!("{named}\t")))
        .unwrap_or_else(|| panic!("no row named {named} in {lines:#?}"))
        .clone()
}

fn number(lines: &[String], named: &str, column: usize) -> i64 {
    row(lines, named)
        .split('\t')
        .nth(column)
        .unwrap_or_else(|| panic!("row {named} has no column {column}"))
        .parse()
        .unwrap_or_else(|error| panic!("row {named} is not a number: {error}"))
}

#[test]
fn walks_the_module_the_ci_build_produced() {
    let Ok(bytes) = fs::read(ARTIFACT) else {
        eprintln!("skipped: {ARTIFACT} is built by .github/workflows/engine.yml before cargo test");
        return;
    };
    assert_eq!(parse(&bytes), FORMAT_WASM);
    assert_eq!(
        kind(),
        FORMAT_WASM,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "wasm", "the reader has to name what it walked");
    let lines = report();
    assert_eq!(
        number(&lines, "wasm", 1),
        1,
        "the only module version in the spec: {lines:#?}"
    );
    assert_eq!(number(&lines, "truncated", 1), 0, "{lines:#?}");
    assert!(
        lines.iter().any(|entry| entry == "walked\tend"),
        "the sections must account for the file: {lines:#?}"
    );
    assert_eq!(
        number(&lines, "wasm", 3),
        0,
        "a toolchain output should carry no undefined section id"
    );
    // The decisive cross-check: the function section lists one entry per function, the code section
    // one body per function. Two independent counts agreeing is what says the boundaries are real
    // rather than an accumulating arithmetic error that happens to land on the file size.
    assert_eq!(number(&lines, "code_matches_functions", 1), 1, "{lines:#?}");
    assert!(
        number(&lines, "exports", 1) > 40,
        "the engine exports its C ABI"
    );
    assert!(number(&lines, "functions", 1) > 100);
    assert!(
        lines.iter().any(|entry| entry.starts_with("custom\tname")),
        "a release build names its functions: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|entry| entry.starts_with("custom\tproducers")),
        "LLVM records the toolchain it used: {lines:#?}"
    );
}

fn module(sections: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for section in sections {
        out.extend_from_slice(section);
    }
    out
}

#[test]
fn a_section_that_overshoots_the_file_is_named_not_assumed() {
    // Self-authored: a type section that declares more bytes than remain. The walk has to stop and
    // say so, instead of reporting a completed module.
    let bytes = module(&[&[0x01, 0x40, 0x00, 0x00]]);
    assert_eq!(parse(&bytes), FORMAT_WASM);
    let lines = report();
    assert_eq!(number(&lines, "truncated", 1), 1, "{lines:#?}");
    assert_eq!(number(&lines, "wasm", 2), 0, "no section was completed");
    assert!(
        !lines.iter().any(|entry| entry == "walked\tend"),
        "{lines:#?}"
    );
}

#[test]
fn an_unknown_section_id_is_reported_as_unknown() {
    // Self-authored: id 63 is not in the specification. It is still a section with a length, so the
    // walk continues past it - but it is counted, and it is not given a name the spec does not use.
    let unknown = [63u8, 0x02, 0xaa, 0x55];
    let export = [0x07u8, 0x01, 0x03];
    let bytes = module(&[&unknown, &export]);
    assert_eq!(parse(&bytes), FORMAT_WASM);
    let lines = report();
    assert_eq!(
        number(&lines, "wasm", 2),
        2,
        "both sections counted: {lines:#?}"
    );
    assert_eq!(
        number(&lines, "wasm", 3),
        1,
        "one of them is unknown: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|entry| entry.starts_with("section\tunknown")),
        "{lines:#?}"
    );
    assert!(
        lines.iter().any(|entry| entry == "section\texport\t1\t14"),
        "the section after it was still reached: {lines:#?}"
    );
    assert_eq!(number(&lines, "exports", 1), 3, "{lines:#?}");
    assert_eq!(number(&lines, "truncated", 1), 0);
    assert!(
        lines.iter().any(|entry| entry == "walked\tend"),
        "{lines:#?}"
    );
}

#[test]
fn a_non_module_is_not_a_module() {
    let mut near = b"\x00asm".to_vec();
    near.extend_from_slice(&[0x01, 0x00, 0x00, 0x02]);
    assert_eq!(
        parse(&near),
        -2,
        "a header with no section at all is nothing to read"
    );
    assert_eq!(parse(b"\x00aix\x01\x00\x00\x00"), -2);
}
