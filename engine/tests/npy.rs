//! NumPy `.npy` arrays: the signature, the header dictionary, and the size arithmetic.
//!
//! Every fixture is written by `numpy.save` / `numpy.lib.format.write_array`
//! (`scripts/make-npy-fixtures.py`), and the generator refuses to commit a file whose data area is
//! not exactly `numpy.dtype.itemsize * product(shape)` as numpy itself computes it. So the item
//! sizes in the rows below - including `'<U4'` being sixteen bytes and not four - are the library's
//! numbers, which is the point: the header spells a type, and the reader has to turn that spelling
//! into a width without any help from the file.
//!
//! The two header widths are the other thing that could quietly go wrong. Version 1 stores the
//! header length as a little-endian u16 and versions 2 and 3 as a u32, and a reader that used one
//! for both would find the header starting on a zero byte - so `v2.npy` is a real u32-headed file
//! rather than a hand-made one.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_NPY};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-npy-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn npy(major: u8, header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x93u8, b'N', b'U', b'M', b'P', b'Y', major, 0];
    if major == 1 {
        out.extend_from_slice(&(header.len() as u16).to_le_bytes());
    } else {
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(header);
    out.extend_from_slice(data);
    out
}

#[test]
fn reads_what_numpy_wrote_and_proves_the_data_area_is_the_array() {
    let bytes = fixture("f64.npy");
    assert_eq!(parse(&bytes), FORMAT_NPY);
    assert_eq!(kind(), FORMAT_NPY, "kind() must agree with the return code");
    assert_eq!(name(), "npy", "the reader has to name what it walked");
    assert_eq!(
        report(),
        vec![
            "npy\t1\t0\t118\t128",
            "dtype\t<f8",
            "shape\t1\t6",
            "fortran_order\tfalse",
            "sizes\t8\telements\t6\texpects\t48\tavailable\t48",
            "walked\tend",
        ]
    );
}

#[test]
fn the_item_size_comes_from_the_type_not_from_the_digits_alone() {
    // '<U4' is four characters of four bytes each, which numpy reports as 16; the rest are their
    // own widths. One row each, all six fixtures, all six numbers from numpy's dtype.
    let cases = [
        (
            "i32.npy",
            "dtype\t>i4",
            "sizes\t4\telements\t12\texpects\t48\tavailable\t48",
        ),
        (
            "uint16.npy",
            "dtype\t<u2",
            "sizes\t2\telements\t6\texpects\t12\tavailable\t12",
        ),
        (
            "bools.npy",
            "dtype\t|b1",
            "sizes\t1\telements\t3\texpects\t3\tavailable\t3",
        ),
        (
            "bytes4.npy",
            "dtype\t|S4",
            "sizes\t4\telements\t2\texpects\t8\tavailable\t8",
        ),
        (
            "unicode.npy",
            "dtype\t<U4",
            "sizes\t16\telements\t2\texpects\t32\tavailable\t32",
        ),
    ];
    for (file, dtype, sizes) in cases {
        assert_eq!(parse(&fixture(file)), FORMAT_NPY, "{file}");
        let lines = report();
        assert_eq!(lines[1], dtype, "{file}");
        assert_eq!(lines[4], sizes, "{file}");
        assert!(
            lines.iter().any(|line| line == "walked\tend"),
            "{file}: {lines:?}"
        );
    }
    assert_eq!(
        parse(&fixture("uint16.npy")),
        FORMAT_NPY,
        "the Fortran-order fixture is also the only one that says so"
    );
    assert_eq!(report()[3], "fortran_order\ttrue");
    assert_eq!(report()[2], "shape\t2\t2\t3");
}

#[test]
fn a_zero_dimensional_array_is_one_element_and_an_empty_shape() {
    assert_eq!(parse(&fixture("scalar.npy")), FORMAT_NPY);
    let lines = report();
    assert_eq!(lines[2], "shape\t0");
    assert_eq!(lines[4], "sizes\t8\telements\t1\texpects\t8\tavailable\t8");
    assert!(lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn versions_two_and_three_widen_the_header_length() {
    assert_eq!(parse(&fixture("v2.npy")), FORMAT_NPY);
    let lines = report();
    assert_eq!(
        lines[0], "npy\t2\t0\t180\t192",
        "a u16 read would not start the header on a brace"
    );
    assert_eq!(
        lines[1], "dtype\t[('alpha', '<f4'), ('beta', '|i1'), ('gamma', '<f8')]",
        "a field list is kept as the text the file holds"
    );
    assert_eq!(
        lines[4],
        "sizes\tunknown\telements\t12\texpects\tunknown\tavailable\t156"
    );
    assert!(
        !lines.iter().any(|line| line == "walked\tend"),
        "no item size, no claim about the data: {lines:?}"
    );

    assert_eq!(parse(&fixture("v3.npy")), FORMAT_NPY);
    let lines = report();
    assert_eq!(lines[0], "npy\t3\t0\t116\t128");
    assert_eq!(lines[1], "dtype\t[('unicode', '<U4')]");
    assert_eq!(
        lines[4],
        "sizes\tunknown\telements\t4\texpects\tunknown\tavailable\t64"
    );
}

#[test]
fn a_data_area_that_does_not_match_the_shape_is_reported_without_being_denied() {
    // Self-authored: two float64 claimed, one supplied. The header is read, the mismatch is printed,
    // and the end is not claimed.
    let bytes = npy(
        1,
        b"{'descr': '<f8', 'fortran_order': False, 'shape': (2,), }",
        &[0u8; 8],
    );
    assert_eq!(parse(&bytes), FORMAT_NPY);
    let lines = report();
    assert_eq!(lines[0], "npy\t1\t0\t57\t67");
    assert_eq!(lines[2], "shape\t1\t2");
    assert_eq!(lines[4], "sizes\t8\telements\t2\texpects\t16\tavailable\t8");
    assert_eq!(lines.len(), 5, "{lines:?}");
}

#[test]
fn a_header_that_cannot_be_read_is_not_claimed_at_all() {
    assert_eq!(
        parse(&npy(4, b"{'descr': '<f8', 'shape': (), }", &[])),
        -2,
        "version 4"
    );
    assert_eq!(
        parse(&npy(1, b"{}", &[])),
        -2,
        "a header too short to be a dictionary"
    );
    assert_eq!(
        parse(&npy(1, b"{'descr': '<f8', 'shape': (x,), }", &[])),
        -2,
        "a shape that is not numbers"
    );
    assert_eq!(
        parse(&npy(1, b"{'descr': '<f8', 'fortran_order': False}", &[])),
        -2,
        "no shape key at all"
    );
    assert_eq!(parse(&npy(1, b"not a dict", &[])), -2, "no braces");
    let mut long = npy(1, b"{'descr': '<f8', 'shape': (), }", &[]);
    let length = 9999u16.to_le_bytes();
    long[8..10].copy_from_slice(&length);
    assert_eq!(parse(&long), -2, "a header longer than the file");
    assert_eq!(
        parse(b"\x93NUMPY\x01\x00\x02\x00ab"),
        -2,
        "too short for any of it"
    );
    assert_eq!(parse(&[0u8; 64]), -2, "zero bytes carry no numpy signature");
}
