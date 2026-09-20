//! COFF object files: what `clang -c` leaves behind before a linker runs, read the way objdump reads it.
//!
//! `test/fixtures/answer.obj` and `test/fixtures/i686.obj` are written by LLVM 22.1.8 - `clang -target
//! x86_64-w64-windows-gnu -c` and the i686 triple - by `scripts/make-coff-fixtures.py`, which then runs
//! GNU objdump over the same bytes and refuses to write the probe unless its own walk agrees with
//! `objdump -h` on every section name, size and file offset, and with `objdump -t` on every symbol's
//! name, value, section, type and storage class. That is the only reason the field offsets below are
//! trustworthy: they came out of a second implementation's output rather than anyone's memory of a
//! specification.
//!
//! Two properties of the format are what the reader has to get right. A name longer than eight bytes
//! is not in the record at all - a section writes `/4` and a symbol leaves four zero bytes plus an
//! offset, and both mean the string table that follows the last symbol record. And the header's symbol
//! count counts *records*, auxiliary entries included, which is why the indices step 0, 2, 4 and why a
//! walk that runs out of file before those records is the only thing a cut row can mean here.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_COFF, FORMAT_ICC, FORMAT_STL};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-coff-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_COFF, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_COFF, "kind() must agree with the return code");
    assert_eq!(name(), "coff", "the reader has to name what it walked");
    report()
}

fn patch(bytes: &mut Vec<u8>, at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn reads_the_x86_64_object_clang_wrote() {
    assert_eq!(
        rows(&fixture("answer.obj")),
        vec![
            "coff\t904\tbroken\t0\tmachine\t8664(x86-64)\tsections\t7\topts\t0",
            "layout\tstamp\t0\tsyms\t19\tat\t544\tstrings\t18@886\tchars\t0000",
            "section\t0\t.text\tvsize\t0\tvaddr\t0\traw\t31@300\treloc\t331x1\tlines\t0x0\tchars\t60500020",
            "section\t1\t.data\tvsize\t0\tvaddr\t0\traw\t0@341\treloc\t0x0\tlines\t0x0\tchars\tc0300040",
            "section\t2\t.bss\tvsize\t0\tvaddr\t0\traw\t0@0\treloc\t0x0\tlines\t0x0\tchars\tc0300080",
            "section\t3\t.xdata\tvsize\t0\tvaddr\t0\traw\t8@341\treloc\t0x0\tlines\t0x0\tchars\t40300040",
            "section\t4\t.debug$S\tvsize\t0\tvaddr\t0\traw\t152@349\treloc\t0x0\tlines\t0x0\tchars\t42300040",
            "section\t5\t.pdata\tvsize\t0\tvaddr\t0\traw\t12@501\treloc\t513x3\tlines\t0x0\tchars\t40300040",
            "section\t6\t.llvm_addrsig\tvsize\t0\tvaddr\t0\traw\t1@543\treloc\t0x0\tlines\t0x0\tchars\t00100800",
            "symbol\t0\t.text\tvalue\t0\tsect\t1\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t2\t.data\tvalue\t0\tsect\t2\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t4\t.bss\tvalue\t0\tsect\t3\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t6\t.xdata\tvalue\t0\tsect\t4\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t8\t.debug$S\tvalue\t0\tsect\t5\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t10\t.pdata\tvalue\t0\tsect\t6\ttype\t0000\tscl\t3\taux\t1\tbase\t-",
            "symbol\t12\t.llvm_addrsig\tvalue\t0\tsect\t7\ttype\t0000\tscl\t3\taux\t1\tbase\t4",
            "symbol\t14\t@feat.00\tvalue\t0\tsect\t-1\ttype\t0000\tscl\t3\taux\t0\tbase\t-",
            "symbol\t15\tanswer\tvalue\t0\tsect\t1\ttype\t0020\tscl\t2\taux\t0\tbase\t-",
            "symbol\t16\thelper\tvalue\t10\tsect\t1\ttype\t0020\tscl\t2\taux\t0\tbase\t-",
            "symbol\t17\t.file\tvalue\t0\tsect\t-2\ttype\t0000\tscl\t103\taux\t1\tbase\t-",
            "walked\tend",
        ]
    );
}

#[test]
fn the_string_table_gives_the_long_names_back_in_both_spellings() {
    // Section six's record holds `/4`; symbol twelve's holds four zero bytes and the offset 4. objdump
    // prints `.llvm_addrsig` for both, which is the witness that the table was read the right way.
    let lines = rows(&fixture("answer.obj"));
    assert!(
        lines[8].starts_with("section\t6\t.llvm_addrsig\t"),
        "{}",
        lines[8]
    );
    assert_eq!(
        lines
            .iter()
            .find(|line| line.starts_with("symbol\t12\t"))
            .unwrap(),
        "symbol\t12\t.llvm_addrsig\tvalue\t0\tsect\t7\ttype\t0000\tscl\t3\taux\t1\tbase\t4"
    );
}

#[test]
fn the_i686_object_reads_the_same_way_under_underscored_names() {
    let lines = rows(&fixture("i686.obj"));
    assert_eq!(
        lines[0],
        "coff\t697\tbroken\t0\tmachine\t014c(i386)\tsections\t5\topts\t0"
    );
    assert_eq!(
        lines[lines.len() - 3],
        "symbol\t12\t_helper\tvalue\t10\tsect\t1\ttype\t0020\tscl\t2\taux\t0\tbase\t-"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
    // The 32-bit object carries no SEH unwind sections, so the difference between the two files is the
    // section list - not the record layout, which is why one reader covers both.
    assert!(
        !lines.iter().any(|line| line.contains(".pdata") || line.contains(".xdata")),
        "{lines:?}"
    );
}

#[test]
fn a_section_pointing_past_the_end_is_counted_and_still_listed() {
    let mut bytes = fixture("answer.obj");
    // Section zero's SizeOfRawData, at 20 + 16.
    patch(&mut bytes, 36, 0xFFFF_FFFF);
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "coff\t904\tbroken\t1\tmachine\t8664(x86-64)\tsections\t7\topts\t0"
    );
    assert!(
        lines[2].contains("raw\t4294967295@300"),
        "the claim is printed as stated: {}",
        lines[2]
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
}

#[test]
fn a_string_table_that_mis_states_itself_is_the_other_kind_of_failure() {
    let mut bytes = fixture("answer.obj");
    // The table starts at 886 and says it is 18 bytes, which is exactly what lands on the end of the
    // file; a lie there cannot be checked any other way.
    patch(&mut bytes, 886, 40);
    let lines = rows(&bytes);
    assert_eq!(
        lines[0],
        "coff\t904\tbroken\t1\tmachine\t8664(x86-64)\tsections\t7\topts\t0"
    );
    assert_eq!(
        lines[1],
        "layout\tstamp\t0\tsyms\t19\tat\t544\tstrings\t40@886\tchars\t0000"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
}

#[test]
fn an_object_that_states_no_symbols_says_so_instead_of_pointing_at_a_table() {
    let mut bytes = fixture("answer.obj");
    patch(&mut bytes, 12, 0);
    let lines = rows(&bytes);
    assert_eq!(
        lines[1],
        "layout\tstamp\t0\tsyms\t0\tat\t544\tstrings\t-\tchars\t0000",
        "with no records there is nothing for the string table to follow, so its place is unknown"
    );
    assert_eq!(
        lines.iter().filter(|line| line.starts_with("symbol")).count(),
        0
    );
    assert_eq!(lines.len(), 10, "header, layout, seven sections, walked");
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn an_image_or_a_file_that_cannot_hold_its_own_tables_is_not_claimed() {
    let mut with_header = fixture("answer.obj");
    with_header[16..18].copy_from_slice(&224u16.to_le_bytes());
    assert_ne!(
        parse(&with_header),
        FORMAT_COFF,
        "an optional header means an image, which is the PE reader's business when MZ leads"
    );

    let mut dos = fixture("answer.obj");
    dos[0..2].copy_from_slice(b"MZ");
    assert_ne!(
        parse(&dos),
        FORMAT_COFF,
        "an object cannot open with the DOS stub, so the MZ bytes mean a different file"
    );

    let mut no_sections = fixture("answer.obj");
    no_sections[2..4].copy_from_slice(&0u16.to_le_bytes());
    assert_ne!(parse(&no_sections), FORMAT_COFF, "no sections is no object");

    let mut too_many = fixture("answer.obj");
    too_many[2..4].copy_from_slice(&400u16.to_le_bytes());
    assert_ne!(
        parse(&too_many),
        FORMAT_COFF,
        "400 records of 40 bytes are not in 904 bytes"
    );

    let mut stray = fixture("answer.obj");
    patch(&mut stray, 8, 5000);
    assert_ne!(
        parse(&stray),
        FORMAT_COFF,
        "a symbol table outside the file is not read at all"
    );

    assert_eq!(parse(b"aaaaaaaabbbbbbbb"), -2, "sixteen bytes name no object");
    assert_ne!(parse(&fixture("srgb.icc")), FORMAT_COFF, "a profile is not an object");
    assert_ne!(parse(&fixture("tet.stl")), FORMAT_COFF, "nor is a mesh");
    assert_eq!(
        parse(&fixture("srgb.icc")),
        FORMAT_ICC,
        "and the profile still reaches its own reader"
    );
    assert_eq!(
        parse(&fixture("tet.stl")),
        FORMAT_STL,
        "and the mesh still reaches its own"
    );
}
