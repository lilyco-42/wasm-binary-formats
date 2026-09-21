//! The version block a PE states about itself, read from the resource tree and checked against
//! `version.dll`.
//!
//! `scripts/make-version-fixtures.py` parses `res.dll`'s 564-byte VERSIONINFO in Python - the tree
//! under the resource directory's type 16, reached by the same walk the Resources panel uses - and then
//! asks Windows the same questions through `GetFileVersionInfoW` and `VerQueryValueW`, which load the
//! block without running the file. The probe is not written unless the thirteen words of the fixed block
//! match exactly, the language and codepage pairs match, and every key the file's tree lists answers
//! the same string through the API - and, the other way round, unless the API has no key the tree does
//! not list.
//!
//! That second direction is the reason this panel exists. `VerQueryValueW` cannot enumerate, so a
//! caller that asks for a fixed list of names never sees `Assembly Version`, which is a key `csc`
//! writes and no standard list carries. Only reading the file finds it.
//!
//! Three facts came out of making the fixtures and are what the tests below hold: a text node's
//! `wValueLength` counts characters and a binary one's bytes - read the four-byte `Translation` as
//! double its size and the next node's `wLength` (404) turns into a second language that the file does
//! not have; `GetFileVersionInfoSizeW` answers 1132 for a 564-byte body, so it is not a check on the
//! resource's own length; and a `Var` node can carry text type with a zero value length, which is how
//! `VarFileInfo` reaches its child at an offset its own value does not explain.

use apk_lens_analysis::{analyse, version_at, version_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run python scripts/make-version-fixtures.py: {error}")
    });
    assert!(analyse(&bytes).is_some(), "{name} has to be a PE");
    let total = version_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = version_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written >= 0, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// What `csc` says about a library it built with no company, no product and no description: the three
/// free-text fields come out as a single space each, and the version is the assembly version - four
/// numbers, printed as the file states them rather than as the two u32s that hold them.
#[test]
fn the_version_block_a_managed_compiler_writes_is_the_one_the_api_reads() {
    assert_eq!(
        rows("res.dll"),
        vec![
            "version\tsignature\t0xfeef04bd\tstruct\t1.0\tfile\t0.0.0.0\tproduct\t0.0.0.0\tflags-mask\t0x3f\tflags\t0x0\tos\t0x4\ttype\t0x2\tsubtype\t0x0\tdate\t0\ttables\t1\tstrings\t7",
            "translation\t0\tlang\t0x0000\tcodepage\t0x04b0",
            "string\tFileDescription\t ",
            "string\tFileVersion\t0.0.0.0",
            "string\tInternalName\tres.dll",
            "string\tLegalCopyright\t ",
            "string\tOriginalFilename\tres.dll",
            "string\tProductVersion\t0.0.0.0",
            "string\tAssembly Version\t0.0.0.0",
        ]
    );
}

/// The key `version.dll` is never asked for by name, and the only reason it appears here is that the
/// file's own tree was read rather than a list of expected keys.
#[test]
fn a_key_no_standard_list_carries_still_has_to_answer() {
    let found = rows("res.dll");
    assert!(
        found.iter().any(|row| row == "string\tAssembly Version\t0.0.0.0"),
        "the tree's own keys were not listed: {found:?}"
    );
    // Two of the three free-text fields are a single space in this file, which is what the file says
    // rather than what a viewer would prefer - so they stay, and are not reported as empty.
    let blanks = found.iter().filter(|row| row.ends_with('\t')).count();
    assert_eq!(blanks, 0, "a value was dropped instead of printed as the file spells it");
    assert_eq!(found.iter().filter(|row| row.starts_with("string\t")).count(), 7);
}

/// A PE with no version resource answers with nothing, and so does a PE that was built by a different
/// toolchain entirely: `rcres.dll` carries three string-typed resources and no version block, and
/// `GetFileVersionInfoSizeW` reports zero for it - the two readers agreeing on the absence.
#[test]
fn a_file_that_says_nothing_about_itself_answers_with_nothing() {
    assert_eq!(rows("rcres.dll"), Vec::<String>::new());
    for name in ["lab.elf", "answer.obj"] {
        let bytes = fs::read(format!("{FIXTURES}{name}")).expect("the fixture");
        assert!(analyse(&bytes).is_some(), "{name} has to parse");
        assert_eq!(version_count(), 0, "{name} answered with a version block");
    }
}
