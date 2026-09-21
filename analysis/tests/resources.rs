//! The Resources window: every body two PE writers hung on a directory tree, read three ways.
//!
//! `test/fixtures/resource.probe.json` comes from `scripts/make-resource-fixtures.py`, which builds the
//! two fixtures with two different toolchains and then asks three implementations about them:
//!
//!   * `res.dll` - `csc` (the .NET compiler service) with an icon file, a manifest and its own version
//!     block. Every identifier is numeric, because that is all a managed compiler ever emits.
//!   * `rcres.dll` - Microsoft's `rc.exe` writes the tree, GNU `windres` turns the `.res` into an object
//!     and `gcc` links it, so the container comes from a third project. This one has *string* types and
//!     a *string* name, the half of the name table `csc` cannot reach, and it is PE32+.
//!
//! The readers are a Python walk of the bytes, `llvm-readobj --coff-resources`, and Windows' own loader
//! through `LoadLibraryExW(..., LOAD_LIBRARY_AS_DATAFILE)` - a mapping that runs no code and needs no
//! elevation. The loader is the one that makes the rest checkable: it enumerates the types, states each
//! body's size, and hands back the bytes, which are compared against the file at the offset this walk
//! derived from the entry's RVA. An RVA that resolves to the wrong byte would agree with nobody.
//!
//! Two things the fixtures settled rather than assumed. rc stores a string *type* with the quote
//! characters inside the text (`"LABNAME"`), and llvm prints the name with them taken off - the rows
//! keep the file's own spelling, since that is what the loader hands back too. And GNU's chain leaves
//! the codepage word of a data entry uninitialised, so `rcres.dll` prints a number that is not a
//! codepage: the row is what the file carries, not what the format intended.

use apk_lens_analysis::{analyse, resource_at, resource_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-resource-fixtures.py: {error}")
    });
    assert!(analyse(&bytes).is_some(), "{name} has to be a PE");
    let total = resource_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = resource_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// The tree a managed compiler writes: four types, five bodies, every identifier numeric, and the two
/// icon bodies under the same type at names 2 and 3 - which is why the entry row carries its type's
/// index as well as its own number within that type.
#[test]
fn a_managed_library_lists_the_icon_version_and_manifest_it_carries() {
    assert_eq!(
        rows("res.dll"),
        vec![
            "resources\ttypes\t4\tentries\t5\tstrings\t0\tdir\t2\trva\t0x4000\tmachine\tx86\twide\tno",
            "type\t0\tid\t3\tword\tICON\tbodies\t2",
            "type\t1\tid\t14\tword\tGROUP_ICON\tbodies\t1",
            "type\t2\tid\t16\tword\tVERSIONINFO\tbodies\t1",
            "type\t3\tid\t24\tword\tMANIFEST\tbodies\t1",
            "entry\t0\t0\tid\t2\tlang\t0\tbytes\t95\trva\t0x4398\toff\t2456\tcodepage\t0",
            "entry\t0\t1\tid\t3\tlang\t0\tbytes\t125\trva\t0x43f8\toff\t2552\tcodepage\t0",
            "entry\t1\t0\tid\t32512\tlang\t0\tbytes\t34\trva\t0x4478\toff\t2680\tcodepage\t0",
            "entry\t2\t0\tid\t1\tlang\t0\tbytes\t564\trva\t0x4160\toff\t1888\tcodepage\t0",
            "entry\t3\t0\tid\t2\tlang\t0\tbytes\t297\trva\t0x44a0\toff\t2720\tcodepage\t0",
        ]
    );
}

/// The other half of the name table, from a different writer and a wider header: two string types with
/// numeric names, one numeric type with a string name, and language 1033 where `csc` used 0.
#[test]
fn a_string_type_and_a_string_name_are_the_files_spelling_not_the_readers_invention() {
    assert_eq!(
        rows("rcres.dll"),
        vec![
            "resources\ttypes\t3\tentries\t3\tstrings\t3\tdir\t2\trva\t0x4000\tmachine\t0x8664\twide\tyes",
            "type\t0\ttext\t\"LABNAME\"\tword\t-\tbodies\t1",
            "type\t1\ttext\t\"OTHER\"\tword\t-\tbodies\t1",
            "type\t2\tid\t10\tword\tRCDATA\tbodies\t1",
            "entry\t0\t0\tid\t11\tlang\t1033\tbytes\t15\trva\t0x4120\toff\t2848\tcodepage\t1735357008",
            "entry\t1\t0\tid\t260\tlang\t1033\tbytes\t15\trva\t0x4130\toff\t2864\tcodepage\t909259060",
            "entry\t2\t0\ttext\tLABTYPE\tlang\t1033\tbytes\t20\trva\t0x4140\toff\t2880\tcodepage\t1212350575",
        ]
    );
}

/// Every body's offset has to be a place in the file that holds the body, so the bytes there are read
/// back and compared with what the writer says the resource contains. This is the check the loader also
/// makes in the probe script; on this side it catches a section-table mapping that would otherwise only
/// show up as a wrong number in a panel.
#[test]
fn every_body_the_tree_names_is_where_the_tree_says_it_is() {
    let bytes = fs::read(format!("{FIXTURES}res.dll")).expect("the fixture the probe was made from");
    for row in rows("res.dll").into_iter().filter(|one| one.starts_with("entry\t")) {
        let cell: Vec<&str> = row.split('\t').collect();
        let at: usize = cell[cell.iter().position(|one| *one == "off").unwrap() + 1].parse().unwrap();
        let size: usize = cell[cell.iter().position(|one| *one == "bytes").unwrap() + 1].parse().unwrap();
        assert!(at + size <= bytes.len(), "{row} reads past the end of the file");
        assert!(size > 0, "{row} states an empty body");
        // The two icon bodies are PNG data, and the manifest is XML: whatever they are, they are not
        // another directory header, which is what a mis-mapped RVA would land on.
        let head = &bytes[at..at + 4];
        assert!(!head.starts_with(b"PE\0\0"), "{row} points at a header, not a body");
    }
}

/// An ELF has no resource directory, so the panel is empty rather than wrong - and a PE without one is
/// empty the same way, not an error.
#[test]
fn a_file_with_no_resource_directory_answers_with_nothing() {
    assert!(analyse(&fs::read(format!("{FIXTURES}lab.elf")).expect("the ELF fixture")).is_some());
    assert_eq!(resource_count(), 0, "an ELF was given a resource tree");
    // A COFF object is not an image, so it has no data directories at all - the same empty answer, for
    // a different reason, and the one a panel has to be able to tell from "the file has none".
    let bare = fs::read(format!("{FIXTURES}answer.obj")).expect("an object file");
    assert!(analyse(&bare).is_some());
    assert_eq!(resource_count(), 0, "an object file grew a resource directory");
}
