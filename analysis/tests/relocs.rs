//! The base-relocation directory of three real PE images: what the loader is told to rewrite.
//!
//! `test/fixtures/reloc.dll` is `clang` plus `lld-link` for `x86_64-pc-windows-msvc`, and it exists
//! because the committed images had nothing to read: `exp.dll` carries no directory at all and
//! `lab.exe` is a freestanding image whose data needs no fixup. `lab.dll` is the .NET compiler's PE32,
//! which is the other half of the optional-header branch and the only fixture with a padding entry.
//!
//! `scripts/make-reloc-fixtures.py` read all three with `llvm-readobj --coff-basereloc` and with
//! `pefile`, and refuses to write `test/fixtures/reloc.probe.json` unless the two agree on every entry.
//! That agreement is also where the type numbers got their names: the pairing `10 -> DIR64` came from
//! the same address carrying both in one file, so the numbers below are witnessed rather than recalled,
//! and a number no fixture paired is printed as a number.

use apk_lens_analysis::{analyse, reloc_at, reloc_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-reloc-fixtures.py: {error}")
    })
}

fn rows(name: &str) -> Vec<String> {
    rows_of(&fixture(name))
}

fn rows_of(bytes: &[u8]) -> Vec<String> {
    assert!(analyse(bytes).is_some(), "the file has to be an object");
    let total = reloc_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = reloc_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// A PE32+ whose `.data` holds four address-taken objects, so the linker had to record four fixups.
/// Each one is in a section, and the position is where the loader will write - which is the whole reason
/// to read the directory: a word at `0x3000` is a pointer, not the number `0`.
#[test]
fn a_shared_object_lists_the_addresses_its_linker_left_to_be_fixed_up() {
    assert_eq!(
        rows("reloc.dll"),
        vec![
            "relocs\tdir\t0x5000\tbytes\t16\toff\t3072\tsection\t.reloc\tblocks\t1\tentries\t4\tnamed\t4",
            "block\tpage\t0x3000\tsize\t16\tentries\t4",
            "fixup\t0x3000\ttype\t10\tname\tDIR64\toff\t2048\tsection\t.data",
            "fixup\t0x3008\ttype\t10\tname\tDIR64\toff\t2056\tsection\t.data",
            "fixup\t0x3010\ttype\t10\tname\tDIR64\toff\t2064\tsection\t.data",
            "fixup\t0x3018\ttype\t10\tname\tDIR64\toff\t2072\tsection\t.data",
        ],
        "one block, four 64-bit fixups, in the order the directory carries them"
    );
}

/// The same directory in a PE32, where the block is 12 bytes: one `HIGHLOW` entry and one `ABSOLUTE`
/// padding slot. The padding fixes up nothing and is still listed, because it is in the file and a
/// count that quietly dropped it would not add up to the block's own length.
#[test]
fn a_thirty_two_bit_image_shows_its_padding_entry_and_the_other_header_base() {
    assert_eq!(
        rows("lab.dll"),
        vec![
            "relocs\tdir\t0x6000\tbytes\t12\toff\t2560\tsection\t.reloc\tblocks\t1\tentries\t2\tnamed\t2",
            "block\tpage\t0x2000\tsize\t12\tentries\t2",
            "fixup\t0x2310\ttype\t3\tname\tHIGHLOW\toff\t1296\tsection\t.text",
            "fixup\t0x2000\ttype\t0\tname\tABSOLUTE\toff\t512\tsection\t.text",
        ]
    );
}

/// An image with nothing to apply is an answer, not a failure: `exp.dll` was linked from a freestanding
/// object with one exported function, so its data holds no address of anything.
#[test]
fn an_image_with_no_directory_says_so_rather_than_being_reported_as_broken() {
    assert_eq!(
        rows("exp.dll"),
        vec!["relocs\tdir\t0x0\tbytes\t0\toff\t-1\tsection\tnone\tblocks\t0\tentries\t0\tnamed\t0"]
    );
    // A COFF object has no data directories to look at at all, so the list is empty rather than left
    // over from the DLL read a moment before.
    rows_of(&fixture("answer.obj"));
    assert_eq!(reloc_count(), 0, "an object file has no base relocations");
    assert_eq!(reloc_at(0, std::ptr::null_mut(), 0), -1);
    // An ELF is an image and still answers with nothing: the per-page block list is a PE's, and an
    // ELF's fixups are relocation records, which are a different structure read a different way.
    rows_of(&fixture("lab.elf"));
    assert_eq!(reloc_count(), 0, "an ELF keeps its fixups in relocation records");
}

/// A block whose own length is impossible ends the walk and says which claim it stopped on. The entry
/// counts stay at what was read before the contradiction, because those are the file's own earlier words.
#[test]
fn a_block_that_contradicts_its_directory_is_stopped_and_named() {
    // The block header's u32 length, four bytes past the directory's start at file offset 3072.
    for (size, why) in [(4u32, "block size"), (4096, "block size")] {
        let mut bytes = fixture("reloc.dll");
        bytes[3076..3080].copy_from_slice(&size.to_le_bytes());
        let listed = rows_of(&bytes);
        assert_eq!(
            listed[0],
            format!(
                "relocs\tdir\t0x5000\tbytes\t16\toff\t3072\tsection\t.reloc\tblocks\t0\tentries\t0\tnamed\t0\tstopped\t{why}"
            ),
            "a block of {size} bytes: {listed:?}"
        );
        assert_eq!(listed.len(), 1, "nothing past the contradiction is listed: {listed:?}");
    }
}

/// A type number that no fixture ever put beside a name stays a number. The row is still printed,
/// because the entry is in the file; only the *word* for it is withheld, since nothing here established
/// which word belongs to it.
#[test]
fn an_unpaired_type_number_is_printed_as_a_number_and_not_named() {
    let mut bytes = fixture("reloc.dll");
    // The first entry's high nibble. The block starts at file offset 3072, so its eight-byte header
    // ends at 3080 and the first two-byte entry lives there: 7 is no type in this lab's pairings.
    bytes[3081] = 0x70;
    let listed = rows_of(&bytes);
    assert_eq!(
        listed[2],
        "fixup\t0x3000\ttype\t7\toff\t2048\tsection\t.data",
        "the number is the file's; the name would be ours: {listed:?}"
    );
    assert!(
        listed[0].ends_with("\tentries\t4\tnamed\t3"),
        "one entry lost its name: {}",
        listed[0]
    );
    // The other three are still DIR64, so the pairing is per entry and not per file.
    assert!(listed[3].contains("\tname\tDIR64\t"), "{}", listed[3]);
}
