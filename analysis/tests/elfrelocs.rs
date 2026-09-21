//! The dynamic relocation records of two real shared objects: what `ld.so` is told to rewrite.
//!
//! `test/fixtures/lab.so` and `lab32.so` are compiled here with `clang --target=… -shared -nostdlib
//! -fPIC`, so every record is the linker's doing. `scripts/make-elf-reloc-fixtures.py` lists them twice
//! with readers that are not this repo's - `readelf -rW` and `objdump -R` - and refuses to write
//! `test/fixtures/elfreloc.probe.json` unless the two agree on every offset, type name, symbol and
//! addend. The rows below are the probe's, which is to say both witnesses'.
//!
//! The point of carrying both classes is the last column of the pairing: the *same number* means a
//! different word in the two instruction sets. Six is `R_X86_64_GLOB_DAT` in one file and
//! `R_386_GLOB_DAT` in the other, and one is `R_X86_64_64` against `R_386_32`, so the name table is
//! keyed on the machine rather than on the number alone.

use apk_lens_analysis::{analyse, reloc_at, reloc_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-elf-reloc-fixtures.py: {error}")
    });
    assert!(analyse(&bytes).is_some(), "{name} has to be an object");
    let total = reloc_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = reloc_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

fn column(row: &str, key: &str) -> Option<String> {
    let cell: Vec<&str> = row.split('\t').collect();
    let at = cell.iter().position(|one| *one == key)?;
    let value = *cell.get(at + 1)?;
    Some(value.to_owned())
}

/// Both tables of the 64-bit object, in the order the section headers list them, with the record size
/// the class actually steps by (24 for a RELA slot, not the 16 a REL slot of the same class uses).
#[test]
fn a_sixty_four_bit_shared_object_lists_every_slot_the_linker_left() {
    let listed = rows("lab.so");
    assert_eq!(
        listed[0],
        "relocs\tkind\tdyn\ttables\t2\tentries\t9\tsymbolic\t8\trelative\t1\tmachine\tx86_64\tbits\t64",
        "{}",
        listed[0]
    );
    assert_eq!(listed[1], "table\t.rela.dyn\tentries\t7\tslot_bytes\t24\taddend\tyes");
    assert_eq!(listed[2], "table\t.rela.plt\tentries\t2\tslot_bytes\t24\taddend\tyes");
    assert_eq!(listed.len(), 12, "a different number of rows: {listed:#?}");
    for row in listed.iter().skip(3) {
        assert!(row.starts_with("fixup\t0x"), "{row}");
        assert!(column(row, "name").is_some(), "{row} has no name column");
    }
    // A pointer to something elsewhere: the slot is in `.got`, the symbol has no value of its own, and
    // the addend is the zero the file states rather than nothing.
    assert_eq!(
        listed[4],
        "fixup\t0x2680\ttype\t6\tname\tR_X86_64_GLOB_DAT\tsym\tdata_at\taddend\t0\tsection\t.got"
    );
    // The addend case: `&table[1]` is the symbol plus four, and both readers said four.
    assert_eq!(
        listed[7],
        "fixup\t0x36b8\ttype\t1\tname\tR_X86_64_64\tsym\ttable\taddend\t4\tsection\t.data"
    );
    // And a jump slot, which is the PLT's own pointer rather than a data one.
    assert_eq!(
        listed[10],
        "fixup\t0x36f8\ttype\t7\tname\tR_X86_64_JUMP_SLOT\tsym\tuse_data\taddend\t0\tsection\t.got.plt"
    );
}

/// The symbol-less record - "write the load address plus this" - has no name to print, and the count of
/// them is in the totals row, because a reader that quietly resolved index zero would name the first
/// entry of `.dynsym` (an undefined null symbol) as if the file had pointed at it.
#[test]
fn a_relative_record_prints_no_symbol_because_it_has_none() {
    let listed = rows("lab.so");
    assert_eq!(
        listed[3],
        "fixup\t0x36d8\ttype\t8\tname\tR_X86_64_RELATIVE\tsym\t-\taddend\t14016\tsection\t.data"
    );
    assert_eq!(column(&listed[0], "relative"), Some("1".to_owned()));
    assert_eq!(column(&listed[0], "symbolic"), Some("8".to_owned()));
    let unnamed: Vec<&String> = listed
        .iter()
        .filter(|one| column(one, "sym").as_deref() == Some("-"))
        .collect();
    assert_eq!(unnamed.len(), 1, "{listed:#?}");
}

/// The 32-bit object's records are eight bytes with no addend word, and its type numbers mean the i386
/// words. Every offset in this file is a `.got` or `.got.plt` slot too, so the two classes are read at
/// different strides and named from different tables while answering the same question.
#[test]
fn the_same_type_number_is_named_for_the_machine_the_file_was_written_for() {
    let listed = rows("lab32.so");
    assert_eq!(
        listed[0],
        "relocs\tkind\tdyn\ttables\t2\tentries\t9\tsymbolic\t8\trelative\t1\tmachine\ti386\tbits\t32",
        "{}",
        listed[0]
    );
    assert_eq!(listed[1], "table\t.rel.dyn\tentries\t7\tslot_bytes\t8\taddend\tno");
    assert_eq!(listed[2], "table\t.rel.plt\tentries\t2\tslot_bytes\t8\taddend\tno");
    assert_eq!(
        listed[4],
        "fixup\t0x2460\ttype\t6\tname\tR_386_GLOB_DAT\tsym\tdata_at\taddend\t-\tsection\t.got"
    );
    assert_eq!(
        listed[7],
        "fixup\t0x347c\ttype\t1\tname\tR_386_32\tsym\ttable\taddend\t-\tsection\t.data"
    );
    for row in listed.iter().skip(3) {
        assert_eq!(column(row, "addend"), Some("-".to_owned()), "{row}");
    }
    let shared: Vec<(String, String)> = [
        ("lab.so", &listed),
        ("lab32.so", &rows("lab.so")),
    ]
    .into_iter()
    .flat_map(|(name, one)| {
        one.iter()
            .filter(|row| row.starts_with("fixup"))
            .map(move |row| (name.to_owned(), column(row, "name").unwrap_or_default()))
    })
    .collect();
    assert!(
        shared.iter().any(|(_, one)| one == "R_386_32") && shared.iter().any(|(_, one)| one == "R_X86_64_64"),
        "both spellings of type 1 have to appear: {shared:?}"
    );
}

/// The rule that decides which section a slot belongs to is the tightest range, not the first match:
/// `.relro_padding` is NOBITS and spans every writable address in the image, so reading it as the owner
/// of each of these slots would name the padding for all of them.
#[test]
fn a_slot_is_owned_by_the_tightest_section_that_covers_it() {
    let owners: Vec<String> = rows("lab.so")
        .iter()
        .filter(|row| row.starts_with("fixup"))
        .filter_map(|row| column(row, "section"))
        .collect();
    assert_eq!(
        owners,
        vec![
            ".data", ".got", ".got", ".got", ".data", ".got", ".got", ".got.plt", ".got.plt",
        ],
        "the section column drifted"
    );
    assert!(
        !owners.iter().any(|one| one == ".relro_padding" || one == "unmapped"),
        "{owners:?}"
    );
}

/// An AArch64 shared object is where the three readers part company: `objdump -R` prints `UNKNOWN` for
/// every one of its relocation types, while `readelf -rW` and `llvm-readobj --relocs` both write the real
/// words. Two of three is still two readers in agreement, so these types are named; a single reader's
/// word would have gone to the unpaired bucket and printed as a number, which is what the probe's
/// `readelf_only` map is for and why it is empty for these three files. The numbers are the other half of
/// the point: 1025 and 257 are what aarch64 calls the records x86 spells 6 and 1, so a name table keyed
/// on the number alone would have been wrong for every row in this file.
#[test]
fn a_type_two_readers_named_and_one_omitted_is_still_a_named_type() {
    let listed = rows("labarm.so");
    assert_eq!(
        listed[0],
        "relocs\tkind\tdyn\ttables\t2\tentries\t9\tsymbolic\t8\trelative\t1\tmachine\taarch64\tbits\t64",
        "{}",
        listed[0]
    );
    assert_eq!(listed[1], "table\t.rela.dyn\tentries\t7\tslot_bytes\t24\taddend\tyes");
    assert_eq!(listed[2], "table\t.rela.plt\tentries\t2\tslot_bytes\t24\taddend\tyes");
    for row in listed.iter().skip(3) {
        assert!(column(row, "name").is_some_and(|one| one.starts_with("R_AARCH64_")),
                "an aarch64 row without its name: {row}");
    }
    let numbers: Vec<String> = listed
        .iter()
        .skip(3)
        .filter_map(|row| column(row, "type"))
        .collect();
    assert!(
        numbers.contains(&"1025".to_owned()) && numbers.contains(&"257".to_owned()),
        "the aarch64 numbers are 1025 and 257, not x86's 6 and 1: {numbers:?}"
    );
    assert_eq!(
        listed[4],
        "fixup\t0x206a0\ttype\t1025\tname\tR_AARCH64_GLOB_DAT\tsym\tdata_at\taddend\t0\tsection\t.got"
    );
    assert_eq!(
        listed[7],
        "fixup\t0x306d0\ttype\t257\tname\tR_AARCH64_ABS64\tsym\ttable\taddend\t4\tsection\t.data"
    );
}
