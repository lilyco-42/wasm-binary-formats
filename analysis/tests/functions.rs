//! The Functions window: the addresses the file's own symbol tables call functions, cross-checked
//! against `readelf -sW`'s FUNC rows for the same bytes.
//!
//! Every expectation below is `readelf`'s, not this reader's: `Value` becomes the hex address, `Size`
//! the size column, `Ndx` resolves through the section table to the name `readelf -SW` prints at that
//! index, and `Name` is the symbol's own spelling. `cxx.o` and `ops.o` are the objects
//! `scripts/make-demangle-fixtures.py` compiles with clang, `lab.elf` is the freestanding image
//! `scripts/make-image-fixtures.py` links, and the two DLLs are `csc.exe`'s and `lld-link`'s.
//!
//! The demangled column is the two-witness reading the demangler already publishes, so `_Z4varsPcPKwDn`
//! answers `-` here for the same reason it does there: binutils and LLVM disagree about `Dn`, and this
//! window does not pick a side.

use apk_lens_analysis::{analyse, function_at, function_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("{path} missing, run the fixture script named in README: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object");
    let total = function_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = function_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

fn column<'a>(row: &'a str, key: &str) -> Option<&'a str> {
    let cell = row.split('\t').collect::<Vec<_>>();
    cell.iter().position(|one| *one == key).map(|at| cell[at + 1])
}

/// readelf's FUNC list for `cxx.o`, in table order: value, size, section name, symbol name.
const CXX: &[(&str, &str, &str, &str)] = &[
    ("0x0", "20", ".text", "_Z7one_refRiS_"),
    ("0x20", "18", ".text", "_ZN2ns9nested_fnEPNS_3BoxEc"),
    ("0x40", "10", ".text", "_ZN3FooC2Ev"),
    ("0x50", "10", ".text", "_ZN3FooD2Ev"),
    ("0x60", "12", ".text", "_ZNK3Foo4readEv"),
    ("0x70", "18", ".text", "_ZN3Foo3setEPdRKc"),
    ("0x90", "12", ".text", "_ZN3Foo4statEl"),
    ("0xa0", "18", ".text", "_ZN3Foo6matrixERA5_i"),
    ("0xc0", "16", ".text", "_ZNK3Foo2opERKS_"),
    ("0xd0", "19", ".text", "_Z7free_fniPdRKc"),
    ("0xf0", "21", ".text", "_Z6ref_fnRiPPKls"),
    ("0x110", "31", ".text", "_Z5bytesfyajb"),
    ("0x130", "11", ".text", "_Z5retfni"),
    ("0x140", "31", ".text", "_Z4tailjxno"),
    ("0x160", "14", ".text", "_Z4widee"),
    ("0x170", "18", ".text", "_Z4varsPcPKwDn"),
    ("0x190", "21", ".text", "_Z8use_pickv"),
    (
        "0x0",
        "37",
        ".text._Z4pickIiET_S0_S0_",
        "_Z4pickIiET_S0_S0_",
    ),
    ("0x40", "10", ".text", "_ZN3FooC1Ev"),
    ("0x50", "10", ".text", "_ZN3FooD1Ev"),
];

/// Every function in the object, at the address and with the size `readelf` says, in the order the table
/// lists them - including the two entries that share an address because a complete and a base object
/// constructor were emitted for one class.
#[test]
fn an_objects_functions_are_its_own_func_symbols_with_their_stated_sizes() {
    let listed = rows("cxx.o");
    assert_eq!(
        listed[0],
        "functions\ttotal\t20\tsized\t20\tdemangled\t19\tfrom\tsymtabs",
        "the totals row drifted: {}",
        listed[0]
    );
    assert_eq!(listed.len(), CXX.len() + 1, "a different number of rows: {listed:#?}");
    for (index, (address, size, section, symbol)) in CXX.iter().enumerate() {
        let row = &listed[index + 1];
        assert!(row.starts_with("func\t"), "{row}");
        assert_eq!(row.split('\t').nth(1), Some(*address), "{row} address");
        assert_eq!(column(row, "size"), Some(*size), "{row} size");
        assert_eq!(column(row, "section"), Some(*section), "{row} section");
        assert_eq!(column(row, "sym"), Some(*symbol), "{row} symbol name");
    }
    // The demangled column is the two-witness reading, and it is the reason the raw name stays beside it:
    // `C1` and `C2` share one answer, and the `Dn` name has no answer at all.
    assert_eq!(
        column(&listed[1], "name"),
        Some("one_ref(int&, int&)"),
        "{}",
        listed[1]
    );
    assert_eq!(column(&listed[3], "name"), Some("Foo::Foo()"), "{}", listed[3]);
    assert_eq!(column(&listed[19], "name"), Some("Foo::Foo()"), "{}", listed[19]);
    assert_eq!(
        column(&listed[18], "name"),
        Some("int pick<int>(int, int)"),
        "{}",
        listed[18]
    );
    assert_eq!(
        column(&listed[16], "name"),
        Some("-"),
        "the name the two demanglers disagree on must stay unanswered: {}",
        listed[16]
    );
}

/// A linked image carries its entry's *load* address rather than a section offset, and one function is
/// still a window: `readelf` says `entry` is 6 bytes at 0x201190 in `.text`.
#[test]
fn a_linked_image_reports_the_load_address_the_symbol_carries() {
    assert_eq!(
        rows("lab.elf"),
        vec![
            "functions\ttotal\t1\tsized\t1\tdemangled\t0\tfrom\tsymtabs",
            "func\t0x201190\tsize\t6\tsection\t.text\tsym\tentry\tname\t-",
        ]
    );
}

/// The operator object is bigger than the list this module prints for anything else, so its totals row
/// is the one that carries the real count; 48 functions, all sized, all with a spelling two demanglers
/// agree on.
#[test]
fn the_operator_object_lists_every_one_of_its_forty_eight_functions() {
    let listed = rows("ops.o");
    assert_eq!(
        listed[0],
        "functions\ttotal\t48\tsized\t48\tdemangled\t48\tfrom\tsymtabs",
        "{}",
        listed[0]
    );
    assert_eq!(listed.len(), 49, "the list and its totals disagree");
    assert_eq!(
        column(&listed[1], "sym"),
        Some("_ZNK3VecplERKS_"),
        "{}",
        listed[1]
    );
    assert_eq!(
        column(&listed[48], "sym"),
        Some("_Z8shift_inRiRK3Vec"),
        "the last row is not the last symbol: {}",
        listed[48]
    );
}

/// A Windows image with no symbol table names no functions, and that is a row rather than a silence -
/// the export table is a different window and is not quietly counted twice here.
#[test]
fn an_image_with_no_symbol_table_answers_with_zero_functions_rather_than_nothing() {
    for file in ["exp.dll", "lab.dll", "reloc.dll"] {
        let listed = rows(file);
        assert_eq!(
            listed[0],
            "functions\ttotal\t0\tsized\t0\tdemangled\t0\tfrom\tsymtabs",
            "{file} named functions the table does not hold: {listed:#?}"
        );
        assert_eq!(listed.len(), 1, "{file} listed more than its totals");
    }
}

/// A COFF object is the case this window does not claim: `llvm-readobj --symbols` names `answer` and
/// `helper` in `.text`, but a COFF symbol carries no length, so anything printed as a size here would be
/// invented. The assertion is that no row states a size, whichever way the crate's own kind mapping goes.
#[test]
fn a_coff_object_states_no_size_because_its_symbols_carry_none() {
    let listed = rows("answer.obj");
    for row in listed.iter().skip(1) {
        assert_eq!(column(row, "size"), Some("-"), "{row}");
    }
    assert_eq!(
        column(&listed[0], "sized"),
        Some("0"),
        "the totals row claims a size nothing wrote: {}",
        listed[0]
    );
    let named: Vec<&str> = listed
        .iter()
        .skip(1)
        .filter_map(|row| column(row, "sym"))
        .collect();
    for one in &named {
        assert!(
            matches!(*one, "answer" | "helper" | "_answer" | "_helper"),
            "{one} is not a symbol llvm-readobj lists for this object"
        );
    }
}
