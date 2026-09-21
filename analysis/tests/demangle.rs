//! The C++ names one compiler wrote, answered as two demanglers agree they read.
//!
//! `test/fixtures/cxx.o` is `clang++` for `x86_64-unknown-linux-gnu`, and its symbol names are the
//! compiler's own spelling - nothing here is a hand-typed `_Z` string.
//! `scripts/make-demangle-fixtures.py` read those names out of the object with `llvm-readobj
//! --symbols`, then asked binutils' `c++filt` and LLVM's `llvm-cxxfilt` what each one means, and kept
//! as the claim only the names where the two answered with the same string. The full row list is in
//! `test/fixtures/demangle.probe.json` and `test/module.test.mjs` compares the shipped module against
//! every line of it; what is pinned here is the part that would be easy to get quietly wrong.

use apk_lens_analysis::{
    analyse, demangle_at, demangle_count, demangle_name, export_count, names_len,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| panic!("{path} missing: {error}"))
}

fn report() -> Vec<String> {
    let total = demangle_count();
    assert!(total > 0, "the object has to answer with something");
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = demangle_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(
                written > 0 && written < slot.len() as i32,
                "row {index} did not fit"
            );
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

fn row_of(want: &str) -> String {
    let rows = report();
    rows.into_iter()
        .find(|row| row.split('\t').nth(3) == Some(want))
        .unwrap_or_else(|| panic!("no row for {want}"))
}

#[test]
fn the_totals_line_counts_what_the_object_holds_not_what_the_reader_guessed() {
    analyse(&fixture("cxx.o")).expect("the fixture is an object file");
    assert_eq!(
        report()[0],
        "demangle\tmangled\t20\tdemangled\t19\trefused\t1\twitnesses\ttwo",
        "twenty `_Z` names, one answer the two demanglers do not share"
    );
}

#[test]
fn a_constructor_and_a_destructor_keep_the_class_name_and_alias_each_other() {
    analyse(&fixture("cxx.o")).expect("the fixture is an object file");
    // `C1` and `C2` are the complete-object and base-object constructor variants, `D1` and `D2` the
    // destructor's, and every one of them demangles to the same string. So the raw name has to stay in
    // the row: a listing of demangled forms alone cannot tell four symbols from two.
    assert_eq!(
        row_of("_ZN3FooC1Ev"),
        "sym\t18\tin\t_ZN3FooC1Ev\tout\tFoo::Foo()"
    );
    assert_eq!(
        row_of("_ZN3FooC2Ev"),
        "sym\t1\tin\t_ZN3FooC2Ev\tout\tFoo::Foo()"
    );
    assert_eq!(
        row_of("_ZN3FooD1Ev"),
        "sym\t19\tin\t_ZN3FooD1Ev\tout\tFoo::~Foo()"
    );
    let same = report()
        .iter()
        .filter(|row| row.ends_with("\tout\tFoo::Foo()"))
        .count();
    assert_eq!(same, 2, "two symbols, one demangled name");
}

#[test]
fn a_qualifier_and_a_return_type_go_where_the_witnesses_put_them() {
    analyse(&fixture("cxx.o")).expect("the fixture is an object file");
    // `const` after the parameter list is what both demanglers print for `NK`, and the array under a
    // reference keeps its brackets outside the declarator - `int (&) [5]`, not `int [5]&`.
    assert_eq!(
        row_of("_ZNK3Foo4readEv"),
        "sym\t3\tin\t_ZNK3Foo4readEv\tout\tFoo::read() const"
    );
    assert_eq!(
        row_of("_ZN3Foo6matrixERA5_i"),
        "sym\t6\tin\t_ZN3Foo6matrixERA5_i\tout\tFoo::matrix(int (&) [5])"
    );
    // A non-template function's return type is not in its mangled name at all, so neither witness can
    // say what `retfn` returns and the row says only `retfn(int)`.
    assert_eq!(row_of("_Z5retfni"), "sym\t11\tin\t_Z5retfni\tout\tretfn(int)");
    // A template's return type *is* in the name, as `T_`, and resolves through the argument list.
    assert_eq!(
        row_of("_Z4pickIiET_S0_S0_"),
        "sym\t16\tin\t_Z4pickIiET_S0_S0_\tout\tint pick<int>(int, int)"
    );
}

#[test]
fn the_one_name_the_two_demanglers_spell_differently_is_answered_with_a_refusal() {
    analyse(&fixture("cxx.o")).expect("the fixture is an object file");
    let refused = row_of("_Z4varsPcPKwDn");
    assert_eq!(
        refused,
        "sym\t14\tin\t_Z4varsPcPKwDn\tout\t-\twhy\tnot in the two-witness subset"
    );
    // Neither spelling appears anywhere in the report, which is the point: binutils writes
    // `decltype(nullptr)` and LLVM writes `std::nullptr_t` for the same two bytes.
    let all = report().join("\n");
    assert!(!all.contains("nullptr"), "a spelling was picked anyway");
    // And the refusal is whole rather than partial: the two parameters this reader does understand are
    // not printed on their own, because a signature with one type missing would read as a fact about
    // the function that the bytes do not settle.
    assert!(!all.contains("wchar_t"), "the name was half demangled");
    assert!(demangle_name("_Z4varsPcPKwDn").is_none());
}

#[test]
fn a_name_outside_the_witnessed_subset_stops_the_walk_rather_than_guessing_on() {
    for name in [
        "",
        "answer",
        "_Z",
        // A length with no name behind it, and a name with no length in front of it.
        "_Z1",
        "_Z_",
        // An operator name: the two-char codes are a table of their own, and no name in this fixture
        // needs one, so nothing here says what `pl` should print.
        "_Z3foopl",
        // A builtin code neither witness was asked about.
        "_Z3fooq",
        // A local of a function, which carries a `$` the grammar has no place for.
        "_ZZ3foovE$FOO",
        // A nested name with nothing in it.
        "_ZNE",
        // A source name whose stated length runs off the end of the string. (`_Z9verylongn` is not a
        // refusal case: nine bytes after the 9 really are `verylongn`, and it reads as a variable.)
        "_Z20verylongn",
        // A template argument list that never closes.
        "_Z3fooIi",
        // The same name the object answers with, minus the parameter that makes it a function.
        "_ZN2ns7counter",
    ] {
        assert_eq!(
            demangle_name(name),
            None,
            "{name} was read as something"
        );
    }
}

#[test]
fn a_file_with_no_c_in_it_answers_with_no_rows_but_its_own_zero() {
    analyse(&fixture("answer.obj")).expect("the fixture is an object file");
    assert_eq!(demangle_count(), 1, "only the totals row");
    assert_eq!(
        report()[0],
        "demangle\tmangled\t0\tdemangled\t0\trefused\t0\twitnesses\ttwo"
    );
    // The same file still has symbols, and this says nothing about them: a C object's names are
    // already readable, and the export list is a different window with its own rows.
    assert!(names_len() > 0, "the address index still has the file's names");
    assert_eq!(export_count(), 0, "a COFF object exports nothing");
}

#[test]
fn rows_ask_for_names_the_symbol_table_actually_carries() {
    analyse(&fixture("cxx.o")).expect("the fixture is an object file");
    let listed: Vec<String> = report()
        .iter()
        .skip(1)
        .map(|row| row.split('\t').nth(3).unwrap_or("").to_owned())
        .collect();
    assert_eq!(listed.len(), 20, "one row per mangled name");
    assert_eq!(listed.iter().collect::<std::collections::HashSet<_>>().len(), 20);
    // Every name in the list came out of this file, so a row that invented one would be visible here.
    for name in &listed {
        assert!(
            String::from_utf8_lossy(&fixture("cxx.o")).contains(name),
            "{name} is not in the object"
        );
    }
}
