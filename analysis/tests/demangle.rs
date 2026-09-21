//! The C++ names two compilers' worth of symbols, answered as two demanglers agree they read.
//!
//! `test/fixtures/cxx.o` and `test/fixtures/ops.o` are `clang++` for `x86_64-unknown-linux-gnu`: every
//! `_Z` name in them is the compiler's own spelling, and nothing in this file is a mangled name typed by
//! hand. `scripts/make-demangle-fixtures.py` read those names out of each object with
//! `llvm-readobj --symbols` and asked binutils' `c++filt` and LLVM's `llvm-cxxfilt` what each means,
//! keeping as a claim only the names where the two wrote the same string. The rows compared below are
//! therefore read out of the probe rather than transcribed, so a fixture that changes cannot leave a
//! passing test behind that describes the old bytes.
//!
//! What is not claimed: an operator code the witnesses were never shown, a builtin code outside the one
//! they both read, a non-type template argument, and `Dn` - the name where the two demanglers part
//! company over how to spell `nullptr`. Those answer with a refusal, which is a true thing to say about
//! a symbol table.

use apk_lens_analysis::{
    analyse, demangle_at, demangle_count, demangle_name, export_count, names_len,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| panic!("{path} missing: {error}"))
}

fn text(name: &str) -> String {
    String::from_utf8(fixture(name)).expect("the probe is text")
}

/// One row out of a `key: value` pair in the probe, as a plain string.
fn scalar(file: &str, key: &str) -> String {
    let body = text("demangle.probe.json");
    let head = body
        .find(&format!("\"{file}\": {{"))
        .unwrap_or_else(|| panic!("{file} is not in the probe"));
    let marker = format!("\"{key}\": ");
    let at = body[head..]
        .find(&marker)
        .unwrap_or_else(|| panic!("{key} is not in {file}'s part of the probe"));
    let rest = &body[head + at + marker.len()..];
    let end = rest.find([',', '\n', ' '].as_ref()).unwrap_or(0);
    rest[..end].trim_matches('"').to_owned()
}

/// The probe's rows for one fixture, without a JSON parser: the script writes one row per line inside
/// `"rows": [ ... ]`, and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("demangle.probe.json");
    let head = body
        .find(&format!("\"{file}\": {{"))
        .unwrap_or_else(|| panic!("{file} is not in the probe"));
    let open = "\"rows\": [";
    let start = body[head..]
        .find(open)
        .unwrap_or_else(|| panic!("{file} has no rows list"));
    let tail = &body[head + start + open.len()..];
    let end = tail
        .find("\n  ]")
        .unwrap_or_else(|| panic!("{file}'s rows list never closes"));
    tail[..end]
        .lines()
        .filter_map(|line| {
            // One row per line, each in quotes, with a comma after all but the last. Only the trailing
            // comma is taken off, so a row whose own text ended in one cannot be shortened by mistake.
            let line = line.trim();
            let line = line.strip_suffix(',').unwrap_or(line);
            let line = line.strip_prefix('"')?;
            let line = line.strip_suffix('"')?;
            Some(line.replace("\\t", "\t"))
        })
        .collect()
}

fn rows_for(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert!(
        analyse(&bytes).is_some(),
        "{file} has to be an object file"
    );
    let total = demangle_count();
    assert!(total > 0, "{file} answered with no rows at all");
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = demangle_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

#[test]
fn every_row_the_reader_prints_is_the_row_the_two_demanglers_wrote() {
    for file in ["cxx.o", "ops.o"] {
        let want = probe_rows(file);
        assert!(want.len() > 20, "{file}: the probe holds {}", want.len());
        assert_eq!(
            scalar(file, "bytes").parse::<usize>().unwrap(),
            fixture(file).len(),
            "{file} is not the object the probe was read out of"
        );
        assert_eq!(rows_for(file), want, "{file}: a row moved");
    }
}

#[test]
fn a_constructor_and_a_destructor_alias_each_other_so_the_raw_name_stays_in_the_row() {
    rows_for("cxx.o");
    // `C1`/`C2` are the complete-object and base-object constructors and `D1`/`D2` the destructor's, and
    // all four demangle to the class name. A listing of demangled forms alone could not tell the
    // symbols apart, which is why each row carries the spelling the file used.
    let listed = rows_for("cxx.o");
    assert_eq!(
        listed
            .iter()
            .filter(|row| row.ends_with("\tout\tFoo::Foo()"))
            .count(),
        2,
        "two constructors, one spelling"
    );
    assert_eq!(
        listed
            .iter()
            .filter(|row| row.ends_with("\tout\tFoo::~Foo()"))
            .count(),
        2,
        "two destructors, one spelling"
    );
}

#[test]
fn a_substitution_names_the_whole_reference_not_the_type_inside_it() {
    rows_for("cxx.o");
    assert_eq!(
        demangle_name("_Z7one_refRiS_").as_deref(),
        Some("one_ref(int&, int&)"),
        "`S_` is the reference that completed first, not `int`"
    );
    // The same rule two candidates deeper, which is what a free binary operator leaves behind: the class
    // name, then the qualified type, then the reference, and `S1_` is the last of those.
    assert_eq!(
        demangle_name("_ZmiRK3VecS1_").as_deref(),
        Some("operator-(Vec const&, Vec const&)")
    );
}

#[test]
fn a_qualifier_a_return_type_and_an_array_go_where_the_witnesses_put_them() {
    rows_for("cxx.o");
    // `const` after the parameter list is what both demanglers print for the `K` that follows the `N`.
    assert_eq!(
        demangle_name("_ZNK3Foo4readEv").as_deref(),
        Some("Foo::read() const")
    );
    // An array under a reference keeps its brackets outside the declarator: `int (&) [5]`, not `int [5]&`.
    assert_eq!(
        demangle_name("_ZN3Foo6matrixERA5_i").as_deref(),
        Some("Foo::matrix(int (&) [5])")
    );
    // A non-template function's return type is not in its mangled name at all, so neither witness - and
    // neither this reader - can say what `retfn` returns.
    assert_eq!(demangle_name("_Z5retfni").as_deref(), Some("retfn(int)"));
    // A template's return type *is* in it, as `T_`, resolved through the argument list.
    assert_eq!(
        demangle_name("_Z4pickIiET_S0_S0_").as_deref(),
        Some("int pick<int>(int, int)")
    );
}

#[test]
fn an_operator_code_is_read_as_the_string_both_demanglers_used() {
    rows_for("ops.o");
    for (name, want) in [
        ("_ZNK3VecplERKS_", "Vec::operator+(Vec const&) const"),
        ("_ZNK3VecixEi", "Vec::operator[](int) const"),
        ("_ZNK3VecclEi", "Vec::operator()(int) const"),
        ("_ZNK3VecptEv", "Vec::operator->() const"),
        ("_ZN3VecppEi", "Vec::operator++(int)"),
        ("_ZNK3VeccviEv", "Vec::operator int() const"),
        ("_ZN3VecnwEm", "Vec::operator new(unsigned long)"),
        ("_ZN3VecdaEPv", "Vec::operator delete[](void*)"),
        ("_ZN3VecdVERKS_", "Vec::operator/=(Vec const&)"),
        ("_Z8take_intOiRKd", "take_int(int&&, double const&)"),
        ("_Z4bitshstm", "bits(unsigned char, short, unsigned short, unsigned long)"),
    ] {
        assert_eq!(demangle_name(name).as_deref(), Some(want), "{name}");
    }
    // `ps` and `pl` are both a plus, one unary and one binary, and `co` is `~`: three spellings that a
    // table written from memory would get wrong and a probe cannot.
    assert_eq!(
        demangle_name("_ZNK3VecpsEv").as_deref(),
        Some("Vec::operator+() const")
    );
    assert_eq!(
        demangle_name("_ZNK3VeccoEv").as_deref(),
        Some("Vec::operator~() const")
    );
}

#[test]
fn the_one_name_the_two_demanglers_spell_differently_is_answered_with_a_refusal() {
    let listed = rows_for("cxx.o");
    let want = probe_rows("cxx.o")
        .into_iter()
        .find(|row| row.contains("_Z4varsPcPKwDn"))
        .expect("the probe carries that name");
    assert!(
        want.contains("\tout\t-\twhy\tnot in the two-witness subset"),
        "the probe stopped disagreeing: {want}"
    );
    assert!(listed.contains(&want), "the reader answered {listed:?}");
    let all = listed.join("\n");
    assert!(!all.contains("nullptr"), "a spelling was picked anyway");
    // And the refusal is whole, not partial: the two parameters this reader does understand are not
    // printed on their own, because a signature with one type missing would read as a fact about the
    // function that the bytes do not settle.
    assert!(!all.contains("wchar_t"), "the name was half demangled");
    assert!(demangle_name("_Z4varsPcPKwDn").is_none());
}

#[test]
fn a_name_outside_the_witnessed_subset_stops_the_walk_rather_than_guessing_on() {
    for name in [
        "",
        "answer",
        "_Z",
        // A length with nothing behind it, and a name with no length in front of it.
        "_Z1",
        "_Z_",
        // An operator code the fixture never held: `ls` is a shift, `ls ` doubled is not in the table,
        // and a code that is not there ends the name.
        "_Z3fooq",
        // `sS` is not a code either witness was shown, unlike `sL` (<<=) which is.
        "_ZN3VecsSERKS_",
        // A local of a function, which carries a `$` the grammar has no place for.
        "_ZZ3foovE$FOO",
        // A nested name with nothing in it.
        "_ZNE",
        // A source name whose stated length runs off the end of the string. (`_Z9verylongn` is not a
        // refusal case: nine bytes after the 9 really are `verylongn`, and it reads as a variable.)
        "_Z20verylongn",
        // A template argument list that never closes.
        "_Z3fooIi",
        // The same name the object answers with, minus the `E` that closes its nested name.
        "_ZN2ns7counter",
        // A non-type template argument, which the argument walk does not read.
        "_Z4pickLi4EEv",
        // An unresolved substitution: nothing has been recorded when it is reached.
        "_Z3fooS_",
    ] {
        assert_eq!(demangle_name(name), None, "{name} was read as something");
    }
}

#[test]
fn a_file_with_no_c_in_it_answers_with_no_rows_but_its_own_zero() {
    rows_for("answer.obj");
    assert_eq!(demangle_count(), 1, "the totals row and nothing else");
    assert_eq!(
        rows_for("answer.obj")[0],
        "demangle\tmangled\t0\tdemangled\t0\trefused\t0\twitnesses\ttwo"
    );
    // The same file still has symbols, and this says nothing about them: a C object's names are already
    // readable, and an object file hands out no exports.
    assert!(names_len() > 0, "the address index still has the file's names");
    assert_eq!(export_count(), 0, "a COFF object exports nothing");
}
