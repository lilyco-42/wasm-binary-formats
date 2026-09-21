//! The Names window: every name the file attaches to an address, taken from `nm -P` and the export
//! directory listings rather than from this reader's own output.
//!
//! `nm -P` prints `name type value size`, and the type letter is the kind the table states - `T` for text
//! and `R` for read-only data in `lab.elf`, both upper case because the symbol is global. The addresses
//! asserted below are those columns. `exp.dll` is the case a symbol table cannot show: four exported
//! names over two addresses, which is why this window does not fold a list of names into one entry per
//! address the way the address index has to.

use apk_lens_analysis::{analyse, named_at, named_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn rows(name: &str) -> Vec<String> {
    let path = format!("{FIXTURES}{name}");
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("{path} missing, see the fixture scripts named in README: {error}"));
    assert!(analyse(&bytes).is_some(), "{name} has to be an object");
    let total = named_count();
    (0..total)
        .map(|index| {
            let mut slot = vec![0u8; 4096];
            let written = named_at(index, slot.as_mut_ptr(), slot.len() as i32);
            assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
            slot.truncate(written as usize);
            String::from_utf8(slot).expect("a row is text")
        })
        .collect()
}

/// The column beside `key`, read from the second cell onward: these rows are tagged `name`, so searching
/// the whole row would answer every lookup of `name` with the address in cell one.
fn column(row: &str, key: &str) -> Option<String> {
    let cell: Vec<&str> = row.split('\t').collect();
    let at = cell.iter().skip(1).position(|one| *one == key)?;
    let value = *cell.get(at + 2)?;
    Some(value.to_owned())
}

fn find<'a>(listed: &'a [String], named: &str) -> &'a String {
    listed
        .iter()
        .find(|row| column(row, "name").as_deref() == Some(named))
        .unwrap_or_else(|| panic!("no row names {named} in {listed:#?}"))
}

/// nm's three symbols, in address order, each with the kind nm's own type letter states.
#[test]
fn a_programs_names_are_the_ones_its_table_lists() {
    let listed = rows("lab.elf");
    assert_eq!(
        listed,
        vec![
            "names\ttotal\t3\taddresses\t3\tdemangled\t0",
            "name\t0x200120\tfrom\tsymtab\tkind\tdata\tname\tmsg\tread\t-",
            "name\t0x200150\tfrom\tsymtab\tkind\tdata\tname\tnote\tread\t-",
            "name\t0x201190\tfrom\tsymtab\tkind\ttext\tname\tentry\tread\t-",
        ],
        "the window drifted away from nm -P"
    );
}

/// Four exported names, two addresses. `alias` and `answer` name the body `shipped` was ordered to
/// publish, so a list that keyed on the address would show one of three and call it complete; the totals
/// row says both numbers, and they are not the same number.
#[test]
fn names_that_share_an_address_stay_three_rows_because_the_file_lists_three() {
    let listed = rows("exp.dll");
    assert_eq!(column(&listed[0], "total"), Some("4".to_owned()), "{}", listed[0]);
    assert_eq!(column(&listed[0], "addresses"), Some("2".to_owned()), "{}", listed[0]);
    let shared: Vec<&String> = listed
        .iter()
        .skip(1)
        .filter(|row| column(row, "kind").as_deref() == Some("-"))
        .collect();
    assert_eq!(shared.len(), 4, "a name from a table other than the export list: {listed:#?}");
    for named in ["alias", "answer", "shipped"] {
        let row = find(&listed, named);
        assert_eq!(column(row, "from").as_deref(), Some("export"), "{row}");
        assert_eq!(column(row, "kind").as_deref(), Some("-"), "{row}");
    }
    let at_first: Vec<&String> = listed
        .iter()
        .skip(1)
        .filter(|row| row.starts_with("name\t0x180001000\t"))
        .collect();
    let mut names: Vec<String> = at_first.iter().filter_map(|row| column(row, "name")).collect();
    names.sort();
    assert_eq!(names, vec!["alias", "answer", "shipped"], "{listed:#?}");
    assert_eq!(
        find(&listed, "helper"),
        &"name\t0x180001010\tfrom\texport\tkind\t-\tname\thelper\tread\t-".to_owned()
    );
}

/// A COFF object's `nm -P` says `answer T 0` and `helper T 10`, and a section symbol is a name with an
/// address of its own - the kind the table gives it is printed beside it rather than dropped, because
/// that is what the file says.
#[test]
fn an_objects_window_keeps_section_names_and_states_their_kind() {
    let listed = rows("answer.obj");
    assert!(listed.len() > 3, "{listed:#?}");
    for named in ["answer", "helper"] {
        let row = find(&listed, named);
        assert_eq!(column(row, "kind").as_deref(), Some("text"), "{row}");
        assert_eq!(column(row, "from").as_deref(), Some("symtab"), "{row}");
    }
    assert_eq!(
        column(find(&listed, "answer"), "name").as_deref(),
        Some("answer")
    );
    let offsets: Vec<String> = ["answer", "helper"]
        .iter()
        .map(|named| column(find(&listed, named), "name").unwrap_or_default())
        .collect();
    assert_eq!(offsets, vec!["answer", "helper"], "the names moved");
    assert_eq!(
        find(&listed, "helper"),
        &"name\t0x10\tfrom\tsymtab\tkind\ttext\tname\thelper\tread\t-".to_owned()
    );
}

/// The C++ objects are the reason a row carries two spellings: `nm` prints `_ZN3Foo3setEPdRKc` and the
/// window's `read` column is what two demanglers agree it means, while a name no demangler reads stays in
/// the list with `-` rather than being left out.
#[test]
fn a_mangled_name_is_listed_with_its_reading_beside_it() {
    let listed = rows("cxx.o");
    assert_eq!(column(&listed[0], "total"), Some("21".to_owned()), "{}", listed[0]);
    assert_eq!(column(&listed[0], "demangled"), Some("20".to_owned()), "{}", listed[0]);
    // 21 names over 17 addresses, because `C1`/`C2` and `D1`/`D2` are four symbols at two
    // addresses and `ns::counter` is a data object rather than a function - the row that carries it
    // says `kind data`, which is the demangler panel not being able to say it.
    assert_eq!(column(&listed[0], "addresses"), Some("17".to_owned()), "{}", listed[0]);
    let row = find(&listed, "_ZN3Foo3setEPdRKc");
    assert_eq!(column(row, "read").as_deref(), Some("Foo::set(double*, char const&)"), "{row}");
    assert_eq!(column(row, "kind").as_deref(), Some("text"), "{row}");
    let refused = find(&listed, "_Z4varsPcPKwDn");
    assert_eq!(column(refused, "read").as_deref(), Some("-"), "{refused}");
    assert!(
        listed.iter().skip(1).count() <= 64,
        "the list went past the cap without a cut row"
    );
}
