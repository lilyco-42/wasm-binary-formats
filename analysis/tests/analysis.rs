//! The analysis module's own report, over a binary built in this file and over whatever the CI
//! machine happens to have installed.
//!
//! `sample_elf()` is an ELF64 object assembled here, byte by byte, so the expected rows do not depend
//! on a compiler being present. `/bin/ls` is the opposite: a real distribution binary that the module
//! has never seen, read only where it exists (the CI runner), and asserted loosely enough to survive
//! a different distro - the shape of the report, not its section names. In between sits
//! `test/fixtures/answer.obj`, a real compiler's output that is committed, so the address-to-name
//! index is checked against a file whose objdump listing is frozen in this repo.

use apk_lens_analysis::{abi_version, analyse, name_for, names_len, sample_elf, self_test};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| panic!("{path} missing: {error}"))
}

fn rows(bytes: &[u8]) -> Vec<String> {
    analyse(bytes).expect("the input is an object file")
}

#[test]
fn the_stub_elf_reports_its_own_section_table() {
    let lines = rows(&sample_elf());
    assert_eq!(
        lines[0],
        "file\telf\tbits\t64\tendian\tlittle\tkind\tdynamic\tmachine\tx86_64\tsections\t2\tsymbols\t0\tdynsym\t0\tentry\t0",
        "the counts in the header row have to be the counts the rows below carry"
    );
    assert_eq!(
        lines[1],
        "section\t0\t\taddr\t0\toff\t0\tsize\t0\tdisk\t0\talign\t0"
    );
    assert_eq!(
        lines[2], "section\t1\t.text\taddr\t0\toff\t192\tsize\t7\tdisk\t7\talign\t1",
        "the string table names itself, and the name it holds is `.text`"
    );
    assert_eq!(lines.len(), 3);
}

#[test]
fn self_test_answers_with_the_same_number_the_host_report_has() {
    assert_eq!(self_test(), rows(&sample_elf()).len() as i32);
    assert_eq!(abi_version(), 1);
}

#[test]
fn bytes_that_are_not_an_object_file_are_refused_rather_than_guessed() {
    assert!(analyse(b"not a binary, not even close").is_none());
    assert!(
        analyse(&[0x7F, b'E', b'L', b'F']).is_none(),
        "a truncated magic"
    );
    let mut broken = sample_elf();
    broken[60] = 9;
    broken[61] = 9;
    assert!(
        analyse(&broken).map_or(true, |lines| lines[0].contains("sections\t")),
        "a header that promises nine sections either answers or refuses, and never panics"
    );
}

#[test]
fn a_distribution_binary_comes_through_the_same_abi() {
    let Ok(bytes) = std::fs::read("/bin/ls") else {
        eprintln!("skip: no /bin/ls here, so only CI runs this");
        return;
    };
    let lines = rows(&bytes);
    assert!(lines[0].starts_with("file\t"), "{:?}", lines[0]);
    assert!(
        lines[0].contains("\tsections\t") || lines[0].contains("\tsymbols\t"),
        "{:?}",
        lines[0]
    );
    let listed = lines
        .iter()
        .filter(|line| line.starts_with("section\t"))
        .count();
    assert!(
        listed > 1,
        "a real binary has more than one section: {listed}"
    );
    // A distribution binary is stripped: what it still carries is the dynamic table.
    assert!(
        lines.iter().any(|line| line.starts_with("dynsym\t")),
        "no dynamic symbols in a dynamically linked /bin/ls"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("dynsym\t") && line.contains("\taddr\t")),
        "a dynamic symbol row has no address column"
    );
    let declared: usize = lines[0]
        .split('\t')
        .skip_while(|field| *field != "dynsym")
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    assert!(declared >= 1, "the header row undercounts: {}", lines[0]);
    // The same table read through the other direction: every listed symbol that the file says lives
    // in a section has to answer for its own address. Skipping this is what would let the index be
    // quietly empty for a real distribution binary.
    let mut addressable = 0usize;
    for line in &lines {
        let cells: Vec<&str> = line.split('\t').collect();
        if cells[0] != "symbol" && cells[0] != "dynsym" {
            continue;
        }
        let column = |wanted: &str| {
            cells
                .iter()
                .position(|field| *field == wanted)
                .and_then(|at| cells.get(at + 1))
                .copied()
        };
        if cells[2].is_empty() || column("section") == Some("-") {
            continue;
        }
        if matches!(column("kind"), Some("section") | Some("file")) {
            continue;
        }
        let Some(Ok(at)) = column("addr").map(str::parse::<u64>) else {
            continue;
        };
        addressable += 1;
        assert!(
            name_for(at).is_some(),
            "{} lives in a section at {at:#x} and answered with nothing",
            cells[2]
        );
    }
    assert!(addressable > 0, "no addressable symbol in {lines:#?}");
}

#[test]
fn an_address_answers_with_the_name_objdump_prints_beside_the_instruction() {
    // `answer.obj` is the `clang -c` object the base module's COFF reader was proved against, so the
    // two names below and the offsets between them are not this crate's invention: objdump's `-t`
    // listing and `-d` annotations are frozen in test/fixtures/coff.probe.json, which says
    // `answer` at 0, `helper` at 16, and prints `call 19 <helper+0x9>` for the call site.
    let lines = rows(&fixture("answer.obj"));
    assert!(
        lines[0].contains("kind\trelocatable"),
        "an object is not a rejected input, it is a file with sections: {}",
        lines[0]
    );
    assert_eq!(
        names_len(),
        2,
        "eleven symbols are listed and two of them own an address: {lines:#?}"
    );
    assert_eq!(name_for(0).as_deref(), Some("answer"));
    assert_eq!(name_for(5).as_deref(), Some("answer+0x5"));
    assert_eq!(name_for(16).as_deref(), Some("helper"));
    assert_eq!(name_for(19).as_deref(), Some("helper+0x9"));

    // The exclusions, each of which the rows carry and the index does not: `.text` is a section symbol
    // at the very address `answer` owns, `@feat.00` is clang's absolute feature word (no section), and
    // the file symbol names the compilation unit (no section either). All three report address 0, so
    // `name_for(0) == "answer"` above is what says none of them got indexed.
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("symbol\t0\t.text") && line.contains("kind\tsection")),
        "no section symbol to exclude: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("@feat.00") && line.contains("section\t-")),
        "@feat.00 should still be listed, and still have no section: {lines:#?}"
    );
}

#[test]
fn a_file_with_no_symbol_table_leaves_the_index_empty() {
    assert_eq!(rows(&sample_elf()).len(), 3);
    assert_eq!(names_len(), 0);
    assert_eq!(name_for(0), None);
    assert_eq!(name_for(u64::MAX), None, "nothing is below nothing");

    // And a refusal clears what the previous file left standing, on this thread at least.
    rows(&fixture("answer.obj"));
    assert_eq!(names_len(), 2);
    assert!(analyse(b"plain text, not a binary").is_none());
    assert_eq!(
        names_len(),
        0,
        "a rejected file must not keep the last names"
    );
}
