//! The analysis module's own report, over a binary built in this file and over whatever the CI
//! machine happens to have installed.
//!
//! `sample_elf()` is an ELF64 object assembled here, byte by byte, so the expected rows do not depend
//! on a compiler being present. `/bin/ls` is the opposite: a real distribution binary that the module
//! has never seen, read only where it exists (the CI runner), and asserted loosely enough to survive
//! a different distro - the shape of the report, not its section names.

use apk_lens_analysis::{abi_version, analyse, sample_elf, self_test};

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
}
