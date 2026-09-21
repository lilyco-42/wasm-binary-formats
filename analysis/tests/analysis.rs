//! The analysis module's own report, over a binary built in this file and over whatever the CI
//! machine happens to have installed.
//!
//! `sample_elf()` is an ELF64 object assembled here, byte by byte, so the expected rows do not depend
//! on a compiler being present. `/bin/ls` is the opposite: a real distribution binary that the module
//! has never seen, read only where it exists (the CI runner), and asserted loosely enough to survive
//! a different distro - the shape of the report, not its section names. In between sits
//! `test/fixtures/answer.obj`, a real compiler's output that is committed, so the address-to-name
//! index is checked against a file whose objdump listing is frozen in this repo.

use apk_lens_analysis::{
    abi_version, alloc, analyse, dealloc, name_at, name_for, names_count, names_len, region_at,
    region_count, sample_elf, self_test,
};
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
    // Every *listed* symbol the file says lives in a section has to answer for its own address. The
    // listing is capped at 64 and the index is not, and on this runner that distinction is visible:
    // every dynsym row printed here is an undefined import - a linker puts those first - so this loop
    // can legitimately check nothing while the index still holds the names further down the table.
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
        assert!(
            name_for(at).is_some(),
            "{} lives in a section at {at:#x} and answered with nothing",
            cells[2]
        );
    }
    // Stripped means `.symtab` is gone, not that nothing is named: the dynamic table still defines
    // `_init`, `_fini`, `data_start` and the rest, each in a section, each therefore indexed.
    assert!(
        names_len() > 0,
        "a distribution binary with {declared} dynamic symbols named none of them"
    );
}

#[test]
fn an_address_answers_with_the_name_objdump_prints_beside_the_instruction() {
    // `answer.obj` is the `clang -c` object the base module's COFF reader was proved against, so the
    // two names below and the offsets between them are not this crate's invention: objdump's `-t`
    // listing and `-d` annotations are frozen in test/fixtures/coff.probe.json, which says `answer` at
    // 0, `helper` at 16, and prints the call as `call 19 <helper+0x9>` - and objdump writes addresses
    // in hex, so that call target is 0x19, which is 0x10 nine bytes along. Reading the `19` as
    // decimal is the one way to get this test wrong, and the pair below is written to make it obvious.
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
    assert_eq!(name_for(0x13).as_deref(), Some("helper+0x3"));
    assert_eq!(name_for(0x19).as_deref(), Some("helper+0x9"));

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
/// The byte-region map: every range the file points at, plus what lies between them.
///
/// Both images are linked by clang + lld (`scripts/make-image-fixtures.py`) and the rows below are the
/// shadow's, which the script refuses to write unless `readelf -h -l -S` and `objdump -h` agree with its
/// own reading of the same header fields. So the offsets here are the linker's, not a sketch of the
/// formats: ELF64 keeps its two-byte header tail at 54/56/58/60 because `e_flags` is four bytes wide at
/// 48, and the COFF file header has a `TimeDateStamp` before its symbol pointer.
#[test]
fn the_map_of_an_elf_names_the_header_tables_and_the_padding_between_them() {
    let bytes = fixture("lab.elf");
    assert!(!bytes.is_empty());
    assert!(analyse(&bytes).is_some(), "the analyser has to read the file first");
    let lines = regions();
    assert_eq!(
        lines[0],
        "regions\t12\tfile\t1064\tclaimed\t1046\tunloaded\t18\tloaded-unaddressed\t0",
        "{lines:#?}"
    );
    assert_eq!(lines[1], "region\t0\t64\theader\telf header\t-");
    assert_eq!(lines[2], "region\t64\t224\ttables\tprogram headers\t-");
    assert_eq!(
        lines[3],
        "region\t288\t44\trodata\t.rodata\tloaded at 0x200120",
        "the section name comes out of the file's own string table"
    );
    assert_eq!(lines[4], "region\t332\t4\tgap\tunreferenced\tnot loaded");
    assert_eq!(lines[5], "region\t336\t6\tcode\t.text\tloaded at 0x201150");
    assert_eq!(
        lines[lines.len() - 1],
        "region\t616\t448\ttables\tsection headers\t-",
        "an ELF ends with its section header table, so there is nothing after it"
    );
    assert!(tiles(1064, &lines), "the map must account for every byte: {lines:#?}");
    // .comment, .symtab and both string tables are structure a tool reads, not data the program runs.
    for named in [
        "region\t342\t99\tmeta\t.comment\tnot loaded",
        "region\t448\t96\tmeta\t.symtab\tnot loaded",
        "region\t594\t15\tmeta\t.strtab\tnot loaded",
    ] {
        assert!(lines.contains(&named.to_string()), "missing {named}");
    }
}

#[test]
fn a_pe_section_claims_only_the_bytes_it_says_it_uses_and_the_rest_is_padding() {
    let bytes = fixture("lab.exe");
    assert!(analyse(&bytes).is_some());
    let lines = regions();
    assert_eq!(
        lines[0],
        "regions\t9\tfile\t3072\tclaimed\t1199\tunloaded\t1873\tloaded-unaddressed\t0",
        "{lines:#?}"
    );
    assert_eq!(
        lines[1],
        "region\t0\t1024\theader\tms-dos stub and nt headers\t-"
    );
    // SizeOfRawData is 512 for a section whose virtual size is 6: the 506 bytes after it are file
    // alignment, and calling them `.text` would colour 500-odd bytes as code that nothing reads.
    assert_eq!(
        lines[2],
        "region\t1024\t6\tcode\t.text\tvaddr 0x1000, raw 0x200 in file"
    );
    assert_eq!(lines[3], "region\t1030\t506\tgap\tunreferenced\tnot loaded");
    assert_eq!(
        lines[lines.len() - 1],
        "region\t2596\t476\toverlay\tafter the last table\tnot loaded",
        "what sits behind the last table is an overlay, and this file's is not a signature"
    );
    assert!(tiles(3072, &lines), "the map must account for every byte: {lines:#?}");
    assert!(
        !lines.iter().any(|row| row.contains("\tcert\t")),
        "an unsigned file must not be shown as signed: {lines:#?}"
    );
}

#[test]
fn a_object_file_and_a_lie_about_a_table_both_leave_a_map_the_page_can_still_paint() {
    // A COFF object is neither of the two image formats whose header tables this map walks, so it gets no
    // map - which the page shows as "no map" rather than as one big unclaimed range.
    let bytes = fixture("answer.obj");
    assert!(analyse(&bytes).is_some());
    assert_eq!(regions().len(), 0, "an object file has no segment map to draw");

    // A section-header count that cannot be true is clipped to the file and says so, rather than leaving
    // the map with a range running off the end - and the entries themselves stop being read at the first
    // one that is not there, so a truncated table still shows the header, the segments and the real
    // sections. That is what makes the tiling hold for a file that lies about its own size.
    let mut lies = fixture("lab.elf");
    lies[60] = 0xff;
    lies[61] = 0xff;
    assert!(analyse(&lies).is_some());
    let lines = regions();
    assert!(tiles(1064, &lines), "a lying count must not break the tiling: {lines:#?}");
    assert!(
        lines
            .iter()
            .any(|row| row.starts_with("region\t616\t448\ttables\tsection headers\tbeyond end of file")),
        "the table claim should have been clipped to the file: {lines:#?}"
    );
}

/// The map's rows, read through the same C ABI the page uses.
fn regions() -> Vec<String> {
    let cap = 4096;
    let count = region_count();
    assert!(count <= 1 + 256, "the row list is capped, and said so: {count}");
    (0..count)
        .map(|index| {
            let pointer = alloc(cap);
            let written = region_at(index, pointer, cap).max(0) as usize;
            let keep = written.min(cap as usize);
            let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, keep) }.to_vec();
            dealloc(pointer, cap);
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .collect()
}

/// Every range starts where the previous one ended, and the last one ends on the file's last byte. That
/// is the whole promise a colour map makes, and the only one worth asserting without reading the file.
fn tiles(total: u64, lines: &[String]) -> bool {
    let mut cursor = 0u64;
    for line in lines.iter().skip(1) {
        let field: Vec<&str> = line.split('\t').collect();
        if field.first().map(|head| *head != "region").unwrap_or(true) {
            return false;
        }
        let start: u64 = match field.get(1).and_then(|each| each.parse().ok()) {
            Some(value) => value,
            None => return false,
        };
        let length: u64 = match field.get(2).and_then(|each| each.parse().ok()) {
            Some(value) => value,
            None => return false,
        };
        if start != cursor || length == 0 {
            return false;
        }
        cursor = start + length;
    }
    cursor == total
}
