//! The Mach-O windows, checked against what the file states and what two readers print beside it.
//!
//! `test/fixtures/macho.probe.json` comes from `scripts/make-macho-fixtures.py`, which writes three
//! objects with `clang -c` and links a fourth file with `ld64.lld`, then reads all four with
//! `llvm-readobj --file-headers / --macho-segment / --relocs / --macho-dysymtab` and with
//! `llvm-objdump -h / -r` and `llvm-nm -m`. A row is in the probe only where the byte walk and those
//! listings said the same thing.
//!
//! Three claims are worth the fixtures, and each is one the reader could get wrong in silence:
//!
//! - the colour a section earns comes from `S_ATTR_PURE_INSTRUCTIONS` and `S_ATTR_DEBUG` in its own
//!   attribute word, and `llvm-objdump -h` answers `TEXT` for exactly those sections;
//! - a symbol's `n_sect` counts from one, so the section it names is the one the file's section list
//!   calls `n_sect - 1` - one off, and every name in the file would sit in its neighbour;
//! - a relocation's eight bytes split as 24/1/2/1/3 bits, which is what makes `X86_64_RELOC_BRANCH`
//!   the number 2 rather than the 3 the older header says: only the numbers two readers printed
//!   beside the same record are named here.

use apk_lens_analysis::{analyse, region_at, region_count, reloc_at, reloc_count};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");
const NAMES: [&str; 4] = ["macho64.o", "macho-arm.o", "macho32.o", "macho.mh"];

fn text(name: &str) -> String {
    let path = format!("{FIXTURES}{name}");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run scripts/make-macho-fixtures.py to write it: {error}")
    })
}

/// The probe's rows for one fixture, without a JSON parser: one row per line inside `"rows": [ ... ]`,
/// and the only escape those lines carry is the `\t` between columns.
fn probe_rows(file: &str) -> Vec<String> {
    let body = text("macho.probe.json");
    let head = body
        .find(&format!("\"{file}\": {{"))
        .unwrap_or_else(|| panic!("{file} is not in the probe"));
    let start = body[head..]
        .find("\"rows\": [")
        .unwrap_or_else(|| panic!("{file} has no rows list"));
    let tail = &body[head + start + "\"rows\": [".len()..];
    if tail.starts_with(']') {
        return Vec::new();
    }
    let end = tail
        .find("\n  ]")
        .unwrap_or_else(|| panic!("{file}'s rows list never closes"));
    tail[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_suffix(',').unwrap_or(line);
            let line = line.strip_prefix('"')?;
            let line = line.strip_suffix('"')?;
            Some(line.replace("\\t", "\t"))
        })
        .collect()
}

/// Read one file through the module and hand back two windows: the colour map and the relocations.
fn opened(name: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let bytes = fs::read(format!("{FIXTURES}{name}"))
        .unwrap_or_else(|error| panic!("{name} missing, run scripts/make-macho-fixtures.py: {error}"));
    let listed = analyse(&bytes).unwrap_or_else(|| panic!("{name} has to be an object file"));
    let taken = |count: i32, at: extern "C" fn(i32, *mut u8, i32) -> i32| -> Vec<String> {
        (0..count)
            .map(|index| {
                let mut slot = vec![0u8; 4096];
                let written = at(index, slot.as_mut_ptr(), slot.len() as i32);
                assert!(written > 0 && written < slot.len() as i32, "{name} row {index}");
                slot.truncate(written as usize);
                String::from_utf8(slot).expect("a row is text")
            })
            .collect()
    };
    (
        listed,
        taken(region_count(), region_at),
        taken(reloc_count(), reloc_at),
    )
}

fn cell(row: &str, key: &str) -> Option<String> {
    let parts: Vec<&str> = row.split('\t').collect();
    parts.iter().position(|one| *one == key).map(|at| parts[at + 1].to_owned())
}

fn number(row: &str, key: &str) -> u64 {
    cell(row, key)
        .unwrap_or_else(|| panic!("{row} has no {key}"))
        .parse()
        .expect("a number")
}

#[test]
fn a_section_earns_its_colour_from_its_own_attribute_word() {
    for name in NAMES {
        let (listed, regions, _) = opened(name);
        let _ = &listed;
        let wanted = probe_rows(name);
        let claim = |one: &str| {
            let start = number(one, "off").to_string();
            let size = number(one, "size").to_string();
            regions
                .iter()
                .filter(|row| row.starts_with("region\t"))
                .filter(|row| {
                    let parts: Vec<&str> = row.split('\t').collect();
                    parts[1] == start && parts[2] == size
                })
                .map(|row| row.to_owned())
                .collect::<Vec<String>>()
        };
        for row in wanted.iter().filter(|row| row.starts_with("sect\t")) {
            let place = row.split('\t').nth(2).expect("a section name").to_owned();
            let found = claim(row);
            if cell(row, "disk").as_deref() == Some("no") {
                assert!(
                    found.is_empty(),
                    "{name}: {place} has no bytes in the file, yet the map drew it"
                );
                continue;
            }
            let kind = cell(row, "kind").expect("a kind");
            assert_eq!(
                found.len(),
                1,
                "{name}: {place} should be drawn once at its own bytes, found {}",
                found.len()
            );
            let drawn = &found[0];
            let parts: Vec<&str> = drawn.split('\t').collect();
            assert_eq!(parts[3], kind, "{name}: {place} is coloured {kind}");
            assert_eq!(parts[4], place, "{name}: {place} is named by the map");
        }
        let head = &regions[0];
        assert!(head.starts_with("regions\t"), "{name}: row zero counts the map");
        let (file, claimed, unloaded, idle) = (
            number(head, "file"),
            number(head, "claimed"),
            number(head, "unloaded"),
            number(head, "loaded-unaddressed"),
        );
        assert_eq!(file, fs::metadata(format!("{FIXTURES}{name}")).unwrap().len(), "{name}");
        assert_eq!(claimed + unloaded + idle, file, "{name}: the map does not tile the file");
    }
}

#[test]
fn a_symbols_section_number_counts_from_one() {
    for name in NAMES {
        let (listed, _, _) = opened(name);
        for row in probe_rows(name).iter().filter(|row| row.starts_with("sym\t")) {
            let index = row.split('\t').nth(1).expect("a symbol index");
            let mine = listed
                .iter()
                .find(|one| one.starts_with(&format!("symbol\t{index}\t")))
                .unwrap_or_else(|| panic!("{name}: no row for symbol {index}"));
            assert_eq!(
                cell(mine, "addr").as_deref(),
                cell(row, "addr").as_deref(),
                "{name}: symbol {index} stands where the file says"
            );
            let wanted = cell(row, "sect").expect("a section");
            let got = cell(mine, "section").expect("a section column");
            assert_eq!(got, if wanted == "-" { "-" } else { &wanted }, "{name}: symbol {index}");
            assert_eq!(
                cell(row, "n_sect").as_deref().map(|one| one.to_owned()),
                Some(if wanted == "-" { "0".to_owned() } else { (wanted.parse::<u64>().unwrap() + 1).to_string() }),
                "{name}: symbol {index} is one past the section the file lists"
            );
        }
    }
}

#[test]
fn the_relocations_two_readers_name_are_the_ones_the_file_holds() {
    for name in NAMES {
        let (_, _, mine) = opened(name);
        let wanted: Vec<String> = probe_rows(name)
            .into_iter()
            .filter(|row| {
                row.starts_with("relocs\t") || row.starts_with("table\t") || row.starts_with("fixup\t")
            })
            .collect();
        if mine.is_empty() {
            assert!(wanted.is_empty(), "{name}: the probe lists relocations this reader missed");
            continue;
        }
        assert_eq!(cell(&mine[0], "kind").as_deref(), Some("sect"), "{name}: a Mach-O list");
        if mine.len() != wanted.len() {
            panic!("{name}: the probe lists {} rows, this reader {}", wanted.len(), mine.len());
        }
        for (index, (one, two)) in mine.iter().zip(&wanted).enumerate() {
            if one != two {
                panic!("{name} row {index}: the readers said {two:?}, this reader says {one:?}");
            }
        }
    }
}

#[test]
fn a_linked_image_has_a_map_and_nothing_to_apply() {
    let (_, regions, relocs) = opened("macho.mh");
    assert!(regions.len() > 2, "an image still has a map");
    let head = &relocs[0];
    assert_eq!(cell(head, "entries").as_deref(), Some("0"), "{head}");
    assert_eq!(cell(head, "tables").as_deref(), Some("0"), "{head}");
    assert_eq!(relocs.len(), 1, "a linked file states no relocation record: {relocs:?}");
    let code = regions
        .iter()
        .filter(|row| row.starts_with("region\t") && row.contains("\tcode\t"))
        .count();
    assert_eq!(code, 1, "one section of the image is instructions");
}

#[test]
fn a_file_that_is_not_mach_o_leaves_the_window_alone() {
    for name in ["answer.obj", "lab.so"] {
        let bytes = fs::read(format!("{FIXTURES}{name}"))
            .unwrap_or_else(|error| panic!("{name} missing: {error}"));
        assert!(analyse(&bytes).is_some(), "{name} is an object file");
        let count = reloc_count();
        let rows: Vec<String> = (0..count)
            .map(|index| {
                let mut slot = vec![0u8; 4096];
                let written = reloc_at(index, slot.as_mut_ptr(), slot.len() as i32);
                if written < 0 {
                    return String::new();
                }
                slot.truncate(written as usize);
                String::from_utf8_lossy(&slot[..]).into_owned()
            })
            .collect();
        assert!(
            !rows.iter().any(|row| row.contains("\tsect\t")),
            "{name} answered as if it were Mach-O: {:?}",
            rows.first()
        );
    }
}
