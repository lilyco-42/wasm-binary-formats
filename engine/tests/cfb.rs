//! Compound File Binary: the sector FAT, the directory it indexes, and the mini stream that lives
//! inside the root entry's own data.
//!
//! `test/fixtures/word97.doc` is written by LibreOffice from a document python-docx generated, and
//! `excel97.xls` / `wide97.xls` by xlwt, which owns its own compound-file writer
//! (`scripts/make-cfb-fixtures.py`). That script re-reads every one of them with olefile and refuses
//! to emit `cfb.probe.json` unless its walk of the bytes agrees with olefile on each stream name and
//! size - which is also how the header layout was pinned down: the word at 0x38 is `Mini Stream
//! Size`, and the DIFAT starts at 0x4C, the only offset that keeps all 109 slots in the header.
//!
//! Sector chains are linked lists, so sector numbers interleave freely; what they may not do is
//! share a sector. That is the one invariant these tests push on, and the hand-built cases below are
//! the files no writer will supply on cue. `temp/cfb-hand.py` builds the same bytes and walks them
//! with the mirror, which is where the expected rows come from.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_CFB};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");
const END: u32 = 0xFFFF_FFFE;
const FREE: u32 = 0xFFFF_FFFF;
const FATSECT: u32 = 0xFFFF_FFFD;
const SECTOR: usize = 512;

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-cfb-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert_eq!(parse(&bytes), FORMAT_CFB, "{file} is a compound file");
    assert_eq!(kind(), FORMAT_CFB, "kind() must agree with the return code");
    assert_eq!(name(), "cfb", "the reader has to name what it walked");
    report()
}

/// One 128-byte directory entry. `name` is UTF-16LE and the length counts the terminating NUL.
fn entry(entry_name: &str, kind: u8, start: u32, size: u64, child: u32) -> Vec<u8> {
    let mut raw = vec![0u8; 128];
    let encoded: Vec<u8> = entry_name
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    raw[..encoded.len()].copy_from_slice(&encoded);
    raw[64..66].copy_from_slice(&(((encoded.len() + 2) as u16).to_le_bytes()));
    raw[66] = kind;
    raw[67] = 1;
    raw[68..80].copy_from_slice(&[0xFF; 12]);
    raw[76..80].copy_from_slice(&child.to_le_bytes());
    raw[116..120].copy_from_slice(&start.to_le_bytes());
    raw[120..128].copy_from_slice(&size.to_le_bytes());
    raw
}

/// A 14-sector compound file: the FAT in sector 0, the mini FAT in 1, the directory in 2 and 3,
/// `Big` across sectors 5-12, and the root's mini stream in 13. With `broken`, `Small` is moved into
/// the regular space starting on the sector the root already owns; with `looped`, sectors 5 and 6
/// link to each other instead of to the end.
fn hand_built(broken: bool, looped: bool) -> Vec<u8> {
    let mut fat = vec![FREE; 128];
    fat[0] = FATSECT;
    fat[1] = END;
    fat[2] = 3;
    fat[3] = END;
    for sector in 5..12 {
        fat[sector] = (sector + 1) as u32;
    }
    fat[12] = END;
    fat[13] = END;
    if looped {
        fat[5] = 6;
        fat[6] = 5;
    }
    let mut mini = vec![FREE; 128];
    mini[0] = 1;
    mini[1] = END;

    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    header[24..26].copy_from_slice(&62u16.to_le_bytes());
    header[26] = 3;
    header[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
    header[30..32].copy_from_slice(&9u16.to_le_bytes());
    header[32..34].copy_from_slice(&6u16.to_le_bytes());
    header[44..48].copy_from_slice(&1u32.to_le_bytes());
    header[48..52].copy_from_slice(&2u32.to_le_bytes());
    header[56..60].copy_from_slice(&4096u32.to_le_bytes());
    header[60..64].copy_from_slice(&1u32.to_le_bytes());
    header[64..68].copy_from_slice(&1u32.to_le_bytes());
    header[68..72].copy_from_slice(&END.to_le_bytes());
    header[72..76].copy_from_slice(&0u32.to_le_bytes());
    for slot in 0..109 {
        let value = if slot == 0 { 0 } else { FREE };
        header[76 + slot * 4..80 + slot * 4].copy_from_slice(&value.to_le_bytes());
    }

    let small = if broken {
        entry("Small", 2, 13, 4096, FREE)
    } else {
        entry("Small", 2, 0, 70, FREE)
    };
    let directory = [
        entry("Root Entry", 5, 13, 128, 1),
        small,
        entry("Big", 2, 5, 4096, FREE),
        entry("\u{1}Group", 1, END, 0, 4),
        entry("Nested", 2, 2, 20, FREE),
    ]
    .concat();

    let mut out = header;
    for value in fat {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in mini {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&directory);
    // Five entries do not fill a sector, and a chain cannot be padded forward from a half sector.
    while out.len() % SECTOR != 0 {
        out.push(0);
    }
    while out.len() < SECTOR + 14 * SECTOR {
        out.extend_from_slice(&vec![0u8; SECTOR]);
    }
    out
}

#[test]
fn reads_the_word_97_storage_libreoffice_wrote() {
    let lines = rows("word97.doc");
    assert_eq!(
        lines[0],
        "cfb\t18432\tbroken\t0\tversion\t3.59\tsector\t512\tmini\t64"
    );
    assert_eq!(
        lines[1],
        "layout\tfat\t1\tdifat\t0\tdir\t2\tminifat\t1\tsectors\t35"
    );
    assert_eq!(
        lines[2],
        "root\tstart\t3\tsize\t4352\tsectors\t9\tholds\t4608\tmini\t68\tclsid\t0609020000000000C000000000000046",
        "the root entry is the mini stream: 68 mini sectors of 64 bytes, held by 9 regular ones"
    );
    assert_eq!(
        lines[3],
        "stream\t1\t.CompObj\tsize\t106\tstart\t0\twhere\tmini\tsectors\t2\tholds\t128"
    );
    assert_eq!(
        lines[5],
        "stream\t3\t1Table\tsize\t10485\tstart\t4\twhere\tregular\tsectors\t21\tholds\t10752",
        "the one stream at or above the cutoff is chained through the real FAT"
    );
    assert_eq!(
        lines[7],
        "stream\t5\tWordDocument\tsize\t3645\tstart\t8\twhere\tmini\tsectors\t57\tholds\t3648"
    );
    assert_eq!(
        lines[9],
        "inventory\tstreams\t6\tstorages\t0\tfree\t1\tbytes\t14700\tcollisions\t0\thint\tword"
    );
    assert_eq!(lines[10], "walked\tend");
    assert_eq!(lines.len(), 11);
}

#[test]
fn a_workbook_at_exactly_the_cutoff_is_not_a_mini_stream() {
    assert_eq!(
        rows("excel97.xls"),
        vec![
            "cfb\t5632\tbroken\t0\tversion\t3.62\tsector\t512\tmini\t64",
            "layout\tfat\t1\tdifat\t0\tdir\t1\tminifat\t0\tsectors\t10",
            "root\tstart\t4294967294\tsize\t0\tsectors\t0\tholds\t0\tmini\t0\tclsid\t-",
            "stream\t1\tWorkbook\tsize\t4096\tstart\t0\twhere\tregular\tsectors\t8\tholds\t4096",
            "inventory\tstreams\t1\tstorages\t0\tfree\t2\tbytes\t4096\tcollisions\t0\thint\texcel",
            "walked\tend",
        ],
        "xlwt gives every stream to the big FAT and writes no mini stream at all"
    );
}

#[test]
fn a_second_fat_sector_extends_the_table_rather_than_just_the_count() {
    let lines = rows("wide97.xls");
    assert_eq!(
        lines[1],
        "layout\tfat\t2\tdifat\t0\tdir\t1\tminifat\t0\tsectors\t187"
    );
    assert_eq!(
        lines[3],
        "stream\t1\tWorkbook\tsize\t94208\tstart\t0\twhere\tregular\tsectors\t184\tholds\t94208",
        "the chain runs past sector 127, so it can only be read if the second FAT sector is placed \
         at its own position in the table"
    );
    assert!(lines[4].contains("\tcollisions\t0"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "walked\tend"), "{lines:?}");
}

#[test]
fn a_hand_built_directory_splits_mini_and_regular_streams() {
    let bytes = hand_built(false, false);
    assert_eq!(parse(&bytes), FORMAT_CFB, "{} bytes", bytes.len());
    assert_eq!(
        report(),
        vec![
            format!(
                "cfb\t{}\tbroken\t0\tversion\t3.62\tsector\t512\tmini\t64",
                bytes.len()
            ),
            "layout\tfat\t1\tdifat\t0\tdir\t2\tminifat\t1\tsectors\t14".to_owned(),
            "root\tstart\t13\tsize\t128\tsectors\t1\tholds\t512\tmini\t2\tclsid\t-".to_owned(),
            "stream\t1\tSmall\tsize\t70\tstart\t0\twhere\tmini\tsectors\t2\tholds\t128".to_owned(),
            "stream\t2\tBig\tsize\t4096\tstart\t5\twhere\tregular\tsectors\t8\tholds\t4096"
                .to_owned(),
            "storage\t3\t.Group\tchild\t4".to_owned(),
            "stream\t4\tNested\tsize\t20\tstart\t2\twhere\tmini\tsectors\t1\tholds\t64".to_owned(),
            "inventory\tstreams\t3\tstorages\t1\tfree\t3\tbytes\t4186\tcollisions\t0\thint\t-"
                .to_owned(),
            "walked\tend".to_owned(),
        ]
    );
}

#[test]
fn a_name_that_cannot_be_printed_is_kept_as_a_dot_rather_than_dropped() {
    // The storage is named 0x01Group, exactly as a stream that carries an Ole marker is named, and
    // the row has to keep the byte's place without putting a control character in the report.
    let bytes = hand_built(false, false);
    assert_eq!(parse(&bytes), FORMAT_CFB);
    let lines = report();
    assert_eq!(lines[5], "storage\t3\t.Group\tchild\t4");
    assert_eq!(
        lines[5].matches('.').count(),
        1,
        "the control byte left exactly one dot"
    );
    assert!(!lines[5].contains('\u{1}'), "{:?}", lines[5]);
}

#[test]
fn one_sector_cannot_belong_to_two_owners() {
    let bytes = hand_built(true, false);
    assert_eq!(parse(&bytes), FORMAT_CFB);
    let lines = report();
    assert!(lines[0].starts_with("cfb\t7680\tbroken\t1"), "{lines:?}");
    assert_eq!(
        lines[3],
        "stream\t1\tSmall\tsize\t4096\tstart\t13\twhere\tregular\tsectors\t1\tholds\t512"
    );
    assert_eq!(
        lines[7],
        "inventory\tstreams\t3\tstorages\t1\tfree\t3\tbytes\t8212\tcollisions\t1\thint\t-"
    );
    assert_eq!(lines[8], "stopped\tbroken\t1");
}

#[test]
fn a_fat_that_links_two_sectors_to_each_other_stops_instead_of_spinning() {
    let bytes = hand_built(false, true);
    assert_eq!(parse(&bytes), FORMAT_CFB);
    let lines = report();
    assert!(lines[0].contains("\tbroken\t1"), "{lines:?}");
    assert_eq!(
        lines[4], "stream\t2\tBig\tsize\t4096\tstart\t5\twhere\tregular\tsectors\t2\tholds\t1024",
        "the walk visits both sectors and then refuses to repeat one"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1");
    assert!(
        lines[lines.len() - 2].contains("\tcollisions\t0"),
        "a cycle is not a share: {lines:?}"
    );
}

#[test]
fn a_short_or_foreign_file_is_not_a_compound_container() {
    // Eight bytes is the shortest input the dispatcher hands to any reader, so these are the
    // "recognised nothing" answers; anything smaller is refused as too short to identify at all.
    assert_eq!(
        parse(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        -2,
        "the magic alone is not a file"
    );
    assert_eq!(parse(&[0u8; 600]), -2, "zero bytes carry no magic");
    assert_eq!(
        parse(b"D0CF11E0aaaaaaaa"),
        -2,
        "the magic is the bytes, not their name"
    );
    assert_eq!(parse(&[0u8; 7]), -1, "below the size any reader can use");

    // Right magic, big-endian byte order mark: a layout this reader will not guess.
    let mut swapped = hand_built(false, false);
    swapped[28..30].copy_from_slice(&0xFEFFu16.to_le_bytes());
    assert_eq!(
        parse(&swapped),
        -2,
        "0xFEFF order is not walked as little-endian"
    );

    // A sector shift of zero would make every sector one byte long.
    let mut tiny = hand_built(false, false);
    tiny[30..32].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(parse(&tiny), -2, "a sector below 512 bytes is not believed");

    // A directory whose first entry is not the root storage has nothing to anchor the walk to.
    let mut orphan = hand_built(false, false);
    orphan[SECTOR + 2 * SECTOR + 66] = 2;
    assert_eq!(parse(&orphan), -2, "the first entry has to be the root");
}

#[test]
fn a_difat_that_names_a_sector_past_the_file_is_reported_not_walked() {
    let mut bytes = hand_built(false, false);
    let past = (bytes.len() - SECTOR) / SECTOR + 400;
    bytes[76..80].copy_from_slice(&(past as u32).to_le_bytes());
    assert_eq!(
        parse(&bytes),
        FORMAT_CFB,
        "the magic still identifies the container"
    );
    let lines = report();
    assert!(lines[0].contains("\tbroken\t"), "{lines:?}");
    assert!(
        !lines.iter().any(|line| line == "walked\tend"),
        "a FAT sector that is not there cannot be believed: {lines:?}"
    );
}
