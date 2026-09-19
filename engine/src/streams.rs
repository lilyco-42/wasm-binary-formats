//! Compressed-stream framing readers: xz, bzip2, lz4, zstd and gzip.
//!
//! Scope is the framing - magic, flags and the size fields that are byte-aligned - not
//! decompression. Every fact asserted by the tests was read out of files produced by the
//! command-line tools of the same name, which is what corrected two assumptions while writing this:
//! the .xz Stream Footer ends with the two bytes "YZ" (0x59 0x5A), not a four-byte magic, and the
//! bzip2 block magic 0x314159265359 starts on a byte boundary right after the level digit.

use crate::scan::Le;
use std::cell::RefCell;

pub const FORMAT_XZ: i32 = 5;
pub const FORMAT_BZIP2: i32 = 6;
pub const FORMAT_LZ4: i32 = 7;
pub const FORMAT_ZSTD: i32 = 8;
pub const FORMAT_GZIP: i32 = 9;

thread_local! {
    static FIELDS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static STREAM_KIND: RefCell<i32> = const { RefCell::new(0) };
}

fn note(kind: i32, lines: Vec<String>) -> i32 {
    STREAM_KIND.with(|slot| *slot.borrow_mut() = kind);
    FIELDS.with(|slot| *slot.borrow_mut() = lines);
    kind
}

pub fn kind() -> i32 {
    STREAM_KIND.with(|slot| *slot.borrow())
}

/// The family name beside the code, next to the constants rather than in a caller's table.
pub fn name() -> &'static str {
    match kind() {
        FORMAT_XZ => "xz",
        FORMAT_BZIP2 => "bzip2",
        FORMAT_LZ4 => "lz4",
        FORMAT_ZSTD => "zstd",
        FORMAT_GZIP => "gzip",
        _ => "unknown",
    }
}

pub fn count() -> i32 {
    FIELDS.with(|slot| slot.borrow().len() as i32)
}

pub fn field(index: i32) -> Option<String> {
    FIELDS.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}

fn starts(bytes: &[u8], magic: &[u8]) -> bool {
    bytes.len() >= magic.len() && bytes[..magic.len()] == *magic
}

/// Stream Header is magic(6) + stream flags(2) + CRC32(4); the footer's backward size field is
/// the index size divided by 4, minus one.
fn read_xz(bytes: &[u8]) -> Option<i32> {
    if !starts(bytes, &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) || bytes.len() < 16 {
        return None;
    }
    let file = Le(bytes);
    let check = i32::try_from(bytes[7] & 0x3f).unwrap_or(0);
    let footer_at = bytes.len() - 12;
    let backward = file.u32(footer_at + 4)?;
    Some(note(
        FORMAT_XZ,
        vec![
            format!("checkType\t{}", check),
            format!("blockHeaderSize\t{}", (bytes[12] as i64 + 1) * 4),
            format!("backwardSize\t{}", backward),
            format!("indexSize\t{}", (backward + 1) * 4),
            format!(
                "footerMagic\t{}",
                u16::from_le_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]])
            ),
        ],
    ))
}

fn read_bzip2(bytes: &[u8]) -> Option<i32> {
    if !starts(bytes, b"BZh") || bytes.len() < 10 {
        return None;
    }
    let level = (bytes[3] as char).to_digit(10)? as i64;
    // The block magic is a 48-bit big-endian field: asking Le for a u64 here wants eight bytes
    // from a six-byte window, returns None, and the whole format silently failed to match.
    let block = bytes[4..10]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    if block != 0x3141_5926_5359 {
        return None;
    }
    Some(note(
        FORMAT_BZIP2,
        vec![
            format!("level\t{}", level),
            format!("blockMagic\t{:#x}", block),
            format!("nominalBlockSize\t{}", level * 100_000),
        ],
    ))
}

/// The LZ4 frame magic is little-endian 0x184D2204; FLG/BD follow it and the block maximum is
/// encoded in BD bits 4-6.
fn read_lz4(bytes: &[u8]) -> Option<i32> {
    if !starts(bytes, &[0x04, 0x22, 0x4d, 0x18]) || bytes.len() < 7 {
        return None;
    }
    let flg = bytes[4];
    let bd = bytes[5];
    let block_max = match (bd >> 4) & 0x7 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => 0,
    };
    Some(note(
        FORMAT_LZ4,
        vec![
            format!("version\t{}", (flg >> 6) & 3),
            format!("blockIndep\t{}", (flg >> 5) & 1),
            format!("contentChecksum\t{}", (flg >> 2) & 1),
            format!("blockMaxSize\t{}", block_max),
        ],
    ))
}

/// Zstd framing is reported as the raw header bytes. The descriptor packs several field widths
/// into single bits and I have not verified each one against the spec, so guessing them here would
/// put wrong names on correct bytes - container level is the honest claim.
fn read_zstd(bytes: &[u8]) -> Option<i32> {
    if !starts(bytes, &[0x28, 0xb5, 0x2f, 0xfd]) || bytes.len() < 6 {
        return None;
    }
    Some(note(
        FORMAT_ZSTD,
        vec![
            format!("frameHeaderDescriptor\t{}", bytes[4]),
            format!("windowDescriptor\t{}", bytes[5]),
        ],
    ))
}

fn read_gzip(bytes: &[u8]) -> Option<i32> {
    if !starts(bytes, &[0x1f, 0x8b]) || bytes.len() < 10 {
        return None;
    }
    Some(note(
        FORMAT_GZIP,
        vec![
            format!("method\t{}", bytes[2]),
            format!("flags\t{}", bytes[3]),
            format!("mtime\t{}", Le(bytes).u32(4).unwrap_or_default()),
            format!("os\t{}", bytes[9]),
        ],
    ))
}

/// -1 too short, -2 not a recognised stream. Otherwise the FORMAT_* code.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < 10 {
        return -1;
    }
    if let Some(kind) = read_xz(bytes) {
        return kind;
    }
    if let Some(kind) = read_bzip2(bytes) {
        return kind;
    }
    if let Some(kind) = read_lz4(bytes) {
        return kind;
    }
    if let Some(kind) = read_zstd(bytes) {
        return kind;
    }
    if let Some(kind) = read_gzip(bytes) {
        return kind;
    }
    -2
}
