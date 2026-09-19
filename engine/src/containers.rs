//! Container readers for formats that have no Kaitai spec in the pinned compiler bundle:
//! tar (ustar), ar (and therefore the control part of .deb), RIFF/WebP, and TIFF.
//!
//! These are structural reads - member names and sizes, chunk lists, IFD tags - not decompression
//! or rendering. Every accessor goes through a bounds-checked reader, so a truncated or hostile
//! file produces an error code instead of a panic, and nothing is written anywhere.
//!
//! Layouts are the published ones:
//!   tar   512-byte blocks; name[0..100], size[124..136] octal ASCII, typeflag[156],
//!         magic[257..263] "ustar\0", prefix[345..500]
//!   ar    "!<arch>\n" then 60-byte member headers: name[0..16], size[48..58], terminator "`\n"
//!   RIFF  "RIFF", u32le total-8, form FourCC, then chunks of FourCC + u32le size + padded body
//!   TIFF  "II"/"MM", u16 42 (or 43 for bigtiff), u32 first IFD; IFD = u16 count, 12-byte
//!         entries (tag, type, count, value), then u32 next IFD offset

use crate::scan::Le;
use std::cell::RefCell;

pub const FORMAT_TAR: i32 = 1;
pub const FORMAT_AR: i32 = 2;
pub const FORMAT_RIFF: i32 = 3;
pub const FORMAT_TIFF: i32 = 4;
// 5..9 are the stream formats in `streams.rs`, so these stay unique across both kinds.
pub const FORMAT_BMFF: i32 = 10;
pub const FORMAT_EBML: i32 = 11;

thread_local! {
    static RESULT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static KIND: RefCell<i32> = const { RefCell::new(0) };
}

fn reject(message: &str, code: i32) -> i32 {
    crate::set_error(message);
    KIND.with(|slot| *slot.borrow_mut() = 0);
    RESULT.with(|slot| slot.borrow_mut().clear());
    code
}

fn accept(kind: i32, lines: Vec<String>) -> i32 {
    KIND.with(|slot| *slot.borrow_mut() = kind);
    RESULT.with(|slot| *slot.borrow_mut() = lines);
    kind
}

pub fn kind() -> i32 {
    KIND.with(|slot| *slot.borrow())
}

pub fn count() -> i32 {
    RESULT.with(|slot| slot.borrow().len() as i32)
}

pub fn at(index: i32) -> Option<String> {
    RESULT.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}

/// Endianness-aware field reader. Big-endian TIFF is the only reason this exists, so it is
/// implemented once here rather than branching at every call site.
struct Fields<'a> {
    bytes: &'a [u8],
    little: bool,
}

impl Fields<'_> {
    fn u16(&self, at: usize) -> Option<i32> {
        if at + 2 > self.bytes.len() {
            return None;
        }
        let pair: [u8; 2] = self.bytes[at..at + 2].try_into().unwrap();
        Some(i32::from(if self.little {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        }))
    }

    fn u32(&self, at: usize) -> Option<i64> {
        if at + 4 > self.bytes.len() {
            return None;
        }
        let quad: [u8; 4] = self.bytes[at..at + 4].try_into().unwrap();
        Some(i64::from(if self.little {
            u32::from_le_bytes(quad)
        } else {
            u32::from_be_bytes(quad)
        }))
    }
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn octal(bytes: &[u8]) -> Option<i64> {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_matches(|c: char| c == ' ' || c == '\0' || c == '\n');
    if trimmed.is_empty() {
        return Some(0);
    }
    i64::from_str_radix(trimmed, 8).ok()
}

fn fourcc(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn read_tar(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 512 {
        return None;
    }
    let mut entries = Vec::new();
    let mut block = 0usize;
    while block + 512 <= bytes.len() {
        let header = &bytes[block..block + 512];
        block += 512;
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let magic_ok = header[257..262] == *b"ustar";
        if !magic_ok {
            continue;
        }
        let Some(size) = octal(&header[124..136]) else {
            continue;
        };
        let name = cstr(&header[0..100]);
        let prefix = cstr(&header[345..500]);
        let full = if prefix.is_empty() {
            name
        } else {
            format!("{}/{}", prefix, name)
        };
        entries.push(format!("{}\t{}\t{}", full, size, header[156] as char));
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

fn read_ar(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 8 || &bytes[0..8] != b"!<arch>\n" {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = 8usize;
    while at + 60 <= bytes.len() {
        let header = &bytes[at..at + 60];
        if &header[58..60] != b"`\n" {
            break;
        }
        let Some(size) = octal(&header[48..58]) else {
            break;
        };
        let name = cstr(&header[0..16])
            .trim_end()
            .trim_end_matches('/')
            .to_string();
        let mode = cstr(&header[40..48]).trim_end().to_string();
        entries.push(format!("{}\t{}\t{}", name, size, mode));
        at += 60 + size as usize + (size as usize & 1);
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

fn read_riff(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 12 || fourcc(&bytes[0..4]) != "RIFF" {
        return None;
    }
    let file = Le(bytes);
    let form = fourcc(&bytes[8..12]);
    let declared = file.u32(4)?.max(0) as i64 + 8;
    let mut entries = vec![format!("form\t{}\t{}", form, declared)];
    let mut at = 12usize;
    while at + 8 <= bytes.len() {
        let id = fourcc(&bytes[at..at + 4]);
        let size = file.u32(at + 4)?.max(0) as usize;
        entries.push(format!("{}\t{}\t{}", id, size, at + 8));
        let step = size + (size & 1);
        if at + 8 + step > bytes.len() {
            break;
        }
        at += 8 + step;
    }
    if entries.len() > 1 {
        Some(entries)
    } else {
        None
    }
}

fn read_tiff(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 8 {
        return None;
    }
    let little = match &bytes[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let fields = Fields { bytes, little };
    let marker = fields.u16(2)?;
    // Only classic TIFF (42) is read. Bigtiff (43) stores its offsets as 8-byte values, so
    // walking it with these readers would report tags from the wrong positions.
    if marker != 42 {
        return None;
    }
    let mut offset = fields.u32(4)?;
    let mut entries = Vec::new();
    for ifd in 0..4i32 {
        if offset < 8 || offset as usize >= bytes.len() {
            break;
        }
        let base = offset as usize;
        let count = fields.u16(base)? as usize;
        for index in 0..count.min(512) {
            let entry = base + 2 + index * 12;
            let (Some(tag), Some(field_type), Some(value_count)) = (
                fields.u16(entry),
                fields.u16(entry + 2),
                fields.u32(entry + 4),
            ) else {
                break;
            };
            entries.push(format!(
                "ifd{}\t{}\t{}\t{}",
                ifd, tag, field_type, value_count
            ));
        }
        offset = fields.u32(base + 2 + count * 12)?;
        if offset <= 0 {
            break;
        }
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// ISO base media file format (mp4/3gp/m4v family): top-level box list, the brands in `ftyp`, and
/// the `mvhd` timescale and duration when a `moov` is present. Boxes are 32-bit size plus FourCC,
/// with size 0 meaning "to end of file" and size 1 meaning "the real size is the following u64".
fn read_bmff(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 || fourcc(&bytes[4..8]) != "ftyp" {
        return None;
    }
    let be = Fields {
        bytes,
        little: false,
    };
    let declared = be.u32(0)?.max(0) as usize;
    if declared < 16 || declared > bytes.len() {
        return None;
    }
    let mut entries = vec![format!("ftyp\t{}\t{}", fourcc(&bytes[8..12]), be.u32(12)?)];
    let mut at = 16usize;
    while at + 4 <= declared {
        entries.push(format!("brand\t{}", fourcc(&bytes[at..at + 4])));
        at += 4;
    }
    let mut cursor = 0usize;
    let mut boxes = 0i64;
    while cursor + 8 <= bytes.len() && boxes < 256 {
        let Some((size, header)) = box_extent(bytes, &be, cursor) else {
            break;
        };
        let kind = fourcc(&bytes[cursor + 4..cursor + 8]);
        entries.push(format!("box\t{kind}\t{size}\t{cursor}"));
        boxes += 1;
        let body = cursor + header;
        if kind == "moov" {
            let mut inner = body;
            let limit = (cursor + size).min(bytes.len());
            while inner + 8 <= limit {
                let Some((inner_size, _)) = box_extent(bytes, &be, inner) else {
                    break;
                };
                let inner_kind = fourcc(&bytes[inner + 4..inner + 8]);
                entries.push(format!("child\t{inner_kind}\t{inner_size}\t{inner}"));
                if inner_kind == "mvhd" {
                    let version = usize::from(bytes[inner + 8]);
                    let (timescale, duration) = if version == 1 {
                        (be.u32(inner + 28)?, Le(bytes).u64(inner + 32)?)
                    } else {
                        (be.u32(inner + 20)?, i64::from(be.u32(inner + 24)?))
                    };
                    let millis = if timescale > 0 {
                        duration.saturating_mul(1000) / timescale
                    } else {
                        0
                    };
                    entries.push(format!("duration\t{timescale}\t{duration}\t{millis}"));
                }
                if inner_size < 8 || inner + inner_size > limit {
                    break;
                }
                inner += inner_size;
            }
        }
        if size < 8 || cursor + size > bytes.len() {
            break;
        }
        cursor += size;
    }
    if cursor == bytes.len() {
        entries.push("walked\tend".to_string());
    }
    Some(entries)
}

/// (total box size, bytes of header) for the box starting at `at`, honouring the size-0 and
/// size-1 forms. None when the length cannot be read at all.
fn box_extent(bytes: &[u8], be: &Fields, at: usize) -> Option<(usize, usize)> {
    let first = be.u32(at)?.max(0) as usize;
    match first {
        0 => Some((bytes.len() - at, 8)),
        1 => Some((Le(bytes).u64(at + 8)?.max(0) as usize, 16)),
        other => Some((other, 8)),
    }
}

/// EBML, the master/element tree Matroska and WebM are built from. Element ids and sizes are
/// variable-length: the number of bytes is the position of the first set bit in the leading byte,
/// and for a size that same leading byte carries the value's top bits.
fn read_ebml(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 {
        return None;
    }
    if ebml_id(bytes, 0)
        .filter(|(id, _)| *id == 0x1a45_dfa3)
        .is_none()
    {
        return None;
    }
    let (header_size, header_len) = vint(bytes, 4)?;
    let header_end = (4 + header_len + header_size as usize).min(bytes.len());
    let mut at = 4 + header_len;
    let mut doctype = String::new();
    let mut versions = [0i64; 3];
    while at + 2 <= header_end {
        let Some((id, id_len)) = ebml_id(bytes, at) else {
            break;
        };
        let Some((size, size_len)) = vint(bytes, at + id_len) else {
            break;
        };
        let body = at + id_len + size_len;
        if body + size as usize > bytes.len() {
            break;
        }
        let raw = &bytes[body..body + size as usize];
        match id {
            0x4282 => doctype = crate::scan::utf8_or_hex(raw),
            0x4286 => versions[0] = unsigned(raw),
            0x4287 => versions[1] = unsigned(raw),
            0x4285 => versions[2] = unsigned(raw),
            _ => {}
        }
        at = body + size as usize;
    }
    let mut entries = vec![format!(
        "header\t{}\t{}\t{}\t{}",
        doctype, versions[0], versions[1], versions[2]
    )];
    let Some((segment_id, id_len)) = ebml_id(bytes, at) else {
        return Some(entries);
    };
    if segment_id != 0x1853_8067 {
        return Some(entries);
    }
    let (segment_size, size_len) = vint(bytes, at + id_len)?;
    let unknown = segment_size == (1i64 << (7 * size_len)) - 1;
    entries.push(format!(
        "segment\t{}\t{}",
        if unknown { -1 } else { segment_size },
        at
    ));
    let mut cursor = at + id_len + size_len;
    let limit = if unknown {
        bytes.len()
    } else {
        (cursor + segment_size as usize).min(bytes.len())
    };
    let mut walked = 0i64;
    while cursor + 2 <= limit && walked < 128 {
        let Some((id, id_len)) = ebml_id(bytes, cursor) else {
            break;
        };
        let Some((size, size_len)) = vint(bytes, cursor + id_len) else {
            break;
        };
        let child_unknown = size == (1i64 << (7 * size_len)) - 1;
        entries.push(format!(
            "elem\t{:#x}\t{}\t{}",
            id,
            if child_unknown { -1 } else { size },
            cursor
        ));
        walked += 1;
        let body = cursor + id_len + size_len;
        if matches!(id, 0x1549_a966 | 0x1654_ae6b) && !child_unknown {
            let mut inner = body;
            let inner_limit = (body + size as usize).min(bytes.len());
            while inner + 2 <= inner_limit {
                let Some((inner_id, inner_len)) = ebml_id(bytes, inner) else {
                    break;
                };
                let Some((inner_size, inner_size_len)) = vint(bytes, inner + inner_len) else {
                    break;
                };
                let payload = inner + inner_len + inner_size_len;
                if payload + inner_size as usize > bytes.len() {
                    break;
                }
                let raw = &bytes[payload..payload + inner_size as usize];
                match inner_id {
                    0x2ad7_b1 => entries.push(format!("timecode_scale_ns\t{}", unsigned(raw))),
                    0x4489 => entries.push(format!("duration_ms\t{}", float(raw))),
                    0x4d80 | 0x5741 => entries.push(format!(
                        "app\t{:#x}\t{}",
                        inner_id,
                        crate::scan::utf8_or_hex(raw)
                    )),
                    _ => entries.push(format!("child\t{:#x}\t{}\t{}", inner_id, inner_size, inner)),
                }
                inner = payload + inner_size as usize;
            }
        }
        if child_unknown || size > limit as i64 {
            break;
        }
        cursor = body + size as usize;
    }
    Some(entries)
}

fn ebml_id(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    let first = *bytes.get(at)?;
    let len = (0..8).find(|shift| (first >> (7 - shift)) & 1 == 1)? + 1;
    if len > 4 || at + len > bytes.len() {
        return None;
    }
    let mut value = 0i64;
    for byte in &bytes[at..at + len] {
        value = value << 8 | i64::from(*byte);
    }
    Some((value, len))
}

fn vint(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    let first = *bytes.get(at)?;
    let len = (0..8).find(|shift| (first >> (7 - shift)) & 1 == 1)? + 1;
    if at + len > bytes.len() {
        return None;
    }
    let mut value = i64::from(first & (0xff >> len));
    for byte in &bytes[at + 1..at + len] {
        value = value << 8 | i64::from(*byte);
    }
    Some((value, len))
}

fn unsigned(bytes: &[u8]) -> i64 {
    let mut value = 0i64;
    for byte in bytes.iter().take(8) {
        value = value << 8 | i64::from(*byte);
    }
    value
}

fn float(bytes: &[u8]) -> f64 {
    if bytes.len() == 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        f64::from_bits(u64::from_be_bytes(buf))
    } else if bytes.len() == 4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        f32::from_bits(u32::from_be_bytes(buf)) as f64
    } else {
        0.0
    }
}

/// -1 buffer too small to hold any header, -2 no supported container recognised.
/// Otherwise the FORMAT_* code, matching what `kind()` reports.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < 12 {
        return reject("too small to identify a container", -1);
    }
    if let Some(lines) = read_tar(bytes) {
        return accept(FORMAT_TAR, lines);
    }
    if let Some(lines) = read_ar(bytes) {
        return accept(FORMAT_AR, lines);
    }
    if let Some(lines) = read_ebml(bytes) {
        return accept(FORMAT_EBML, lines);
    }
    if let Some(lines) = read_bmff(bytes) {
        return accept(FORMAT_BMFF, lines);
    }
    if let Some(lines) = read_riff(bytes) {
        return accept(FORMAT_RIFF, lines);
    }
    if let Some(lines) = read_tiff(bytes) {
        return accept(FORMAT_TIFF, lines);
    }
    reject(
        "not a tar, ar, RIFF, TIFF, EBML or ISO base media container",
        -2,
    )
}
