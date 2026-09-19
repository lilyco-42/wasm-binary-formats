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
//!   PDF   "%PDF-x.y" header, `startxref` offset near the end of the file, then a classic `xref`
//!         table of 20-byte rows and a `trailer` dictionary (PDF 1.5 xref streams are reported as
//!         unsupported rather than walked)

use crate::scan::Le;
use std::cell::RefCell;

pub const FORMAT_TAR: i32 = 1;
pub const FORMAT_AR: i32 = 2;
pub const FORMAT_RIFF: i32 = 3;
pub const FORMAT_TIFF: i32 = 4;
// 5..9 are the stream formats in `streams.rs`, 12..15 the audio formats in `audio.rs`, so these
// stay unique across all three kinds.
pub const FORMAT_BMFF: i32 = 10;
pub const FORMAT_EBML: i32 = 11;
pub const FORMAT_PDF: i32 = 16;
pub const FORMAT_NETPBM: i32 = 19;

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
    // The leading byte keeps `len - 1` value bits; masking with 0xff >> len would shift a u8 by 8
    // and panic on the all-ones first byte that means "unknown size".
    let mut value = i64::from(first & (0x7f >> (len - 1)));
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

/// Classic-cross-reference PDFs: the header version, the entry point the file advertises, the xref
/// rows with the offsets they claim, and the object references in the trailer dictionary. PDF 1.5
/// xref and object streams are recognised and reported as unsupported rather than guessed at,
/// because their offsets live in a compressed stream this reader does not decode.
fn read_pdf(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 64 || &bytes[0..5] != b"%PDF-" {
        return None;
    }
    let version = String::from_utf8_lossy(bytes.get(5..8)?).into_owned();
    let mut entries = vec![format!("pdf\t{version}")];
    // Writers put `startxref` in the last few bytes, so only the tail is searched: a hostile file
    // cannot make this scan the whole buffer for a nine-byte needle.
    let tail = bytes.len().saturating_sub(1024);
    let found = find(bytes, tail, b"startxref")?;
    let (offset, _) = digits(bytes, skip_white(bytes, found + b"startxref".len())?)?;
    entries.push(format!("startxref\t{offset}"));
    let base = skip_white(bytes, offset as usize)?;
    if bytes.get(base..base + 4) != Some(b"xref") {
        let stream = find(bytes, base, b"/Type/XRef").is_some()
            || find(bytes, base, b"/Type /XRef").is_some();
        entries.push(format!("xref_stream\t{}", if stream { 1 } else { 0 }));
        return Some(entries);
    }
    let mut cursor = base + 4;
    let mut rows = 0i64;
    let mut live = 0i64;
    let mut free = 0i64;
    let mut verified = 0i64;
    // Subsections are "first count" followed by `count` records of exactly 20 bytes:
    // 10-digit offset, space, 5-digit generation, space, 'n' or 'f', then a two-byte end of line.
    'table: for _subsection in 0..64 {
        let Some(at) = skip_white(bytes, cursor) else {
            break 'table;
        };
        let Some((first, after_first)) = digits(bytes, at) else {
            break 'table;
        };
        let Some(at) = skip_white(bytes, after_first) else {
            break 'table;
        };
        let Some((count, after_count)) = digits(bytes, at) else {
            break 'table;
        };
        // The row area starts after the newline that ends the "first count" line: reading from the
        // digit run's end would shift every 20-byte record by one byte, which still counts the rows
        // but reads each row's type character out of the generation field.
        let Some(cursor_after_header) = skip_white(bytes, after_count) else {
            break 'table;
        };
        cursor = cursor_after_header;
        if count > 8192 || first > bytes.len() as i64 {
            break 'table;
        }
        for index in 0..count {
            let record = cursor + index as usize * 20;
            let Some(body) = bytes.get(record..record + 20) else {
                break 'table;
            };
            let row_offset = digits(body, 0).map_or(0, |(value, _)| value);
            let generation = digits(body, 11).map_or(0, |(value, _)| value);
            let kind = char::from(body[17]);
            rows += 1;
            if kind == 'n' {
                live += 1;
                let at = row_offset as usize;
                let head = bytes.get(at..at + 12).unwrap_or(b"");
                let label = format!("{} ", first + index);
                let named = String::from_utf8_lossy(head).starts_with(&label);
                let open = find(bytes, at, b" obj").is_some_and(|pos| pos - at <= 12);
                if named && open {
                    verified += 1;
                }
            } else if kind == 'f' {
                free += 1;
            }
            entries.push(format!(
                "xref\t{}\t{}\t{}\t{}",
                first + index,
                row_offset,
                generation,
                kind
            ));
        }
        cursor += count as usize * 20;
        match skip_white(bytes, cursor) {
            Some(at) if bytes.get(at..at + 7) == Some(b"trailer") => {
                cursor = at + 7;
                break 'table;
            }
            _ => continue 'table,
        }
    }
    entries.push(format!("rows\t{rows}\tlive\t{live}\tfree\t{free}"));
    entries.push(format!("verified\t{verified}\tof\t{live}"));
    // The trailer dictionary, read as tokens: a `/Name` followed by `number number R` is a
    // reference, which is what `/Root` and `/Info` are. A lone number (`/Size 7`) is not.
    let Some(dict) = skip_white(bytes, cursor).and_then(|at| find(bytes, at, b"<<")) else {
        return Some(entries);
    };
    let stop = find(bytes, dict, b">>")
        .unwrap_or(bytes.len())
        .min(bytes.len());
    let mut scan = dict;
    let mut name = String::new();
    let mut guard = 0usize;
    while scan < stop && guard < 8192 {
        guard += 1;
        match bytes[scan] {
            b'/' => {
                let mut end = scan + 1;
                while end < stop
                    && !matches!(
                        bytes[end],
                        b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'<' | b'>'
                    )
                {
                    end += 1;
                }
                name = String::from_utf8_lossy(&bytes[scan + 1..end]).into_owned();
                scan = end;
            }
            b'0'..=b'9' => {
                let Some((number, after)) = digits(bytes, scan) else {
                    scan += 1;
                    continue;
                };
                let reference = skip_white(bytes, after)
                    .and_then(|at| digits(bytes, at))
                    .and_then(|(gen, next)| Some((gen, skip_white(bytes, next)?)))
                    .filter(|(_, at)| bytes.get(*at) == Some(&b'R'));
                match reference {
                    Some((generation, at)) => {
                        entries.push(format!("ref\t{name}\t{number}\t{generation}"));
                        scan = at + 1;
                    }
                    None => scan = after,
                }
            }
            _ => scan += 1,
        }
    }
    Some(entries)
}

/// Index of the first occurrence of `needle` at or after `from`.
fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > bytes.len() || needle.is_empty() || from + needle.len() > bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// First index at or after `at` that is not whitespace or a NUL byte.
fn skip_white(bytes: &[u8], mut at: usize) -> Option<usize> {
    while at < bytes.len() {
        if matches!(bytes[at], b' ' | b'\t' | b'\r' | b'\n' | 0) {
            at += 1;
        } else {
            return Some(at);
        }
    }
    None
}

/// (value, index just past the digits) for an unsigned decimal run.
fn digits(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    let mut end = at;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == at {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes[at..end]);
    Some((text.parse::<i64>().unwrap_or(0), end))
}

/// Netpbm: the family that spells its geometry in ASCII at the front of the file. P1..P6 are read;
/// P7 (portable anymap) is not, because its header ends with the token `ENDHDR` rather than a fixed
/// number of integers, and reading it with this loop would return a geometry nobody asked for.
fn read_netpbm(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 8 || bytes[0] != b'P' {
        return None;
    }
    let digit = bytes[1];
    if !(b'1'..=b'6').contains(&digit) {
        return None;
    }
    // P1/P4 are bitmaps and carry no maximum sample value, so their header is two numbers.
    let ascii = matches!(digit, b'1' | b'2' | b'3');
    let need = if matches!(digit, b'1' | b'4') { 2 } else { 3 };
    let mut at = 2usize;
    let mut tokens: Vec<i64> = Vec::new();
    while (tokens.len()) < need {
        loop {
            let byte = *bytes.get(at)?;
            if byte == b'#' {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
                continue;
            }
            if byte.is_ascii_whitespace() {
                at += 1;
                continue;
            }
            break;
        }
        let start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        if start == at {
            return None;
        }
        let text = String::from_utf8_lossy(&bytes[start..at]);
        tokens.push(text.parse().ok()?);
    }
    // One whitespace character separates the last header number from the sample area.
    let header = at as i64 + 1;
    let width = *tokens.first()?;
    let height = *tokens.get(1)?;
    let maxval = if need == 3 { *tokens.get(2)? } else { 1 };
    if width <= 0 || height <= 0 || maxval <= 0 {
        return None;
    }
    let sample = if maxval > 255 { 2 } else { 1 };
    let payload = match digit {
        b'1' | b'2' | b'3' => -1,
        b'4' => (width + 7) / 8 * height,
        b'5' => sample * width * height,
        _ => sample * 3 * width * height,
    };
    let complete = if payload < 0 {
        1
    } else {
        i64::from(header + payload <= bytes.len() as i64)
    };
    Some(vec![
        format!(
            "netpbm\tP{}\t{}",
            char::from(digit),
            if ascii { "ascii" } else { "binary" }
        ),
        format!("width\t{width}"),
        format!("height\t{height}"),
        format!("maxval\t{maxval}"),
        format!("header_bytes\t{header}"),
        format!("payload_bytes\t{payload}"),
        format!("complete\t{complete}"),
    ])
}

pub const FORMAT_ASF: i32 = 20;

/// ASF (and therefore WMV/WMA): a sequence of objects, each one a 16-byte GUID followed by a 64-bit
/// little-endian *total* length that includes those 24 bytes. The first object is a header whose own
/// header is `GUID(16) size(8) count(u32) two reserved bytes`, so its children begin at offset 30 -
/// forty was the guess that a hexdump of `test/fixtures/media.asf` disproved, and the constants here
/// are those observed bytes rather than a recollection of a specification.
const ASF_HEADER_GUID: [u8; 16] = [
    0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c,
];

fn guid_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_asf(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 64 || bytes.get(0..16) != Some(ASF_HEADER_GUID.as_slice()) {
        return None;
    }
    let file = Le(bytes);
    let header_size = file.u64(16)?;
    if header_size < 30 || header_size > bytes.len() as i64 {
        return None;
    }
    let count = file.u32(24)?;
    let mut entries = vec![format!(
        "asf\t{}\t{}\t{}",
        guid_hex(&bytes[0..16]),
        header_size,
        count
    )];
    let mut at = 30usize;
    let mut index = 0i64;
    // Children are listed, not decoded. The documented File Description field order does not match
    // what ffmpeg writes here - the slot named "file size" in the spec holds zero, and the real
    // length appears two u64s later - so until that is settled from a second file and the spec text,
    // ASF is credited at container level only, which is all this walk establishes.
    while index < count && at + 24 <= bytes.len() {
        let guid = bytes.get(at..at + 16)?;
        let size = file.u64(at + 16)?;
        entries.push(format!("object\t{}\t{}\t{}", guid_hex(guid), size, at));
        if size < 24 {
            break;
        }
        at += size as usize;
        index += 1;
    }
    entries.push(format!(
        "header_children_end\t{}\twanted\t{}",
        at, header_size
    ));
    let mut top = header_size as usize;
    let mut objects = 1i64;
    while top + 24 <= bytes.len() && objects < 64 {
        let guid = bytes.get(top..top + 16)?;
        let size = file.u64(top + 16)?;
        if size < 24 {
            break;
        }
        entries.push(format!("object\t{}\t{}\t{}", guid_hex(guid), size, top));
        objects += 1;
        top += size as usize;
    }
    entries.push(format!("objects\t{objects}"));
    if top == bytes.len() {
        entries.push("walked\tend".to_string());
    }
    Some(entries)
}

pub const FORMAT_FLV: i32 = 21;

fn be_u32(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at + 4)?;
    Some(i64::from(u32::from_be_bytes([
        part[0], part[1], part[2], part[3],
    ])))
}

fn be_u24(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at + 3)?;
    Some(i64::from(part[0]) << 16 | i64::from(part[1]) << 8 | i64::from(part[2]))
}

/// FLV: a nine-byte header, then tags of `type u8`, `data size u24be`, `timestamp u24be` plus an
/// extended timestamp byte, `stream id u24be`, the data, and a 32-bit back-pointer that has to equal
/// 11 + data size. That back-pointer is what makes the walk checkable: a single wrong length throws
/// every later tag out of step, so the mismatch count is reported rather than hidden.
fn read_flv(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 17 || bytes.get(0..3) != Some(b"FLV") {
        return None;
    }
    let version = i64::from(bytes[3]);
    let flags = i64::from(bytes[4]);
    let hdrlen = be_u32(bytes, 5)?;
    if version != 1 || hdrlen < 9 || (hdrlen as usize) + 17 > bytes.len() {
        return None;
    }
    let prev0 = be_u32(bytes, hdrlen as usize)?;
    let mut at = (hdrlen as usize) + 4;
    let mut tags = 0i64;
    let mut audio = 0i64;
    let mut video = 0i64;
    let mut script = 0i64;
    let mut mismatches = 0i64;
    let mut last_ts = 0i64;
    let mut entries = vec![
        format!("version\t{version}"),
        format!("flags\t{flags}"),
        format!("audio_present	{}", (flags >> 2) & 1),
        format!("video_present	{}", flags & 1),
        format!("header_bytes	{hdrlen}"),
        format!("previous_tag_size_zero	{prev0}"),
    ];
    while at + 11 <= bytes.len() && tags < 200_000 {
        let kind = i64::from(bytes[at]);
        let size = be_u24(bytes, at + 1)?;
        let low = be_u24(bytes, at + 4)?;
        let ts = (i64::from(bytes[at + 7]) << 24) | low;
        let label = match kind {
            8 => "audio",
            9 => "video",
            18 => "script",
            _ => "other",
        };
        match kind {
            8 => audio += 1,
            9 => video += 1,
            18 => script += 1,
            _ => {}
        }
        entries.push(format!("tag	{label}	{size}	{ts}	{at}"));
        last_ts = ts;
        let after = at + 11 + size as usize;
        if after + 4 > bytes.len() {
            at = after;
            break;
        }
        if be_u32(bytes, after)? != 11 + size {
            mismatches += 1;
        }
        at = after + 4;
        tags += 1;
    }
    entries.push(format!("tags	{tags}	audio	{audio}	video	{video}"));
    entries.push(format!("script_tags	{script}"));
    entries.push(format!("last_timestamp_ms	{last_ts}"));
    entries.push(format!("backpointer_mismatches	{mismatches}"));
    if at == bytes.len() {
        entries.push("walked	end".to_string());
    }
    Some(entries)
}

fn folder_area_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub const FORMAT_CAB: i32 = 22;

/// Microsoft cabinet: a 36-byte header, a folder area, then `cFiles` records of 16 bytes
/// (`cbFile u32`, uncompressed offset `u32`, folder `u16`, date `u16`, time `u16`, attributes `u16`)
/// each followed by a NUL-terminated name.
///
/// The folder area is listed, not decoded: two cabinets written by `makecab` here both leave eight
/// bytes between the header and `coffFiles`, where the specification describes a 16-byte `CFFOLDER`,
/// and the two 16-bit fields in those bytes hold 1 and 1 for a 100-byte folder and 19 and 1 for a
/// 600 KB one. Neither reading gives a byte count, so the bytes are reported verbatim and CAB is
/// credited at container level only.
fn read_cab(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 60 || bytes.get(0..4) != Some(b"MSCF") {
        return None;
    }
    let file = Le(bytes);
    let cabinet_bytes = file.u32(8)?;
    let coff_files = file.u32(16)?;
    let folders = i64::from(file.u16(26));
    let files = i64::from(file.u16(28));
    let flags = i64::from(file.u16(30));
    let set_id = i64::from(file.u16(32));
    let index = i64::from(file.u16(34));
    if coff_files < 36 || coff_files as usize >= bytes.len() || cabinet_bytes > bytes.len() as i64 {
        return None;
    }
    let area = bytes.get(36..coff_files as usize)?;
    let mut entries = vec![
        format!("cabinet_bytes	{cabinet_bytes}"),
        format!("version	{}{}", char::from(bytes[25]), char::from(bytes[24])),
        format!("folders	{folders}"),
        format!("files	{files}"),
        format!("flags	{flags}"),
        format!("set_id	{set_id}"),
        format!("set_index	{index}"),
        format!("files_offset	{coff_files}"),
        format!(
            "folder_area\t{}",
            folder_area_hex(&area[..area.len().min(64)])
        ),
    ];
    let mut at = coff_files as usize;
    let mut listed = 0i64;
    let mut total = 0i64;
    let mut offset_sum = 0i64;
    while listed < files && at + 16 <= bytes.len() {
        let size = file.u32(at)?;
        let uoff = file.u32(at + 4)?;
        let folder = i64::from(file.u16(at + 8));
        let date = i64::from(file.u16(at + 12));
        let time = i64::from(file.u16(at + 14));
        let name_at = at + 16;
        let end = bytes[name_at..].iter().position(|byte| *byte == 0)? + name_at;
        let name = String::from_utf8_lossy(bytes.get(name_at..end)?).into_owned();
        entries.push(format!("file	{name}	{size}	{uoff}	{folder}	{date}	{time}"));
        total += size;
        if uoff == offset_sum {
            offset_sum += size;
        }
        at = end + 1;
        listed += 1;
    }
    entries.push(format!("files_listed	{listed}"));
    entries.push(format!("uncompressed_total	{total}"));
    entries.push(format!(
        "contiguous_offsets	{}",
        i64::from(offset_sum == total)
    ));
    entries.push(format!("data_offset	{}", file.u32(36)?));
    Some(entries)
}

/// -1 buffer too small to hold any header
/// -1 buffer too small to hold any header, -2 no supported container recognised.
/// Otherwise the FORMAT_* code, matching what `kind()` reports.
pub fn parse(bytes: &[u8]) -> i32 {
    // Eight bytes is the shortest header any reader below can use (a Netpbm bitmap is seven), and
    // each reader bounds-checks itself, so there is nothing to gain by rejecting earlier.
    if bytes.len() < 8 {
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
    if let Some(lines) = read_pdf(bytes) {
        return accept(FORMAT_PDF, lines);
    }
    if let Some(lines) = read_netpbm(bytes) {
        return accept(FORMAT_NETPBM, lines);
    }
    if let Some(lines) = read_asf(bytes) {
        return accept(FORMAT_ASF, lines);
    }
    if let Some(lines) = read_flv(bytes) {
        return accept(FORMAT_FLV, lines);
    }
    if let Some(lines) = read_cab(bytes) {
        return accept(FORMAT_CAB, lines);
    }
    reject(
        "not a tar, ar, RIFF, TIFF, EBML, PDF, Netpbm, ASF or ISO base media container",
        -2,
    )
}
