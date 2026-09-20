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
//!   bplist "bplist00", objects, then `num` big-endian offsets of `offset_size` each, then a
//!         32-byte trailer; references inside an object are `object_ref_size` wide, which is not
//!         the same number (see `read_bplist`)
//!   PDF   "%PDF-x.y" header, `startxref` offset near the end of the file, then a classic `xref`
//!         table of 20-byte rows and a `trailer` dictionary (PDF 1.5 xref streams are reported as
//!         unsupported rather than walked). The trailer's `/Root` is resolved through the table to
//!         the catalog, and the catalog's `/Pages` to the page tree, so page counts and page sizes
//!         come out of the objects rather than the dictionary text.

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

/// The family name beside the code, kept next to the constants so a caller that has to label what it
/// found does not keep its own copy of the table.
pub fn name() -> &'static str {
    match kind() {
        FORMAT_TAR => "tar",
        FORMAT_AR => "ar",
        FORMAT_RIFF => "riff",
        FORMAT_TIFF => "tiff",
        FORMAT_BMFF => "iso-base-media",
        FORMAT_EBML => "ebml",
        FORMAT_PDF => "pdf",
        FORMAT_NETPBM => "netpbm",
        FORMAT_ASF => "asf",
        FORMAT_FLV => "flv",
        FORMAT_CAB => "cab",
        FORMAT_DEB => "deb",
        FORMAT_TS => "mpegts",
        FORMAT_WASM => "wasm",
        FORMAT_TTF => "ttf",
        FORMAT_WOFF => "woff",
        FORMAT_ICNS => "icns",
        FORMAT_BPLIST => "bplist",
        _ => "unknown",
    }
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
/// rows with the offsets they claim, the object references in the trailer dictionary, and the page
/// tree reached through them. PDF 1.5 xref and object streams are recognised and reported as
/// unsupported rather than guessed at, because their offsets live in a compressed stream this
/// reader does not decode.
fn read_pdf(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 64 || &bytes[0..5] != b"%PDF-" {
        return None;
    }
    let version = String::from_utf8_lossy(bytes.get(5..8)?).into_owned();
    let mut entries = vec![format!("pdf\t{version}")];
    let mut offsets: Vec<(i64, i64)> = Vec::new();
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
            if entries.len() >= 4096 {
                entries.push("truncated\trows".to_owned());
                break 'table;
            }
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
                offsets.push((first + index, row_offset));
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
    let mut refs: Vec<(String, i64)> = Vec::new();
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
                        if refs.len() < 64 {
                            refs.push((name.clone(), number));
                        }
                        scan = at + 1;
                    }
                    None => scan = after,
                }
            }
            _ => scan += 1,
        }
    }
    // Each trailer reference is followed through the table: the row's offset has to land on an
    // object header that repeats that object number, which is what makes the resolved page tree
    // below more than a text search for the word `/MediaBox`.
    let mut root = None;
    for (name, number) in &refs {
        let resolved = object_offset(bytes, &offsets, *number);
        let mut matches = 0i64;
        if let Some(at) = resolved {
            let head: &[u8] = match bytes.get(at..) {
                Some(rest) => &rest[..rest.len().min(12)],
                None => b"",
            };
            let label = format!("{number} ");
            let open = find(bytes, at, b" obj").is_some_and(|pos| pos - at <= 12);
            matches = i64::from(String::from_utf8_lossy(head).starts_with(&label) && open);
        }
        entries.push(format!(
            "resolves\t{name}\t{number}\t{}\t{matches}",
            resolved.map_or(-1, |at| at as i64)
        ));
        if name == "Root" && matches == 1 {
            root = Some(*number);
        }
    }
    // From here on every step is optional: a file whose trailer points at nothing still said true
    // things about its header, its table and its references, so the walk stops and the rows already
    // collected are returned rather than dropping the identification.
    let Some(catalog) = root else {
        return Some(entries);
    };
    let Some(catalog_at) = object_offset(bytes, &offsets, catalog) else {
        return Some(entries);
    };
    let Some(catalog_span) = dict_span(bytes, catalog_at) else {
        return Some(entries);
    };
    let pages = dict_ref(bytes, catalog_span, b"/Pages");
    entries.push(format!(
        "catalog\t{catalog}\tpages\t{}",
        pages.unwrap_or(-1)
    ));
    let Some(pages) = pages else {
        return Some(entries);
    };
    let Some(pages_at) = object_offset(bytes, &offsets, pages) else {
        return Some(entries);
    };
    let Some(pages_span) = dict_span(bytes, pages_at) else {
        return Some(entries);
    };
    let kids = array_refs(bytes, pages_span, b"/Kids").unwrap_or_default();
    entries.push(format!(
        "pages\t{pages}\tcount\t{}\tkids\t{}",
        dict_number(bytes, pages_span, b"/Count").unwrap_or(-1),
        kids.len()
    ));
    let mut tree = PdfTree {
        rows: Vec::new(),
        leaves: 0,
        visited: 0,
        truncated: false,
    };
    for kid in &kids {
        walk_pages(bytes, &offsets, *kid, 1, &mut tree);
    }
    entries.append(&mut tree.rows);
    entries.push(format!(
        "leaves\t{}\tvisited\t{}\ttruncated\t{}",
        tree.leaves,
        tree.visited,
        i64::from(tree.truncated)
    ));
    Some(entries)
}

/// Where the page-tree walk stands: how many leaves it turned into `page` rows, how many objects it
/// opened, and whether either cap was hit.
struct PdfTree {
    rows: Vec<String>,
    leaves: i64,
    visited: i64,
    truncated: bool,
}

const PDF_NODES: i64 = 1024;
const PDF_ROWS: usize = 4096;
const PDF_DEPTH: i32 = 32;

/// A node is a page when its dictionary has no `/Kids`: `/Kids` is what makes a node a branch of
/// the tree, and leaves are the only objects that carry a `/MediaBox` worth reporting.
fn walk_pages(bytes: &[u8], offsets: &[(i64, i64)], object: i64, depth: i32, tree: &mut PdfTree) {
    if tree.visited >= PDF_NODES || tree.rows.len() >= PDF_ROWS {
        tree.truncated = true;
        return;
    }
    tree.visited += 1;
    let Some(at) = object_offset(bytes, offsets, object) else {
        tree.rows.push(format!("unresolved\t{object}"));
        return;
    };
    let Some(span) = dict_span(bytes, at) else {
        tree.rows.push(format!("unresolved\t{object}"));
        return;
    };
    let Some(kids) = array_refs(bytes, span, b"/Kids") else {
        let (width, height) = media_size(bytes, span);
        tree.rows.push(format!(
            "page\t{object}\tmedia\t{}\t{}",
            points(width),
            points(height)
        ));
        tree.leaves += 1;
        return;
    };
    if depth > PDF_DEPTH {
        tree.truncated = true;
        return;
    }
    tree.rows
        .push(format!("branch\t{object}\tkids\t{}", kids.len()));
    for kid in &kids {
        walk_pages(bytes, offsets, *kid, depth + 1, tree);
    }
}

/// Byte offset a live cross-reference row claims for `object`, when the row exists and the offset it
/// names is inside the file.
fn object_offset(bytes: &[u8], offsets: &[(i64, i64)], object: i64) -> Option<usize> {
    offsets
        .iter()
        .find(|(listed, _)| *listed == object)
        .and_then(|(_, at)| usize::try_from(*at).ok())
        .filter(|at| *at < bytes.len())
}

/// The balanced `<< ... >>` that starts at or after `at`, as the byte range including both markers.
/// Delimiters inside literal strings are not skipped, so a dictionary whose text contains `>>`
/// closes early; that is why the page rows are only trusted once `resolves` says 1.
fn dict_span(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let start = find(bytes, at, b"<<")?;
    let mut depth = 0i32;
    let mut scan = start;
    while scan + 1 < bytes.len() {
        if bytes[scan] == b'<' && bytes[scan + 1] == b'<' {
            depth += 1;
            scan += 2;
        } else if bytes[scan] == b'>' && bytes[scan + 1] == b'>' {
            depth -= 1;
            if depth == 0 {
                return Some((start, scan + 2));
            }
            scan += 2;
        } else {
            scan += 1;
        }
    }
    None
}

/// Index just past `key` inside the dictionary, where the key is followed by a delimiter so that
/// `/Count` cannot match the tail of `/CountX`.
fn key_at(bytes: &[u8], span: (usize, usize), key: &[u8]) -> Option<usize> {
    let mut from = span.0;
    while from < span.1 {
        let pos = find_in(bytes, from, span.1, key)?;
        let after = pos + key.len();
        if after >= span.1
            || matches!(
                bytes[after],
                b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'<' | b'>' | b'[' | b']' | b'('
            )
        {
            return Some(after);
        }
        from = pos + 1;
    }
    None
}

/// `number generation R` at `at`, as the referenced object number and the index past the `R`.
fn reference_at(bytes: &[u8], span: (usize, usize), at: usize) -> Option<(i64, usize)> {
    let (number, after) = digits(bytes, skip_white(bytes, at)?)?;
    let (_generation, after) = digits(bytes, skip_white(bytes, after)?)?;
    let at = skip_white(bytes, after)?;
    if at >= span.1 || bytes[at] != b'R' {
        return None;
    }
    Some((number, at + 1))
}

fn dict_ref(bytes: &[u8], span: (usize, usize), key: &[u8]) -> Option<i64> {
    let at = key_at(bytes, span, key)?;
    reference_at(bytes, span, at).map(|(number, _)| number)
}

fn dict_number(bytes: &[u8], span: (usize, usize), key: &[u8]) -> Option<i64> {
    let at = key_at(bytes, span, key)?;
    let (value, _) = digits(bytes, skip_white(bytes, at)?)?;
    Some(value)
}

/// The object numbers listed in a `[/n g R ...]` array value, or `None` when the key has no array.
fn array_refs(bytes: &[u8], span: (usize, usize), key: &[u8]) -> Option<Vec<i64>> {
    let at = key_at(bytes, span, key)?;
    let open = find_in(bytes, at, span.1, b"[")?;
    let close = find_in(bytes, open + 1, span.1, b"]").unwrap_or(span.1);
    let inner = (open + 1, close);
    let mut refs = Vec::new();
    let mut scan = open + 1;
    while scan < close && refs.len() < 4096 {
        match reference_at(bytes, inner, scan) {
            Some((number, next)) => {
                refs.push(number);
                scan = next;
            }
            None => scan += 1,
        }
    }
    Some(refs)
}

/// Width and height in points: the last two numbers of `/MediaBox` minus the first two, because a
/// box does not have to start at the origin.
fn media_size(bytes: &[u8], span: (usize, usize)) -> (Option<f64>, Option<f64>) {
    let miss = (None, None);
    let Some(at) = key_at(bytes, span, b"/MediaBox") else {
        return miss;
    };
    let Some(open) = find_in(bytes, at, span.1, b"[") else {
        return miss;
    };
    let close = find_in(bytes, open + 1, span.1, b"]").unwrap_or(span.1);
    let mut numbers = [0f64; 4];
    let mut taken = 0usize;
    let mut scan = open + 1;
    let mut guard = 0usize;
    while scan < close && taken < 4 && guard < 4096 {
        guard += 1;
        match number_token(bytes, scan, close) {
            Some((value, next)) => {
                numbers[taken] = value;
                taken += 1;
                scan = next;
            }
            None => scan += 1,
        }
    }
    if taken != 4 {
        return miss;
    }
    (Some(numbers[2] - numbers[0]), Some(numbers[3] - numbers[1]))
}

/// A signed decimal token, which is how a page size is written when it is not whole.
fn number_token(bytes: &[u8], at: usize, stop: usize) -> Option<(f64, usize)> {
    let mut end = at;
    if end < stop && matches!(bytes[end], b'-' | b'+') {
        end += 1;
    }
    let digits_from = end;
    while end < stop && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end < stop && bytes[end] == b'.' {
        end += 1;
        while end < stop && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end == digits_from {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes[at..end]);
    text.parse::<f64>().ok().map(|value| (value, end))
}

/// A point measure as the file wrote it, or a dash for a page the file gave no box for.
fn points(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |number| number.to_string())
}

/// Index of the first occurrence of `needle` at or after `from`.
fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    find_in(bytes, from, bytes.len(), needle)
}

/// `find` limited to `[from, stop)`, so a dictionary lookup cannot walk the rest of the file.
fn find_in(bytes: &[u8], from: usize, stop: usize, needle: &[u8]) -> Option<usize> {
    let stop = stop.min(bytes.len());
    if from >= stop || needle.is_empty() || stop - from < needle.len() {
        return None;
    }
    bytes[from..stop]
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
    let folders = i64::from(file.u16(26)?);
    let files = i64::from(file.u16(28)?);
    let flags = i64::from(file.u16(30)?);
    let set_id = i64::from(file.u16(32)?);
    let index = i64::from(file.u16(34)?);
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
        let folder = i64::from(file.u16(at + 8)?);
        let date = i64::from(file.u16(at + 12)?);
        let time = i64::from(file.u16(at + 14)?);
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

pub const FORMAT_DEB: i32 = 23;

/// Debian binary package: an ar archive holding the three mandated members. The listing comes from
/// `read_ar`, so what this adds is the check that this archive has the package shape - the version
/// record first, then a control tarball and a data tarball - and nothing beyond the member names,
/// sizes and modes the shared walk already reports.
fn read_deb(bytes: &[u8]) -> Option<Vec<String>> {
    let members = read_ar(bytes)?;
    let names: Vec<&str> = members
        .iter()
        .filter_map(|line| line.split('\t').next())
        .collect();
    if names.first() != Some(&"debian-binary") {
        return None;
    }
    let control = *names.iter().find(|name| name.starts_with("control.tar"))?;
    let data = *names.iter().find(|name| name.starts_with("data.tar"))?;
    let mut entries = vec![
        format!("deb\t{}", members.len()),
        format!("control\t{control}"),
        format!("data\t{data}"),
    ];
    for line in &members {
        entries.push(format!("member\t{line}"));
    }
    Some(entries)
}

/// MPEG-2 transport stream: 188-byte packets, and the PAT/PMT sections that name the elementary
/// streams inside them. 25, because 1..23 are the containers above and 24 is Layer II in `audio.rs`.
pub const FORMAT_TS: i32 = 25;

const TS_PACKET: usize = 188;
const TS_PIDS: usize = 32;
const TS_PROGRAMS: usize = 16;
const TS_STREAMS: usize = 32;

fn ts_pid(packet: &[u8]) -> i64 {
    i64::from(packet[1] & 0x1f) << 8 | i64::from(packet[2])
}

/// A 13-bit PID carried in the low bits of two bytes.
fn ts_u16_pid(packet: &[u8], at: usize) -> i64 {
    i64::from(packet[at] & 0x1f) << 8 | i64::from(packet[at + 1])
}

/// Where a packet's payload starts, honouring the adaptation field; `None` when there is none.
fn ts_payload(packet: &[u8]) -> Option<usize> {
    let control = (packet[3] >> 4) & 3;
    if control & 1 == 0 {
        return None;
    }
    if control & 2 == 0 {
        return Some(4);
    }
    let length = usize::from(*packet.get(4)?);
    let start = 5 + length;
    if start >= TS_PACKET {
        None
    } else {
        Some(start)
    }
}

/// The table a payload-unit-start packet begins, as its offset in the packet and the offset where
/// that section's CRC starts. `section_length` counts the bytes after its own field, CRC included.
/// A section that does not fit in the packet is counted as partial and skipped: stitching tables
/// across packets needs the whole stream buffered, and half a section decoded is worse than none.
fn ts_section(packet: &[u8], partial: &mut i64) -> Option<(usize, usize)> {
    let start = ts_payload(packet)?;
    let pointer = usize::from(*packet.get(start)?);
    let table = start + 1 + pointer;
    if table + 3 >= TS_PACKET {
        *partial += 1;
        return None;
    }
    let length = i64::from(packet[table + 1] & 0x0f) << 8 | i64::from(packet[table + 2]);
    let end = table + 3 + length as usize;
    if length < 9 || end > TS_PACKET {
        *partial += 1;
        return None;
    }
    Some((table, end - 4))
}

/// One PAT section, as a row per program naming the PID its PMT arrives on. A stream repeats the
/// same table every few packets, so a mapping already listed is not listed twice.
fn ts_pat(
    packet: &[u8],
    table: usize,
    crc_end: usize,
    rows: &mut Vec<String>,
    listed: &mut Vec<(i64, i64)>,
) {
    let stream_id = i64::from(packet[table + 3]) << 8 | i64::from(packet[table + 4]);
    let mut entry = table + 8;
    while entry + 4 <= crc_end && listed.len() < TS_PROGRAMS {
        let number = i64::from(packet[entry] & 0x7f) << 8 | i64::from(packet[entry + 1]);
        let named = ts_u16_pid(packet, entry + 2);
        // A program number of zero is the network entry: it points at a NIT, not at a service, so it
        // is keyed as -1 and never counted as a program.
        let key = if number == 0 {
            (-1, named)
        } else {
            (number, named)
        };
        if !listed.contains(&key) {
            listed.push(key);
            if number == 0 {
                rows.push(format!("nit\t{stream_id}\t{named}"));
            } else {
                rows.push(format!("pat\t{stream_id}\t{number}\t{named}"));
            }
        }
        entry += 4;
    }
}

/// One PMT section: the PCR PID it names, then a row per elementary stream. A version already
/// mapped is a repeat of the same table; a version bump is different content and is reported.
fn ts_pmt(
    packet: &[u8],
    table: usize,
    crc_end: usize,
    rows: &mut Vec<String>,
    mapped: &mut Vec<(i64, i64)>,
    streams: &mut Vec<(i64, i64, i64)>,
) {
    let program = i64::from(packet[table + 3] & 0x1f) << 8 | i64::from(packet[table + 4]);
    let version = i64::from((packet[table + 5] >> 1) & 31);
    if mapped.contains(&(program, version)) {
        return;
    }
    mapped.push((program, version));
    let pcr = ts_u16_pid(packet, table + 8);
    let info = usize::from(packet[table + 10] & 0x0f) << 8 | usize::from(packet[table + 11]);
    // A program_info_length that runs past the section ends the table rather than failing the file.
    let mut stream = table.saturating_add(12 + info).min(crc_end).max(table + 12);
    let mut found = 0i64;
    while stream + 5 <= crc_end && streams.len() < TS_STREAMS {
        let kind = i64::from(packet[stream]);
        let elementary = ts_u16_pid(packet, stream + 1);
        let descriptors =
            usize::from(packet[stream + 3] & 0x0f) << 8 | usize::from(packet[stream + 4]);
        if !streams.contains(&(program, kind, elementary)) {
            streams.push((program, kind, elementary));
            rows.push(format!("es\t{program}\t{kind:#x}\t{elementary}"));
            found += 1;
        }
        stream = stream.saturating_add(5 + descriptors).max(stream + 1);
    }
    rows.push(format!("pmt\t{program}\t{version}\t{pcr}\t{found}"));
}

/// MPEG-2 transport stream: the packet grid is checked stride by stride, then the program map is
/// followed from the PAT to the PMTs, so the elementary streams come out of the tables rather than
/// from a census of PIDs.
fn read_ts(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < TS_PACKET * 2 || bytes[0] != 0x47 || bytes[TS_PACKET] != 0x47 {
        return None;
    }
    let mut packets = 0i64;
    let mut bad_sync = 0i64;
    let mut pusi = 0i64;
    let mut cc_gaps = 0i64;
    let mut partial = 0i64;
    let mut pids: Vec<(i64, i64)> = Vec::new();
    let mut counters: Vec<(i64, i64)> = Vec::new();
    let mut programs: Vec<(i64, i64)> = Vec::new();
    let mut mapped: Vec<(i64, i64)> = Vec::new();
    let mut streams: Vec<(i64, i64, i64)> = Vec::new();
    let mut tables: Vec<String> = Vec::new();
    let mut at = 0usize;
    while at + TS_PACKET <= bytes.len() && packets < 200_000 {
        let packet = &bytes[at..at + TS_PACKET];
        packets += 1;
        if packet[0] != 0x47 {
            bad_sync += 1;
            at += TS_PACKET;
            continue;
        }
        let pid = ts_pid(packet);
        if packet[1] & 0x40 != 0 {
            pusi += 1;
            if let Some((table, crc_end)) = ts_section(packet, &mut partial) {
                match packet[table] {
                    0x00 => ts_pat(packet, table, crc_end, &mut tables, &mut programs),
                    0x02 => ts_pmt(
                        packet,
                        table,
                        crc_end,
                        &mut tables,
                        &mut mapped,
                        &mut streams,
                    ),
                    _ => {}
                }
            }
        }
        let counter = i64::from(packet[3] & 0x0f);
        // Locate first, mutate second: an `iter_mut` borrow would still be held by the arm that
        // pushes, and pushing on a miss is the whole point of the lookup.
        match counters.iter().position(|(known, _)| *known == pid) {
            Some(index) => {
                if (counter - counters[index].1).rem_euclid(16) != 1 {
                    cc_gaps += 1;
                }
                counters[index].1 = counter;
            }
            None => counters.push((pid, counter)),
        }
        match pids.iter().position(|(known, _)| *known == pid) {
            Some(index) => pids[index].1 += 1,
            None if pids.len() < TS_PIDS => pids.push((pid, 1)),
            None => {}
        }
        at += TS_PACKET;
    }
    let mut entries = vec![format!("ts\t{TS_PACKET}\t{packets}\t{bad_sync}")];
    entries.extend(tables);
    for (pid, seen) in &pids {
        entries.push(format!("pid\t{pid}\t{seen}"));
    }
    entries.push(format!("pusi\t{pusi}\tcc_gaps\t{cc_gaps}"));
    entries.push(format!("trailer_bytes\t{}", bytes.len() - at));
    entries.push(format!("partial_sections\t{partial}"));
    if at == bytes.len() {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// WebAssembly modules: the section directory, the counts inside each vector-headed section, and
/// the custom-section names. 26, following the transport stream at 25.
pub const FORMAT_WASM: i32 = 26;

/// An unsigned LEB128, as the value and the number of bytes it took. Six bytes is the limit because
/// a seventh would shift past the 32 bits this format uses for these fields.
fn uleb(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    let mut taken = 0usize;
    loop {
        let byte = *bytes.get(at + taken)?;
        value |= i64::from(byte & 0x7f) << shift;
        taken += 1;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, taken));
        }
        if taken >= 6 {
            return None;
        }
    }
}

/// The name a custom section carries, and where its payload starts.
fn wasm_custom_name(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let (length, taken) = uleb(bytes, at)?;
    let start = at + taken;
    let end = start + usize::try_from(length).ok()?;
    if end > bytes.len() {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes[start..end]).into_owned();
    Some((text, end))
}

fn wasm_section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        _ => "unknown",
    }
}

/// A module is a version, then sections of `id u8` + `size u32(LEB)` + that many bytes. Every vector
/// headed section opens with an entry count, and the function/code pair is the check that the walk
/// is on the real section boundaries rather than merely adding up.
fn read_wasm(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 12 || &bytes[0..4] != b"\x00asm" {
        return None;
    }
    let version = i64::from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    let mut rows: Vec<String> = Vec::new();
    let mut counts: Vec<(&'static str, i64)> = Vec::new();
    let mut customs: Vec<String> = Vec::new();
    let mut sections = 0i64;
    let mut unknown = 0i64;
    let mut truncated = 0i64;
    let mut at = 8usize;
    while at < bytes.len() {
        let id = bytes[at];
        let Some((size, taken)) = uleb(bytes, at + 1) else {
            truncated = 1;
            break;
        };
        let body = at + 1 + taken;
        let Ok(span) = usize::try_from(size) else {
            truncated = 1;
            break;
        };
        if body + span > bytes.len() {
            truncated = 1;
            break;
        }
        let name = wasm_section_name(id);
        rows.push(format!("section\t{name}\t{size}\t{body}"));
        sections += 1;
        if name == "unknown" {
            unknown += 1;
        }
        let counted = match id {
            1 => Some("types"),
            2 => Some("imports"),
            3 => Some("functions"),
            4 => Some("tables"),
            5 => Some("memories"),
            6 => Some("globals"),
            7 => Some("exports"),
            9 => Some("elements"),
            10 => Some("code_bodies"),
            11 => Some("data_segments"),
            12 => Some("data_count"),
            _ => None,
        };
        if let Some(key) = counted {
            if let Some((value, _)) = uleb(bytes, body) {
                counts.push((key, value));
            }
        } else if id == 0 && customs.len() < 16 {
            if let Some((text, _)) = wasm_custom_name(bytes, body) {
                customs.push(format!("custom\t{text}\t{size}"));
            }
        }
        at = body + span;
    }
    let mut entries = vec![format!("wasm\t{version}\t{sections}\t{unknown}")];
    entries.extend(rows);
    for (key, value) in &counts {
        entries.push(format!("{key}\t{value}"));
    }
    let functions = counts.iter().find(|(key, _)| *key == "functions");
    let bodies = counts.iter().find(|(key, _)| *key == "code_bodies");
    if let (Some((_, listed)), Some((_, coded))) = (functions, bodies) {
        entries.push(format!(
            "code_matches_functions\t{}",
            i64::from(listed == coded)
        ));
    }
    entries.extend(customs);
    entries.push(format!("truncated\t{truncated}"));
    if at == bytes.len() {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// sfnt-based outlines (TrueType) and the WOFF wrapper around them. 27 and 28, following the
/// WebAssembly module at 26.
pub const FORMAT_TTF: i32 = 27;
pub const FORMAT_WOFF: i32 = 28;

const FONT_TABLES: usize = 128;

fn be_u16(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at + 2)?;
    Some(i64::from(u16::from_be_bytes([part[0], part[1]])))
}

fn be_i16(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at + 2)?;
    Some(i16::from_be_bytes([part[0], part[1]]) as i64)
}

fn be_u32_at(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at + 4)?;
    Some(i64::from(u32::from_be_bytes([
        part[0], part[1], part[2], part[3],
    ])))
}

/// The sfnt table directory: `version(4) numTables(2) searchRange entryRange rangeShift`, then
/// 16 bytes per table (`tag checksum offset length`). Offset 0 of a table is where its own fields
/// start, which is how `head`, `maxp` and `hhea` are read without guessing at positions.
fn read_sfnt(bytes: &[u8]) -> Option<Vec<String>> {
    let version = match bytes.get(0..4)? {
        [0x00, 0x01, 0x00, 0x00] => "1.0",
        b"true" => "true",
        b"OTTO" => "OTTO",
        _ => return None,
    };
    if bytes.len() < 12 {
        return None;
    }
    let number = be_u16(bytes, 4)?;
    if number > FONT_TABLES as i64 {
        return None;
    }
    let mut entries = vec![format!("sfnt\t{version}\t{number}\t0")];
    let directory_end = 12 + 16 * number as usize;
    if directory_end > bytes.len() {
        entries[0] = format!("sfnt\t{version}\t{number}\t1");
        return Some(entries);
    }
    let mut found: Vec<(&'static str, usize)> = Vec::new();
    let mut highest = 0usize;
    for index in 0..number as usize {
        let record = 12 + 16 * index;
        let tag = match bytes.get(record..record + 4) {
            Some(four) => match std::str::from_utf8(four) {
                Ok(text) => text.to_owned(),
                Err(_) => "?".to_owned(),
            },
            None => break,
        };
        let Some(offset) = be_u32_at(bytes, record + 8) else {
            continue;
        };
        let Some(length) = be_u32_at(bytes, record + 12) else {
            continue;
        };
        let Ok(at) = usize::try_from(offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(length) else {
            continue;
        };
        entries.push(format!("table\t{tag}\t{offset}\t{length}"));
        if let Some(end) = at.checked_add(size) {
            highest = highest.max(end.min(bytes.len()));
        }
        // Four tables carry the numbers worth naming, and only when they are present at all: a font
        // with no `head` is broken, and saying nothing beats inventing a unit size.
        for name in ["head", "maxp", "hhea", "name"] {
            if tag == name && !found.iter().any(|(seen, _)| *seen == name) {
                found.push((name, at));
            }
        }
    }
    for (name, at) in &found {
        match *name {
            "head" => {
                if let Some(units) = be_u16(bytes, at + 18) {
                    entries.push(format!("units_per_em\t{units}"));
                }
            }
            "maxp" => {
                if let Some(glyphs) = be_u16(bytes, at + 4) {
                    entries.push(format!("num_glyphs\t{glyphs}"));
                }
            }
            "hhea" => {
                if let (Some(asc), Some(desc)) = (be_i16(bytes, at + 4), be_i16(bytes, at + 6)) {
                    entries.push(format!("ascender\t{asc}\tdescender\t{desc}"));
                }
            }
            "name" => {
                if let Some(records) = be_u16(bytes, at + 2) {
                    entries.push(format!("name_records\t{records}"));
                }
            }
            _ => {}
        }
    }
    entries.push(format!(
        "tables_end\t{highest}\tuncovered\t{}",
        bytes.len().saturating_sub(highest)
    ));
    Some(entries)
}

/// WOFF wraps an sfnt: the same table tags, but each entry carries a compressed length next to its
/// original one, and `totalSfntSize` says how big the uncompressed sfnt was.
fn read_woff(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 44 || &bytes[0..4] != b"wOFF" {
        return None;
    }
    let flavor = match bytes.get(4..8) {
        Some([0x00, 0x01, 0x00, 0x00]) => "1.0",
        Some(b"OTTO") => "OTTO",
        _ => return None,
    };
    let declared = be_u32_at(bytes, 8)?;
    let number = be_u16(bytes, 12)?;
    let total = be_u32_at(bytes, 16)?;
    if number > FONT_TABLES as i64 {
        return None;
    }
    let mut entries = vec![format!(
        "woff\t{flavor}\t{declared}\t{}\t{number}\t{total}",
        bytes.len()
    )];
    let mut compressed = 0i64;
    let mut original = 0i64;
    let mut highest = 0usize;
    for index in 0..number as usize {
        let record = 44 + 20 * index;
        if record + 20 > bytes.len() {
            entries.push(format!("truncated\t{index}"));
            return Some(entries);
        }
        let tag = String::from_utf8_lossy(&bytes[record..record + 4]).into_owned();
        let Some(offset) = be_u32_at(bytes, record + 4) else {
            continue;
        };
        let Some(comp) = be_u32_at(bytes, record + 8) else {
            continue;
        };
        let Some(orig) = be_u32_at(bytes, record + 12) else {
            continue;
        };
        entries.push(format!("table\t{tag}\t{offset}\t{comp}\t{orig}"));
        compressed += comp;
        original += orig;
        if let (Ok(at), Ok(size)) = (usize::try_from(offset), usize::try_from(comp)) {
            highest = highest.max(at.saturating_add(size).min(bytes.len()));
        }
    }
    entries.push(format!(
        "compressed_bytes\t{compressed}\toriginal_bytes\t{original}"
    ));
    entries.push(format!(
        "tables_end\t{highest}\tuncovered\t{}",
        bytes.len().saturating_sub(highest)
    ));
    Some(entries)
}

/// Apple icon files: the icon directory, and the pixel size of every PNG payload read out of that
/// payload's own header. 30, after the fonts at 27 and 28.
pub const FORMAT_ICNS: i32 = 30;
pub const FORMAT_BPLIST: i32 = 31;

const ICNS_ENTRIES: usize = 128;

/// How far a plist walk is allowed to go: table entries decoded, references read out of one object,
/// report rows emitted, and graph depth. A file that asks for more gets a `stopped` row instead of
/// an unbounded loop.
const BPLIST_OBJECTS: usize = 4096;
const BPLIST_SLOTS: u64 = 4096;
const BPLIST_ROWS: usize = 4096;
const BPLIST_DEPTH: usize = 32;
/// 2001-01-01, the day binary plists count seconds from, expressed in days since 1970-01-01.
const BPLIST_EPOCH_DAYS: i64 = 11_323;

/// Icon entries are `tag(4) length(4, including these eight bytes)`, and the length of the last one
/// decides whether the file was walked to its end. Older icon types carry JPEG-2000 rather than PNG,
/// which this reader classes as `other` instead of guessing at a box signature it has not seen.
fn read_icns(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 || &bytes[0..4] != b"icns" {
        return None;
    }
    let declared = be_u32_at(bytes, 4)?;
    let mut at = 8usize;
    let mut count = 0i64;
    let mut broken = 0i64;
    let mut toc = 0i64;
    let mut rows: Vec<String> = Vec::new();
    while at + 8 <= bytes.len() && (count as usize) < ICNS_ENTRIES {
        let tag = String::from_utf8_lossy(bytes.get(at..at + 4)?).into_owned();
        let Some(size) = be_u32_at(bytes, at + 4) else {
            broken += 1;
            break;
        };
        let Ok(span) = usize::try_from(size) else {
            broken += 1;
            break;
        };
        if span < 8 || at + span > bytes.len() {
            broken += 1;
            break;
        }
        let payload = bytes.get(at + 8..at + span).unwrap_or(bytes);
        let kind = if payload.starts_with(b"\x89PNG\r\n\x1a\n") {
            "png"
        } else {
            "other"
        };
        rows.push(format!("icon\t{tag}\t{span}\t{kind}"));
        if kind == "png" {
            if let (Some(width), Some(height)) = (be_u32_at(payload, 16), be_u32_at(payload, 20)) {
                rows.push(format!("px\t{tag}\t{width}\t{height}"));
            }
        } else if tag == "TOC " {
            toc = ((span - 8) / 8) as i64;
        }
        count += 1;
        at += span;
    }
    let mut entries = vec![format!(
        "icns\t{declared}\t{}\t{count}\t{broken}",
        bytes.len()
    )];
    entries.extend(rows);
    entries.push(format!("toc_lists\t{toc}"));
    entries.push(format!(
        "entries_end\t{at}\tuncovered\t{}",
        bytes.len().saturating_sub(at)
    ));
    if at == bytes.len() {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// Big-endian unsigned integer of 1..=8 bytes, the only width a binary plist trailer, offset table
/// or object reference is allowed to use.
fn be_uint(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    if width == 0 || width > 8 {
        return None;
    }
    let body = bytes.get(at..at.checked_add(width)?)?;
    let mut value = 0u64;
    for byte in body {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

fn be_f32(bytes: &[u8], at: usize) -> Option<f64> {
    let quad: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(f64::from(f32::from_be_bytes(quad)))
}

fn be_f64(bytes: &[u8], at: usize) -> Option<f64> {
    let octet: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(f64::from_be_bytes(octet))
}

/// Days since 1970-01-01 to (year, month, day) - the branch-free civil-from-days conversion that
/// date libraries ship. `tools/plist-sim.py` formats the same instants through python's calendar and
/// both are checked against the same fixture dates, so an error here fails a test instead of
/// quietly reporting a plausible wrong date.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days.saturating_add(719_468);
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_based = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_based + 2) / 5 + 1;
    let month = if march_based < 10 {
        march_based + 3
    } else {
        march_based - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Tab and C0/C1 control characters would break the report's own columns and a lone surrogate has
/// no encoding at all, so both become `?`. Everything else - including the non-ASCII text the
/// fixture carries - passes through: a reader that shows a string shows the string.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c == '\t' || c.is_control() { '?' } else { c })
        .collect()
}

fn utf16_be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let mut out = String::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let next = units.get(index + 1).copied();
        let pair =
            next.filter(|low| (0xD800..0xDC00).contains(&unit) && (0xDC00..0xE000).contains(low));
        let value = match pair {
            Some(low) => {
                Some(0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00))
            }
            None => Some(u32::from(unit)),
        };
        out.push(value.and_then(char::from_u32).unwrap_or('?'));
        index += 1 + usize::from(pair.is_some());
    }
    out
}

/// A counted object: the length or element count is the low nibble, or - when that nibble is 0xF -
/// an integer object written inline straight after the marker, which is not a table entry of its
/// own. Returns the count and the offset the payload or the references start at.
fn bp_count(bytes: &[u8], at: usize, low: u8) -> Option<(u64, usize)> {
    if low != 0xF {
        return Some((u64::from(low), at.checked_add(1)?));
    }
    let int_marker = *bytes.get(at.checked_add(1)?)?;
    if int_marker >> 4 != 1 {
        return None;
    }
    let width = 1usize << (int_marker & 0xF);
    let value = be_uint(bytes, at + 2, width)?;
    Some((value, at + 2 + width))
}

/// An object that holds references: which marker class it is (`dict` says keys-then-values), the
/// count it claims, and the references this reader accepted out of that count.
struct BpNode {
    dict: bool,
    count: u64,
    refs: Vec<(u64, usize)>,
}

struct BpWalk {
    reachable: i64,
    depth: usize,
    cycles: i64,
}

/// The walk from the top object. An object reached twice is sharing, which KeyedArchiver graphs do
/// constantly; only a reference back to something already on this path is a cycle.
fn walk_bp(
    index: usize,
    depth: usize,
    nodes: &[Option<BpNode>],
    seen: &mut [bool],
    path: &mut Vec<usize>,
    walk: &mut BpWalk,
) {
    if path.contains(&index) {
        walk.cycles += 1;
        return;
    }
    if depth > walk.depth {
        walk.depth = depth;
    }
    if seen.get(index).copied().unwrap_or(true) {
        return;
    }
    seen[index] = true;
    walk.reachable += 1;
    if depth >= BPLIST_DEPTH {
        return;
    }
    path.push(index);
    if let Some(node) = nodes.get(index).and_then(|slot| slot.as_ref()) {
        for (_, reference) in &node.refs {
            walk_bp(*reference, depth + 1, nodes, seen, path, walk);
        }
    }
    path.pop();
}

/// One object header decoded into report rows, plus its references when it holds any. Anything the
/// bytes do not support - a count that runs past the object area, an integer width the format does
/// not have, a 0xF nibble not followed by an integer - becomes a `bad` row naming what stopped it,
/// never a guessed value.
fn bp_object(
    bytes: &[u8],
    at: usize,
    row: &str,
    ref_size: usize,
    objects: u64,
    body_end: usize,
    table_len: usize,
) -> (Vec<String>, Option<BpNode>) {
    let Some(marker) = bytes.get(at).copied() else {
        return (vec![format!("{row}\tbad\toffset")], None);
    };
    let high = marker >> 4;
    let low = marker & 0xF;
    match high {
        0 => {
            let body = match low {
                0x0 => format!("{row}\tnull"),
                0x8 => format!("{row}\tbool\tfalse"),
                0x9 => format!("{row}\tbool\ttrue"),
                0xF => format!("{row}\tfiller"),
                _ => format!("{row}\tmarker\t0x{marker:02x}"),
            };
            (vec![body], None)
        }
        1 => {
            let width = 1usize << low;
            if width > 8 {
                return (vec![format!("{row}\tbad\twidth")], None);
            }
            let body = match be_uint(bytes, at + 1, width) {
                // Only the full eight-byte integer is signed, which is how a negative number
                // written by one comes back out of another's bytes.
                Some(raw) if width == 8 && raw >= 1 << 63 => {
                    format!("{row}\tint\t{}\t{width}", raw as i64)
                }
                Some(raw) => format!("{row}\tint\t{raw}\t{width}"),
                None => format!("{row}\tbad\tshort"),
            };
            (vec![body], None)
        }
        2 | 3 => {
            let width = 1usize << low;
            if width != 4 && width != 8 {
                return (vec![format!("{row}\tbad\twidth")], None);
            }
            let number = if width == 4 {
                be_f32(bytes, at + 1)
            } else {
                be_f64(bytes, at + 1)
            };
            let Some(number) = number else {
                return (vec![format!("{row}\tbad\tshort")], None);
            };
            let body = if high == 2 {
                format!("{row}\treal\t{number}")
            } else if !number.is_finite() {
                format!("{row}\tdate\t{number}")
            } else {
                let total = number.floor() as i64;
                let seconds = total.rem_euclid(86_400);
                let days = total.div_euclid(86_400) + BPLIST_EPOCH_DAYS;
                let (year, month, day) = civil_from_days(days);
                if !(1_600..=2_400).contains(&year) {
                    format!("{row}\tdate\t{number}")
                } else {
                    format!(
                        "{row}\tdate\t{year:04}-{month:02}-{day:02}\t{:02}:{:02}:{:02}",
                        seconds / 3_600,
                        (seconds / 60) % 60,
                        seconds % 60
                    )
                }
            };
            (vec![body], None)
        }
        4 | 5 | 6 => match bp_count(bytes, at, low) {
            None => (vec![format!("{row}\tbad\tcount")], None),
            Some((claim, after)) => {
                let unit = 1 + usize::from(high == 6);
                let body = match claim
                    .checked_mul(unit as u64)
                    .and_then(|span| usize::try_from(span).ok())
                    .and_then(|span| after.checked_add(span))
                    .filter(|end| *end <= body_end)
                {
                    None => format!("{row}\tbad\tshort"),
                    Some(end) => {
                        let payload = bytes.get(after..end).unwrap_or_default();
                        match high {
                            4 => {
                                let hint = if payload.starts_with(b"\x89PNG\r\n\x1a\n") {
                                    "png"
                                } else if payload.starts_with(b"\xff\xd8\xff") {
                                    "jpeg"
                                } else {
                                    "bytes"
                                };
                                format!("{row}\tdata\t{claim}\t{hint}")
                            }
                            5 => {
                                let latin: String =
                                    payload.iter().map(|byte| *byte as char).collect();
                                format!("{row}\tascii\t{claim}\t{}", printable(&latin))
                            }
                            _ => {
                                format!("{row}\tutf16\t{claim}\t{}", printable(&utf16_be(payload)))
                            }
                        }
                    }
                };
                (vec![body], None)
            }
        },
        8 => {
            let width = usize::from(low) + 1;
            let body = match be_uint(bytes, at + 1, width) {
                Some(value) => format!("{row}\tuid\t{value}"),
                None => format!("{row}\tbad\tshort"),
            };
            (vec![body], None)
        }
        0xA | 0xD => match bp_count(bytes, at, low) {
            None => (vec![format!("{row}\tbad\tcount")], None),
            Some((count, after)) => {
                let dict = high == 0xD;
                let kind = if dict { "dict" } else { "array" };
                let width = if low == 0xF { "wide" } else { "narrow" };
                let mut rows = vec![format!("{row}\t{kind}\t{count}\t{width}")];
                let slots = count.saturating_mul(u64::from(dict) + 1);
                if slots > BPLIST_SLOTS || after > body_end {
                    return (rows, None);
                }
                let mut refs = Vec::new();
                let mut broken = 0i64;
                for slot in 0..slots {
                    let position =
                        after.saturating_add(slot.saturating_mul(ref_size as u64) as usize);
                    match be_uint(bytes, position, ref_size) {
                        // Both bounds matter: the reference has to name an object the file claims
                        // to hold, and one this reader actually decoded an offset for.
                        Some(value) if value < objects => match usize::try_from(value) {
                            Ok(target) if target < table_len => refs.push((slot, target)),
                            _ => broken += 1,
                        },
                        _ => broken += 1,
                    }
                }
                if broken > 0 {
                    rows.push(format!("{row}\tbad\trefs\t{broken}"));
                }
                (rows, Some(BpNode { dict, count, refs }))
            }
        },
        _ => (vec![format!("{row}\tmarker\t0x{marker:02x}")], None),
    }
}

/// Apple binary property lists: the trailer, the offset table it points at, every object that table
/// addresses, and the reference graph between them.
///
/// 31, after the icon directory at 30. The layout is the one `scripts/make-plist-fixtures.py` writes
/// with CPython's own writer and this reads back byte for byte: an eight-byte `bplist00` magic, then
/// the objects, then `num` big-endian offsets each `offset_size` bytes (trailer byte 6), then the
/// 32-byte trailer carrying `num`, the top object number and the offset-table position. Inside an
/// object, references are `object_ref_size` (trailer byte 7) wide - a different number, which is why
/// both are reported before anything is walked. Integers are `1 << low nibble` bytes and signed only
/// at the full eight; UIDs are `low nibble + 1`; strings count characters while data counts bytes;
/// and a 0xF nibble means the real count follows as an inline integer object.
///
/// Sets and ordered sets (markers 0xB and 0xC) have no fixture here because no writer on this host
/// produces them, so the reader reports their marker byte without naming them - the same rule the
/// WebAssembly reader follows for a section id the specification does not define.
fn read_bplist(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 40 || &bytes[0..8] != b"bplist00" {
        return None;
    }
    let trailer_start = bytes.len() - 32;
    let trailer = bytes.get(trailer_start..)?;
    let offset_size = usize::from(trailer[6]);
    let ref_size = usize::from(trailer[7]);
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return None;
    }
    let objects = be_uint(trailer, 8, 8)?;
    let top = be_uint(trailer, 16, 8)?;
    let table_at = be_uint(trailer, 24, 8)?;
    let table_end = table_at.saturating_add(objects.saturating_mul(offset_size as u64));
    let declared = table_end.saturating_add(32);
    let mut entries = vec![
        format!("bplist\t{declared}\t{}\t{objects}\t{top}", bytes.len()),
        format!("trailer\t{offset_size}\t{ref_size}\t{table_at}\t{table_end}"),
    ];

    let wanted = objects.min(BPLIST_OBJECTS as u64) as usize;
    let mut offsets: Vec<Option<usize>> = Vec::with_capacity(wanted);
    let mut bad_offsets = 0i64;
    for index in 0..wanted {
        let position = table_at.saturating_add((index as u64).saturating_mul(offset_size as u64));
        let slot = usize::try_from(position)
            .ok()
            .and_then(|position| be_uint(bytes, position, offset_size))
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value >= 8 && *value < trailer_start);
        if slot.is_none() {
            bad_offsets += 1;
        }
        offsets.push(slot);
    }
    let increasing = offsets.windows(2).all(|pair| match (pair[0], pair[1]) {
        (Some(left), Some(right)) => right > left,
        _ => true,
    });

    let mut nodes: Vec<Option<BpNode>> = (0..wanted).map(|_| None).collect();
    let mut edges = Vec::new();
    let mut emitted = 0i64;
    let mut unresolved = 0i64;
    let mut stopped = false;
    for (index, slot) in offsets.iter().enumerate() {
        if entries.len() >= BPLIST_ROWS {
            stopped = true;
            break;
        }
        let row = format!("obj\t{index}");
        let Some(at) = slot else {
            entries.push(format!("{row}\tbad\toffset"));
            continue;
        };
        let (rows, node) = bp_object(bytes, *at, &row, ref_size, objects, trailer_start, wanted);
        entries.extend(rows);
        let Some(node) = node else { continue };
        for (slot, reference) in &node.refs {
            if edges.len() >= BPLIST_ROWS {
                stopped = true;
                break;
            }
            if offsets.get(*reference).and_then(|value| *value).is_none() {
                unresolved += 1;
                continue;
            }
            let role = if !node.dict {
                "element"
            } else if *slot < node.count {
                "key"
            } else {
                "value"
            };
            edges.push(format!("child\t{index}\t{slot}\t{reference}\t{role}"));
            emitted += 1;
        }
        nodes[index] = Some(node);
    }
    entries.extend(edges);
    entries.push(format!("edges\t{emitted}\tunresolved\t{unresolved}"));

    let mut walk = BpWalk {
        reachable: 0,
        depth: 0,
        cycles: 0,
    };
    let mut seen = vec![false; wanted];
    let mut path: Vec<usize> = Vec::new();
    if usize::try_from(top).is_ok_and(|top| top < wanted) {
        walk_bp(top as usize, 1, &nodes, &mut seen, &mut path, &mut walk);
    }
    let BpWalk {
        reachable,
        depth,
        cycles,
    } = walk;
    entries.push(format!(
        "reach\t{reachable}\tdepth\t{depth}\tcycles\t{cycles}"
    ));
    entries.push(format!(
        "offsets\t{}\tstrictly_increasing\t{}",
        wanted - bad_offsets as usize,
        u8::from(increasing)
    ));
    entries.push(format!("stopped\t{}", u8::from(stopped)));
    if declared == bytes.len() as u64 {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

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
    if let Some(lines) = read_deb(bytes) {
        return accept(FORMAT_DEB, lines);
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
    if let Some(lines) = read_ts(bytes) {
        return accept(FORMAT_TS, lines);
    }
    if let Some(lines) = read_wasm(bytes) {
        return accept(FORMAT_WASM, lines);
    }
    if let Some(lines) = read_sfnt(bytes) {
        return accept(FORMAT_TTF, lines);
    }
    if let Some(lines) = read_woff(bytes) {
        return accept(FORMAT_WOFF, lines);
    }
    if let Some(lines) = read_icns(bytes) {
        return accept(FORMAT_ICNS, lines);
    }
    if let Some(lines) = read_bplist(bytes) {
        return accept(FORMAT_BPLIST, lines);
    }
    reject(
        "not a tar, ar, deb, RIFF, TIFF, EBML, PDF, Netpbm, ASF, FLV, CAB, MPEG-TS, WebAssembly, font, icon or property-list container",
        -2,
    )
}
