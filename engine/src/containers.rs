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
//!   h5    0x89 "HDF" then CR LF SUB LF, one superblock version byte, the widths of every offset
//!         and length, and addresses that sign the structure they point at
//!   arrow no magic in the stream framing: 0xFFFFFFFF continuation, u32le metadata length, a
//!         flatbuffer, then a body whose length only the flatbuffer states; the file framing adds
//!         "ARROW1" at both ends with a Footer behind an int32 length before the trailing magic
//!   npy   0x93 "NUMPY" + two version bytes, then a little-endian header length (u16 in v1, u32
//!         in v2/v3) and a Python dictionary written as text, then the array data
//!   woff2 "wOF2", u32 flavor/length, u16 table count, u32 sfnt size + compressed size, then a
//!         directory of flags + UIntBase128 lengths over one brotli block
//!   jp2   u32 length + FourCC boxes, first box `jP  ` with signature 0x0D0A870A; `ihdr` inside
//!         the `jp2h` superbox lists height before width and sample depth minus one
//!   qoi   "qoif", u32 width, u32 height, u8 channels, u8 colourspace, then one-byte-tagged
//!         chunks and an eight-byte terminator
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
        FORMAT_QOI => "qoi",
        FORMAT_JP2 => "jp2",
        FORMAT_WOFF2 => "woff2",
        FORMAT_NPY => "npy",
        FORMAT_H5 => "h5",
        FORMAT_AVRO => "avro",
        FORMAT_ARROW => "arrow",
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

/// Quick Open Image: the header, and a walk of the chunk stream that accounts for every pixel that
/// header claims. 32, after the property list at 31.
///
/// `qoif`, then width and height as big-endian u32, then two *single* bytes for channels and
/// colourspace. Every byte of the body starts a chunk: `0xFE` RGB (three colour bytes follow),
/// `0xFF` RGBA (four), `0x00..=0x3F` an index into the last 64 pixels, `0x40..=0x7F` a per-channel
/// difference, `0x80..=0xBF` a luma delta, and `0xC0..=0xFD` a run of `(byte & 0x3F) + 1` repeats.
/// Those ranges cover the whole byte, so a stream cannot hold an unknown tag - the only way it can be
/// wrong is its length. Hence the read is an accounting: pixels walked against `width * height`, and
/// whether the walk lands exactly on the eight terminator bytes.
pub const FORMAT_QOI: i32 = 32;

/// How many chunks a walk will classify before it calls the file too big to read here. A run of 62
/// identical pixels is one chunk, so this only binds on images far past what the browser holds.
const QOI_CHUNKS: i64 = 1 << 20;

fn read_qoi(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 22 || !bytes.starts_with(b"qoif") {
        return None;
    }
    let width = be_u32_at(bytes, 4)?;
    let height = be_u32_at(bytes, 8)?;
    let channels = i64::from(bytes[12]);
    let colorspace = i64::from(bytes[13]);
    let claimed = u64::from(width.max(0) as u32).saturating_mul(u64::from(height.max(0) as u32));
    let body = bytes.len() - 8;
    // rgb, argb, index, diff, luma, run - the order the report prints them in.
    let mut kinds = [0i64; 6];
    let mut scan = 14usize;
    let mut walked = 0u64;
    let mut total = 0i64;
    let mut stopped = "none";
    while scan < body {
        if total >= QOI_CHUNKS {
            stopped = "budget";
            break;
        }
        let tag = bytes[scan];
        let (kind, step, count) = match tag {
            0xFE => (0, 4, 1u64),
            0xFF => (1, 5, 1),
            0x00..=0x3F => (2, 1, 1),
            0x40..=0x7F => (3, 1, 1),
            0x80..=0xBF => (4, 2, 1),
            _ => (5, 1, u64::from(tag & 0x3F) + 1),
        };
        if scan.saturating_add(step) > body {
            stopped = "short";
            break;
        }
        kinds[kind] += 1;
        walked = walked.saturating_add(count);
        total += 1;
        scan += step;
    }
    let terminator = bytes
        .get(body..)
        .and_then(|tail| <[u8; 8]>::try_from(tail).ok())
        == Some([0, 0, 0, 0, 0, 0, 0, 1]);
    if walked > claimed && stopped == "none" {
        stopped = "overrun";
    }
    let mut entries = vec![
        format!("qoi\t{width}\t{height}\t{channels}\t{colorspace}"),
        format!(
            "chunks\t{total}\trgb\t{}\targb\t{}\tindex\t{}\tdiff\t{}\tluma\t{}\trun\t{}",
            kinds[0], kinds[1], kinds[2], kinds[3], kinds[4], kinds[5]
        ),
        format!(
            "pixels\t{claimed}\twalked\t{walked}\tterminator\t{}",
            u8::from(terminator)
        ),
        format!("stopped\t{}\t{stopped}", u8::from(stopped != "none")),
    ];
    if stopped == "none" && walked == claimed && terminator {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// JPEG 2000 PCA (the `.jp2` container, not the codestream inside it): the top-level box list, the
/// `jp2h` superbox's children, and the `ihdr`/`colr` fields. 33, after QOI at 32.
///
/// Boxes here are `u32 length + FourCC` with the length including the header, `0` meaning "runs to
/// the end of the file" and `1` meaning "the real length is the big-endian u64 after the tag" - the
/// same big-endian convention every other integer in the format uses. `ihdr` puts **height before
/// width**, which is the reverse of the `Xsiz`/`Ysiz` order the part-1 codestream uses, and it stores
/// sample depth minus one, so the byte that reads 7 is an eight-bit image. Both come out of
/// `scripts/make-jp2-fixtures.py`, where Pillow encodes the file and then decodes it back and agrees
/// on the size and mode. `colr` is read as far as its method and enumerated colourspace number, and
/// that number is printed as a number: the ECSR code list is not something this repo has a fixture
/// for beyond the two values (16 and 17) that openjpeg wrote here.
pub const FORMAT_JP2: i32 = 33;

const JP2_BOXES: usize = 256;
const JP2_CHILDREN: usize = 64;
const JP2_SIGNATURE: [u8; 4] = [0x0D, 0x0A, 0x87, 0x0A];

/// (total length, header bytes, tag) for the box at `at` inside `end`, or None when the length is
/// smaller than its own header or runs past the area it is allowed to occupy.
fn jp2_box(bytes: &[u8], at: usize, end: usize) -> Option<(usize, usize, String)> {
    let first = usize::try_from(be_u32_at(bytes, at)?).ok()?;
    let tag = fourcc(bytes.get(at + 4..at + 8)?);
    let (size, header) = match first {
        0 => (end.checked_sub(at)?, 8),
        1 => (usize::try_from(be_uint(bytes, at + 8, 8)?).ok()?, 16),
        other => (other, 8),
    };
    if size < header || at.checked_add(size)? > end {
        return None;
    }
    Some((size, header, tag))
}

fn read_jp2(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 12 || fourcc(&bytes[4..8]) != "jP  " || bytes[8..12] != JP2_SIGNATURE {
        return None;
    }
    let mut rows = Vec::new();
    let mut geometry = Vec::new();
    let mut at = 0usize;
    let mut boxes = 0i64;
    let mut broken = 0i64;
    let mut declared = 0i64;
    while at < bytes.len() && (boxes as usize) < JP2_BOXES {
        let Some((size, header, tag)) = jp2_box(bytes, at, bytes.len()) else {
            broken += 1;
            break;
        };
        rows.push(format!("box\t{tag}\t{size}\t{at}"));
        declared += size as i64;
        boxes += 1;
        if tag == "jp2h" {
            let limit = at + size;
            let mut inner = at + header;
            let mut seen = 0usize;
            while inner < limit && seen < JP2_CHILDREN {
                let Some((inner_size, inner_header, child)) = jp2_box(bytes, inner, limit) else {
                    broken += 1;
                    break;
                };
                rows.push(format!("child\t{child}\t{inner_size}\t{inner}"));
                seen += 1;
                let body = bytes
                    .get(inner + inner_header..inner + inner_size)
                    .unwrap_or_default();
                if child == "ihdr" && body.len() >= 14 {
                    if let (Some(height), Some(width), Some(components)) =
                        (be_u32_at(body, 0), be_u32_at(body, 4), be_u16(body, 8))
                    {
                        geometry.push(format!(
                            "ihdr\t{height}\t{width}\t{components}\t{}\tfilter\t{}",
                            i64::from(body[10]) + 1,
                            body[11]
                        ));
                    }
                }
                if child == "colr" && body.len() >= 3 {
                    let method = body[0];
                    if method == 1 && body.len() >= 7 {
                        if let Some(ecsr) = be_u32_at(body, 3) {
                            geometry.push(format!("colr\t{method}\t{ecsr}"));
                        }
                    } else {
                        geometry.push(format!("colr\t{method}"));
                    }
                }
                inner += inner_size;
            }
        }
        at += size;
    }
    let mut entries = vec![format!(
        "jp2\t{declared}\t{}\t{boxes}\t{broken}",
        bytes.len()
    )];
    entries.append(&mut rows);
    entries.append(&mut geometry);
    if broken == 0 && at == bytes.len() {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// WOFF2: the header, the table directory, and where the compressed block ends. 34, after JP2 at 33.
///
/// Unlike WOFF (28), which stores each table separately and may compress each one, WOFF2 keeps a
/// *directory of lengths* and one brotli block for all of them - so the read here is the directory,
/// and the decompression is deliberately not attempted (no brotli in a dependency-free crate). The
/// directory entries are `flags` (six bits of table name, two bits of transform version), an optional
/// literal tag when those six bits say 63, then `origLength` and - only for `glyf` and `loca` at
/// version 0 - `transformLength`, all lengths as UIntBase128.
///
/// The 63-entry name table below is not recited from memory: `scripts/make-woff2-fixture.py` dumps
/// fontTools' own `woff2KnownTags`, and `engine/tests/woff2.rs` compares the two. The fixture also
/// carries the witness that matters more than any table - every untransformed `origLength` equals the
/// length that same table has in `test/fixtures/tiny.ttf`, the font this file was made from, so a
/// directory walked with the wrong widths could not agree with it.
pub const FORMAT_WOFF2: i32 = 34;

const WOFF2_TABLES: usize = 256;

/// Index = tag, exactly as fontTools lists them; the probe next to the fixture is the copy this came
/// from, and the test fails if the two drift apart.
pub const WOFF2_KNOWN_TAGS: [&str; 63] = [
    "cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post", "cvt ", "fpgm", "glyf", "loca",
    "prep", "CFF ", "VORG", "EBDT", "EBLC", "gasp", "hdmx", "kern", "LTSH", "PCLT", "VDMX", "vhea",
    "vmtx", "BASE", "GDEF", "GPOS", "GSUB", "EBSC", "JSTF", "MATH", "CBDT", "CBLC", "COLR", "CPAL",
    "SVG ", "sbix", "acnt", "avar", "bdat", "bloc", "bsln", "cvar", "fdsc", "feat", "fmtx", "fvar",
    "gvar", "hsty", "just", "lcar", "mort", "morx", "opbd", "prop", "trak", "Zapf", "Silf", "Glat",
    "Gloc", "Feat", "Sill",
];

const WOFF2_UNKNOWN_TAG: u8 = 63;

/// UIntBase128: big-endian septets, the high bit meaning "another byte follows". The format allows
/// five, so a fifth continuation bit is a broken directory, not a bigger number.
fn u128(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut cursor = at;
    for _ in 0..5 {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
    }
    None
}

fn read_woff2(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 48 || !bytes.starts_with(b"wOF2") {
        return None;
    }
    let flavor = be_u32_at(bytes, 4)?;
    let declared = be_u32_at(bytes, 8)?;
    let tables = be_u16(bytes, 12)?;
    let reserved = be_u16(bytes, 14)?;
    let total_sfnt = be_u32_at(bytes, 16)?;
    let compressed = be_u32_at(bytes, 20)?;
    let major = be_u16(bytes, 24)?;
    let minor = be_u16(bytes, 26)?;
    let mut entries = vec![
        format!("woff2\t{declared}\t{}\t{tables}\t{reserved}", bytes.len()),
        format!("flavor\t{flavor:x}\tsfnt\t{total_sfnt}"),
        format!("header\t{major}\t{minor}\tcompressed\t{compressed}"),
        format!(
            "areas\t{}\t{}\t{}\t{}\t{}",
            be_u32_at(bytes, 28)?,
            be_u32_at(bytes, 32)?,
            be_u32_at(bytes, 36)?,
            be_u32_at(bytes, 40)?,
            be_u32_at(bytes, 44)?
        ),
    ];
    let mut at = 48usize;
    let mut walked = 0i64;
    let mut broken = 0i64;
    for index in 0..tables.min(WOFF2_TABLES as i64) {
        let Some(flags) = bytes.get(at).copied() else {
            broken += 1;
            break;
        };
        at += 1;
        let slot = flags & 0x3F;
        let version = flags >> 6;
        let tag = if slot == WOFF2_UNKNOWN_TAG {
            let Some(end) = at.checked_add(4) else {
                broken += 1;
                break;
            };
            match bytes.get(at..end) {
                Some(raw) => {
                    at = end;
                    fourcc(raw)
                }
                None => {
                    broken += 1;
                    break;
                }
            }
        } else {
            WOFF2_KNOWN_TAGS[usize::from(slot)].to_owned()
        };
        let Some((original, after)) = u128(bytes, at) else {
            broken += 1;
            break;
        };
        at = after;
        // Only glyf and loca carry a second length, and only at version 0 (their transformed form).
        let transformed = if (tag == "glyf" || tag == "loca") && version == 0 {
            match u128(bytes, at) {
                Some((value, after)) => {
                    at = after;
                    i64::try_from(value).unwrap_or(i64::MAX)
                }
                None => {
                    broken += 1;
                    -1
                }
            }
        } else {
            -1
        };
        entries.push(format!(
            "table\t{index}\t{tag}\t{original}\t{transformed}\t{version}"
        ));
        walked += 1;
    }
    if tables > WOFF2_TABLES as i64 {
        broken += 1;
    }
    let data_end = at as i64 + compressed;
    let padded = data_end.saturating_add(3) & !3;
    entries.push(format!(
        "directory\t{at}\tread\t{walked}\tbroken\t{broken}\tdata_end\t{data_end}\tpadding\t{}",
        padded - data_end
    ));
    if broken == 0 && declared == bytes.len() as i64 && padded == bytes.len() as i64 {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// NumPy arrays: the signature, the header dictionary, and the arithmetic that says the data area is
/// the array the header describes. 35, after WOFF2 at 34.
///
/// `\x93NUMPY` + two version bytes, then the header length as a little-endian u16 in version 1 and a
/// u32 in versions 2 and 3 - a difference that is easy to get wrong and that both `v2.npy` and
/// `f64.npy` in the fixtures pin. The header is a Python dictionary written as text; only its three
/// keys are read here, by matching brackets rather than by evaluating anything, so a structured
/// descr (`[('alpha', '<f4'), ...]`) survives as the text the file holds.
///
/// The item size is not in the file: it is spelled by the descr, and the product of that and the
/// shape has to equal the bytes after the header. `scripts/make-npy-fixtures.py` records numpy's own
/// `itemsize` and `nbytes` beside each fixture, so the numbers below are the library's, not this
/// reader's. Where the descr is a field list the size is left unknown rather than computed - one
/// of the two fixtures has an item size of 13 that only alignment rules could justify.
pub const FORMAT_NPY: i32 = 35;

const NPY_MAGIC: [u8; 6] = [0x93, b'N', b'U', b'M', b'P', b'Y'];

/// The text of one dictionary entry: quoted bodies unwrapped, bracketed bodies taken to their match.
fn npy_value(header: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let at = find(header, 0, key)?.checked_add(key.len())?;
    let mut rest = header.get(at..)?;
    while matches!(rest.first(), Some(&b' ') | Some(&b'\t')) {
        rest = rest.get(1..)?;
    }
    let open = *rest.first()?;
    if open == b'[' || open == b'(' {
        let close = if open == b'[' { b']' } else { b')' };
        let mut depth = 0usize;
        for (index, byte) in rest.iter().enumerate() {
            if *byte == open {
                depth += 1;
            } else if *byte == close {
                depth -= 1;
                if depth == 0 {
                    let body = rest.get(..=index)?;
                    return Some(if open == b'(' {
                        body.get(1..body.len().saturating_sub(1))?.to_vec()
                    } else {
                        body.to_vec()
                    });
                }
            }
        }
        return None;
    }
    if open == b'\'' {
        let tail = rest.get(1..)?;
        let end = tail.iter().position(|byte| *byte == b'\'')?;
        return Some(tail.get(..end)?.to_vec());
    }
    let end = rest
        .iter()
        .position(|byte| {
            let byte = *byte;
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
        })
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(rest.get(..end)?.to_vec())
}

/// `'<f8'`, `'>i4'`, `'|S4'`, `'<U4'`: a byte-order character, a kind character, then a width in
/// bytes - except Unicode, whose width counts characters of four bytes each. Anything else (a field
/// list, a subarray, a padding count) has no size computed here.
fn npy_itemsize(descr: &str) -> Option<u64> {
    let bytes = descr.as_bytes();
    if bytes.len() < 3 || !matches!(bytes[0], b'<' | b'>' | b'|' | b'=') {
        return None;
    }
    let digits = descr.get(2..)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let width: u64 = digits.parse().ok()?;
    Some(if bytes[1] == b'U' { width * 4 } else { width })
}

fn read_npy(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 10 || !bytes.starts_with(&NPY_MAGIC) {
        return None;
    }
    let major = bytes[6];
    let minor = bytes[7];
    if !matches!(major, 1 | 2 | 3) {
        return None;
    }
    // Version 1 keeps the header length in a u16, versions 2 and 3 in a u32 - and the header starts
    // right after it, so the two differ by more than one number.
    let length = if major == 1 {
        i64::from(Le(bytes).u16(8)?)
    } else {
        Le(bytes).u32(8)?
    };
    let header_len = usize::try_from(length.max(0)).ok()?;
    let header_at: usize = if major == 1 { 10 } else { 12 };
    let header_end = header_at.checked_add(header_len)?;
    // numpy pads the header with spaces and ends it with a newline, so the dictionary's own closing
    // brace is not the last byte of the area - trim to it before checking anything else.
    let raw = bytes.get(header_at..header_end)?;
    let mut stop = raw.len();
    while stop > 0 && matches!(raw[stop - 1], b' ' | b'\n' | b'\r' | b'\t') {
        stop -= 1;
    }
    let header = raw.get(..stop)?;
    if header_len < 3 || !header.starts_with(b"{") || !header.ends_with(b"}") {
        return None;
    }
    let descr = npy_value(header, b"'descr':")?;
    let order = npy_value(header, b"'fortran_order':")?;
    let shape = npy_value(header, b"'shape':")?;
    let mut dims: Vec<u64> = Vec::new();
    for part in shape.split(|byte| *byte == b',') {
        let trimmed: Vec<u8> = part.iter().copied().filter(|byte| *byte != b' ').collect();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.iter().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        dims.push(String::from_utf8_lossy(&trimmed).parse().unwrap_or(0));
    }
    let elements = dims.iter().product::<u64>();
    let available = (bytes.len() - header_end) as u64;
    let text = String::from_utf8_lossy(&descr).into_owned();
    let mut entries = vec![
        format!("npy\t{major}\t{minor}\t{header_len}\t{header_end}"),
        format!("dtype\t{}", printable(&text)),
        dims.iter()
            .fold(format!("shape\t{}", dims.len()), |row, dim| {
                format!("{row}\t{dim}")
            }),
        format!(
            "fortran_order\t{}",
            if order.as_slice() == b"True".as_slice() {
                "true"
            } else {
                "false"
            }
        ),
    ];
    let size = npy_itemsize(&text);
    let expects = size.map(|each| each.saturating_mul(elements));
    entries.push(match expects {
        Some(wanted) => format!(
            "sizes\t{}\telements\t{elements}\texpects\t{wanted}\tavailable\t{available}",
            size.unwrap_or(0)
        ),
        None => format!(
            "sizes\tunknown\telements\t{elements}\texpects\tunknown\tavailable\t{available}"
        ),
    });
    if expects.is_some_and(|wanted| wanted == available) {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// HDF5: the superblock, and the addresses inside it that point at real structures. 36, after npy.
///
/// The file starts with `\x89HDF\r\n\x1a\n`, one superblock version byte, then the widths of every
/// offset and length the file will use: generation 0 keeps those two bytes at 13 and 14, generations
/// 2 and 3 at 9 and 10 - and both fixtures in `test/fixtures` use 8 and 8, so the only thing that
/// distinguishes the two positions is that reading them the other way round yields 0, which is not a
/// width. That is the whole reason the reader branches on the version instead of picking one.
///
/// What follows is deliberately *not* a field-by-field walk of a layout table. HDF5's generations
/// disagree about where things sit, the object-header message kinds are a table this repo cannot
/// verify from these two files, and the traversal below the root group (B-trees, local heaps, link
/// messages) is a larger piece of work - so instead the first 128 bytes are scanned in four-byte
/// steps, and every 64-bit little-endian slot is reported for what it demonstrably is: either the
/// file's own length, or an address whose target begins with four ASCII letters, which is how every
/// HDF5 structure signs itself (`TREE`, `HEAP`, `OHDR`, ...). The names therefore come out of the
/// file, not out of a recollection, and the `eof` row is the check that the header describes this
/// file: the stored end-of-file value has to equal the buffer's length.
pub const FORMAT_H5: i32 = 36;

const H5_SCAN: usize = 128;
const H5_ROWS: usize = 32;

fn read_h5(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 || bytes[1..8] != *b"HDF\r\n\x1a\n" {
        return None;
    }
    let version = bytes[8];
    if version > 3 {
        return None;
    }
    let (offset_size, length_size) = if version == 0 {
        (bytes[13], bytes[14])
    } else {
        (bytes[9], bytes[10])
    };
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&length_size) {
        return None;
    }
    let limit = bytes.len().min(H5_SCAN);
    let mut rows = Vec::new();
    let mut eof = None;
    let mut scanned = 0i64;
    let mut found = 0i64;
    let mut at = 8usize;
    while at + 8 <= limit {
        scanned += 1;
        let value = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        if value == bytes.len() as u64 {
            if eof.is_none() {
                eof = Some(format!("eof\t{at}\t{value}\tfile\t{}", bytes.len()));
                found += 1;
            }
        } else if let Ok(target) = usize::try_from(value) {
            let signed = match target.checked_add(4) {
                Some(end) if target >= 8 && end <= bytes.len() => bytes.get(target..end),
                _ => None,
            };
            if let Some(sign) =
                signed.filter(|area| area.iter().all(|byte| byte.is_ascii_alphabetic()))
            {
                if rows.len() >= H5_ROWS {
                    break;
                }
                rows.push(format!(
                    "addr\t{at}\t{target}\tsig\t{}",
                    String::from_utf8_lossy(sign)
                ));
                found += 1;
            }
        }
        at += 4;
    }
    let mut entries = vec![format!(
        "h5\t{version}\t{offset_size}\t{length_size}\t{scanned}\t{found}"
    )];
    let ended = eof.is_some();
    entries.extend(eof);
    entries.append(&mut rows);
    if ended {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// Avro object containers: the metadata map, the synchronisation marker, and the block chain whose
/// record counts have to add up. 37, after HDF5 at 36.
///
/// `Obj\x01`, then a metadata map as zigzag-varint long / byte-string pairs terminated by a zero
/// long, then a 16-byte sync marker, then blocks of `count`, `byte size`, that many bytes of payload
/// and a copy of the sync marker. Every integer here is a variable-length zigzag long, which is why
/// the loop below reads numbers through one bounded helper instead of assuming widths: a block that
/// claims more bytes than the file holds is a broken chain, not a length to trust.
///
/// Nothing is deserialised - the payload bytes are counted, not decoded, and a compressed block is
/// reported with whatever codec name the metadata states rather than inflated. What *is* claimed is
/// the arithmetic: `scripts/make-avro-fixtures.py` asserts that the block counts sum to the number of
/// records fastavro reads back from the same bytes, and `many.avro` is deliberately written with
/// `sync_interval=1000` so that several blocks exist - a one-block file cannot tell a loop from a
/// block that merely happens to end where the file does.
pub const FORMAT_AVRO: i32 = 37;

const AVRO_BLOCKS: usize = 512;
const AVRO_SYNC: usize = 16;

/// Zigzag-encoded variable-length long, at most ten bytes, or None when the file runs out first or
/// the bytes do not fit.
fn avro_long(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    let mut result = 0u64;
    let mut cursor = at;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        let chunk = u64::from(byte & 0x7F).checked_mul(1u64.checked_shl(shift)?)?;
        result = result.checked_add(chunk)?;
        if byte & 0x80 == 0 {
            let signed = ((result >> 1) as i64) ^ -((result & 1) as i64);
            return Some((signed, cursor));
        }
    }
    None
}

/// The first `"name"` key in the schema text, which is the record type's own name: the fields come
/// later in the array, and the writer puts the record's name first.
fn avro_record_name(text: &[u8]) -> Option<String> {
    let needle = b"\"name\"";
    let mut at = find(text, 0, needle)? + needle.len();
    while matches!(text.get(at), Some(b' ') | Some(b'\t') | Some(b'\n')) {
        at += 1;
    }
    if *text.get(at)? != b':' {
        return None;
    }
    at += 1;
    while matches!(text.get(at), Some(b' ') | Some(b'\t') | Some(b'\n')) {
        at += 1;
    }
    if *text.get(at)? != b'"' {
        return None;
    }
    at += 1;
    let end = at + text.get(at..)?.iter().position(|byte| *byte == b'"')?;
    Some(String::from_utf8_lossy(text.get(at..end)?).into_owned())
}

fn read_avro(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 8 || !bytes.starts_with(b"Obj\x01") {
        return None;
    }
    let mut broken = 0i64;
    let mut at = 4usize;
    let Some((pairs, after)) = avro_long(bytes, at) else {
        return None;
    };
    at = after;
    let mut codec = None;
    let mut schema: Option<Vec<u8>> = None;
    let mut listed = 0i64;
    for _ in 0..pairs.max(0) {
        let Some((key_len, after)) = avro_long(bytes, at) else {
            broken += 1;
            break;
        };
        at = after;
        let Ok(len) = usize::try_from(key_len) else {
            broken += 1;
            break;
        };
        let Some(key) = at.checked_add(len).and_then(|end| bytes.get(at..end)) else {
            broken += 1;
            break;
        };
        at += len;
        let Some((value_len, after)) = avro_long(bytes, at) else {
            broken += 1;
            break;
        };
        at = after;
        let Ok(len) = usize::try_from(value_len) else {
            broken += 1;
            break;
        };
        let Some(value) = at.checked_add(len).and_then(|end| bytes.get(at..end)) else {
            broken += 1;
            break;
        };
        at += len;
        listed += 1;
        if key == b"avro.codec".as_slice() {
            codec = Some(String::from_utf8_lossy(value).into_owned());
        }
        if key == b"avro.schema".as_slice() {
            schema = Some(value.to_vec());
        }
    }
    // The map ends with a zero-length block; without it the sync marker would be read from the
    // wrong place and every block offset after it would be nonsense.
    let Some((terminator, after)) = avro_long(bytes, at) else {
        return None;
    };
    at = after;
    if terminator != 0 {
        broken += 1;
    }
    let sync: Vec<u8> = bytes
        .get(at..at.checked_add(AVRO_SYNC)?)
        .unwrap_or_default()
        .to_vec();
    if sync.len() != AVRO_SYNC {
        return None;
    }
    at += AVRO_SYNC;

    let mut rows = Vec::new();
    let mut blocks = 0i64;
    let mut records = 0i64;
    let mut syncs_agree = true;
    while at < bytes.len() {
        if blocks as usize >= AVRO_BLOCKS {
            broken += 1;
            break;
        }
        let Some((count, after)) = avro_long(bytes, at) else {
            broken += 1;
            break;
        };
        at = after;
        let Some((size, after)) = avro_long(bytes, at) else {
            broken += 1;
            break;
        };
        at = after;
        let Ok(len) = usize::try_from(size) else {
            broken += 1;
            break;
        };
        let Some(end) = at
            .checked_add(len)
            .and_then(|end| end.checked_add(AVRO_SYNC))
        else {
            broken += 1;
            break;
        };
        if end > bytes.len() {
            broken += 1;
            break;
        }
        if bytes.get(at + len..end).unwrap_or_default() != sync.as_slice() {
            broken += 1;
            syncs_agree = false;
            rows.push(format!("block\t{blocks}\t{count}\t{len}\tsync\tdiffers"));
            break;
        }
        if count >= 0 {
            records += count;
        }
        rows.push(format!("block\t{blocks}\t{count}\t{len}"));
        blocks += 1;
        at = end;
    }

    let mut entries = vec![format!("avro\t{at}\t{}\t{blocks}\t{broken}", bytes.len())];
    entries.push(format!(
        "metadata\t{listed}\twith_schema\t{}",
        i64::from(schema.is_some())
    ));
    entries.push(format!(
        "codec\t{}",
        codec.unwrap_or_else(|| "absent".to_owned())
    ));
    entries.push(match schema.as_deref() {
        None => "schema\tabsent".to_owned(),
        Some(text) => match avro_record_name(text) {
            Some(name) => format!("schema\t{}\tname\t{}", text.len(), printable(&name)),
            None => format!("schema\t{}\tname\tunknown", text.len()),
        },
    });
    entries.push(format!(
        "sync\t{}\tagrees\t{}",
        sync.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        u8::from(syncs_agree)
    ));
    entries.append(&mut rows);
    entries.push(format!("records\t{records}"));
    if broken == 0 && at == bytes.len() {
        entries.push("walked\tend".to_owned());
    }
    Some(entries)
}

/// Arrow IPC: the encapsulated message envelope, and the flatbuffer fields inside it. 38, after
/// Avro at 37.
///
/// The stream framing carries no magic: an encapsulated message is a `0xFFFFFFFF` continuation, an
/// int32 metadata length, a flatbuffer, and then a body whose length lives *inside* that flatbuffer.
/// Skipping only the metadata therefore desynchronises the walk at the first record batch, which is
/// why the loop below reads `body_length` before it advances. The file framing adds `ARROW1` at both
/// ends and puts a non-encapsulated Footer behind an int32 length; a Footer `Block` indexes a
/// message by its envelope position with a `metaDataLength` that *already* includes the 8-byte
/// prefix, so the body begins at `offset + meta` - treating both numbers as pure metadata sizes lands
/// eight bytes into every body, which is the trap `file.arrow` pins.
///
/// Field access goes through one vtable helper, because flatbuffers omit every field that equals its
/// default: an absent slot is the default, not a zero to read out of the buffer. A `lz4_frame` batch
/// is exactly that case - its codec ordinal is the enum's zero, so the writer emits no field at all
/// and only `zstd` has to appear, which is what fixes the ordering without a table to trust.
///
/// Column types are reported as the discriminator number and never as a name: the fixtures show
/// `int32` and `string` arriving as 2 and 5, and nothing here demonstrates what the rest of that
/// union means. The same rule keeps the header names to the three kinds actually observed.
pub const FORMAT_ARROW: i32 = 38;

const ARROW_ENVELOPE: usize = 8;
const ARROW_MESSAGES: usize = 512;
const ARROW_FIELDS: usize = 64;
const ARROW_BLOCKS: usize = 128;
const ARROW_BLOCK_BYTES: usize = 24;
const ARROW_NODE_BYTES: usize = 16;
const ARROW_MAX_VERSION: i64 = 4;
const ARROW_CONTINUATION: i64 = 0xFFFF_FFFF;

fn arrow_u8(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(*bytes.get(at)?))
}

fn arrow_i16(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(i16::from_le_bytes(
        bytes.get(at..at + 2)?.try_into().unwrap(),
    )))
}

fn arrow_u32(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(u32::from_le_bytes(
        bytes.get(at..at + 4)?.try_into().unwrap(),
    )))
}

fn arrow_i32(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(i32::from_le_bytes(
        bytes.get(at..at + 4)?.try_into().unwrap(),
    )))
}

fn arrow_i64(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(at..at + 8)?.try_into().unwrap(),
    ))
}

fn arrow_index(value: i64) -> Option<usize> {
    usize::try_from(value).ok()
}

/// Position of one field inside a table, or None when the writer left it at its default. The i32 at
/// a table is an offset *backwards* to its vtable, which carries one u16 per numbered slot.
fn arrow_slot(bytes: &[u8], table: usize, want: usize) -> Option<usize> {
    let back = arrow_i32(bytes, table)?;
    let vtable = arrow_index(i64::try_from(table).ok()?.checked_sub(back)?)?;
    let span = arrow_i16(bytes, vtable)?;
    let entry_at = 4usize.checked_add(want.checked_mul(2)?)?;
    if span < 4 || arrow_index(span)? <= entry_at {
        return None;
    }
    let offset = arrow_i16(bytes, vtable.checked_add(entry_at)?)?;
    if offset == 0 {
        return None;
    }
    let at = table.checked_add(arrow_index(offset)?)?;
    (at < bytes.len()).then_some(at)
}

/// A `short` field, or the caller's default when the writer omitted it.
fn arrow_short(bytes: &[u8], table: usize, want: usize, default: i64) -> i64 {
    arrow_slot(bytes, table, want)
        .and_then(|at| arrow_i16(bytes, at))
        .unwrap_or(default)
}

/// A `long` field, or the caller's default when the writer omitted it.
fn arrow_long(bytes: &[u8], table: usize, want: usize, default: i64) -> i64 {
    arrow_slot(bytes, table, want)
        .and_then(|at| arrow_i64(bytes, at))
        .unwrap_or(default)
}

/// A one-byte discriminator or flag, with no default: the caller has to know whether the writer
/// said anything, because a codec of zero is written by *omitting* the field.
fn arrow_mark(bytes: &[u8], table: usize, want: usize) -> Option<i64> {
    arrow_u8(bytes, arrow_slot(bytes, table, want)?)
}

/// Where a string, vector or nested table actually sits.
fn arrow_ref(bytes: &[u8], table: usize, want: usize) -> Option<usize> {
    let at = arrow_slot(bytes, table, want)?;
    let target = at.checked_add(arrow_index(arrow_u32(bytes, at)?)?)?;
    (target < bytes.len()).then_some(target)
}

fn arrow_text(bytes: &[u8], table: usize, want: usize) -> Option<String> {
    let at = arrow_ref(bytes, table, want)?;
    let end = at
        .checked_add(4)?
        .checked_add(arrow_index(arrow_u32(bytes, at)?)?)?;
    Some(printable(&String::from_utf8_lossy(bytes.get(at + 4..end)?)))
}

/// First element and count of a vector whose elements are `element` bytes wide, or None when the
/// claimed span does not fit the buffer.
fn arrow_vec(bytes: &[u8], table: usize, want: usize, element: usize) -> Option<(usize, usize)> {
    let at = arrow_ref(bytes, table, want)?;
    let count = arrow_index(arrow_u32(bytes, at)?)?;
    let first = at.checked_add(4)?;
    let span = count.checked_mul(element)?;
    (first.checked_add(span)? <= bytes.len()).then_some((first, count))
}

struct ArrowMessage {
    at: usize,
    meta: usize,
    version: i64,
    head: i64,
    body: i64,
    header: usize,
}

/// One encapsulated message, inside the region `stop` bounds.
fn arrow_message(bytes: &[u8], at: usize, stop: usize) -> Option<ArrowMessage> {
    let fb = at.checked_add(ARROW_ENVELOPE)?;
    if fb > stop {
        return None;
    }
    if arrow_u32(bytes, at)? != ARROW_CONTINUATION {
        return None;
    }
    let meta = arrow_index(arrow_u32(bytes, at + 4)?)?;
    if meta < ARROW_ENVELOPE || fb.checked_add(meta)? > stop {
        return None;
    }
    let table = fb.checked_add(arrow_index(arrow_u32(bytes, fb)?)?)?;
    if table.checked_add(ARROW_ENVELOPE)? > stop {
        return None;
    }
    Some(ArrowMessage {
        at,
        meta,
        version: arrow_short(bytes, table, 0, -1),
        head: arrow_mark(bytes, table, 1)?,
        body: arrow_long(bytes, table, 3, 0),
        header: arrow_ref(bytes, table, 2)?,
    })
}

struct ArrowFooter {
    start: usize,
    length: usize,
    head: usize,
    table: usize,
}

/// The file framing's tail: a Footer flatbuffer, the int32 that states its size, and the magic -
/// with an unknown amount of padding between the size and the magic, so the position is whichever
/// candidate yields a table carrying an in-range version and the required schema field.
fn arrow_footer(bytes: &[u8]) -> Option<ArrowFooter> {
    let limit = bytes.len();
    if limit < 14 || !bytes.starts_with(b"ARROW1") || bytes[limit - 6..] != *b"ARROW1" {
        return None;
    }
    for pad in 0..8usize {
        let head = limit.checked_sub(10)?.checked_sub(pad)?;
        let length = arrow_index(arrow_u32(bytes, head)?)?;
        if length < ARROW_ENVELOPE {
            continue;
        }
        let start = head.checked_sub(length)?;
        if start < ARROW_ENVELOPE {
            continue;
        }
        let table = start.checked_add(arrow_index(arrow_u32(bytes, start)?)?)?;
        if table.checked_add(ARROW_ENVELOPE)? > limit {
            continue;
        }
        if !(0..=ARROW_MAX_VERSION).contains(&arrow_short(bytes, table, 0, -1)) {
            continue;
        }
        if arrow_ref(bytes, table, 1).is_none() {
            continue;
        }
        return Some(ArrowFooter {
            start,
            length,
            head,
            table,
        });
    }
    None
}

fn read_arrow(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < ARROW_ENVELOPE * 2 {
        return None;
    }
    let signed = bytes.starts_with(b"ARROW1");
    let footer = if signed { arrow_footer(bytes) } else { None };
    if signed != footer.is_some() {
        return None;
    }
    let framing = if footer.is_some() { "file" } else { "stream" };
    let start = if footer.is_some() { ARROW_ENVELOPE } else { 0 };
    let stop = footer.as_ref().map_or(bytes.len(), |tail| tail.start);
    // A stream that does not open with a Schema message is not an Arrow stream, whatever it holds,
    // and that gate is also what keeps a file full of 0xFF padding from reading as one.
    let first = arrow_message(bytes, start, stop)?;
    if first.head != 1 || !(0..=ARROW_MAX_VERSION).contains(&first.version) {
        return None;
    }
    let mut rows = Vec::new();
    let mut at = start;
    let mut msgs = 0usize;
    let mut batches = 0usize;
    let mut dicts = 0usize;
    let mut named = false;
    let mut broken = 0i64;
    let mut eos = false;
    while at < stop {
        let Some(prefix) = at.checked_add(ARROW_ENVELOPE) else {
            broken += 1;
            break;
        };
        if prefix > stop {
            broken += 1;
            break;
        }
        if arrow_u32(bytes, at) == Some(ARROW_CONTINUATION) && arrow_u32(bytes, at + 4) == Some(0) {
            eos = true;
            at = prefix;
            break;
        }
        let Some(message) = arrow_message(bytes, at, stop) else {
            broken += 1;
            break;
        };
        let body = match usize::try_from(message.body) {
            Ok(size) => size,
            Err(_) => {
                broken += 1;
                break;
            }
        };
        let Some(next) = message
            .at
            .checked_add(ARROW_ENVELOPE)
            .and_then(|pos| pos.checked_add(message.meta))
            .and_then(|pos| pos.checked_add(body))
        else {
            broken += 1;
            break;
        };
        rows.push(format!(
            "message\t{msgs}\thead\t{}\tmeta\t{}\tbody\t{}\tversion\t{}",
            match message.head {
                1 => "Schema".to_owned(),
                2 => "DictionaryBatch".to_owned(),
                3 => "RecordBatch".to_owned(),
                other => other.to_string(),
            },
            message.meta,
            message.body,
            message.version
        ));
        match message.head {
            1 => {
                let (first_field, fields) =
                    arrow_vec(bytes, message.header, 1, 4).unwrap_or((0, 0));
                rows.push(format!(
                    "schema\tfields\t{fields}\tendianness\t{}",
                    arrow_short(bytes, message.header, 0, 0)
                ));
                if !named {
                    for i in 0..fields.min(ARROW_FIELDS) {
                        // arrow_vec already bounded the whole vector, so every element position here
                        // is inside the buffer; only the offset each element holds can still lie.
                        let slot = first_field + i * 4;
                        let Some(shift) = arrow_u32(bytes, slot).and_then(arrow_index) else {
                            break;
                        };
                        let Some(field) = slot.checked_add(shift) else {
                            break;
                        };
                        let name = arrow_text(bytes, field, 0).unwrap_or_else(|| "?".to_owned());
                        let nullable = arrow_mark(bytes, field, 1).unwrap_or(0);
                        let kind = arrow_mark(bytes, field, 2).unwrap_or(0);
                        rows.push(format!(
                            "field\t{i}\t{name}\tnullable\t{nullable}\ttype\t{kind}"
                        ));
                    }
                    named = true;
                }
            }
            2 => {
                let id = arrow_long(bytes, message.header, 0, 0);
                let delta = arrow_mark(bytes, message.header, 2).unwrap_or(0);
                let mut line = format!("dict\t{dicts}\tid\t{id}");
                if let Some(data) = arrow_ref(bytes, message.header, 1) {
                    let inner = arrow_long(bytes, data, 0, 0);
                    let buffers = arrow_vec(bytes, data, 2, ARROW_NODE_BYTES).map_or(0, |(_, n)| n);
                    line.push_str(&format!("\trows\t{inner}\tbuffers\t{buffers}"));
                }
                rows.push(format!("{line}\tdelta\t{delta}"));
                dicts += 1;
            }
            3 => {
                let rows_in = arrow_long(bytes, message.header, 0, 0);
                let nodes =
                    arrow_vec(bytes, message.header, 1, ARROW_NODE_BYTES).map_or(0, |(_, n)| n);
                let buffers =
                    arrow_vec(bytes, message.header, 2, ARROW_NODE_BYTES).map_or(0, |(_, n)| n);
                let mut line = format!(
                    "batch\t{batches}\trows\t{rows_in}\tnodes\t{nodes}\tbuffers\t{buffers}"
                );
                if let Some(compression) = arrow_ref(bytes, message.header, 3) {
                    let codec = arrow_mark(bytes, compression, 0).unwrap_or(0);
                    line.push_str(&format!("\tcodec\t{codec}"));
                }
                rows.push(line);
                batches += 1;
            }
            _ => {}
        }
        msgs += 1;
        at = next;
        if msgs >= ARROW_MESSAGES {
            broken += 1;
            break;
        }
    }
    let mut tail_rows = Vec::new();
    if let Some(tail) = footer.as_ref() {
        let (blocks_at, blocks) =
            arrow_vec(bytes, tail.table, 3, ARROW_BLOCK_BYTES).unwrap_or((0, 0));
        let dictionaries = arrow_vec(bytes, tail.table, 2, ARROW_BLOCK_BYTES).map_or(0, |(_, n)| n);
        let padded = if bytes.starts_with(b"ARROW1\0\0") {
            1
        } else {
            0
        };
        tail_rows.push(format!(
            "footer\t{}\tbytes\t{}\tenvelope\t{}\tversion\t{}\tbatches\t{blocks}\tdicts\t{dictionaries}\tmagic\t{padded}",
            tail.start,
            tail.length,
            tail.head,
            arrow_short(bytes, tail.table, 0, -1),
        ));
        for i in 0..blocks.min(ARROW_BLOCKS) {
            let element = blocks_at + i * ARROW_BLOCK_BYTES;
            let offset = arrow_i64(bytes, element).unwrap_or(0);
            let meta = arrow_i64(bytes, element + 8).unwrap_or(0);
            let body = arrow_i64(bytes, element + 16).unwrap_or(0);
            tail_rows.push(format!(
                "block\t{i}\tenvelope\t{offset}\tmeta\t{meta}\tbody\t{body}"
            ));
        }
    }
    let mut entries = vec![format!(
        "arrow\t{}\t{msgs}\t{broken}\tframing\t{framing}",
        bytes.len()
    )];
    entries.append(&mut rows);
    entries.append(&mut tail_rows);
    entries.push(format!("eos\t{}", if eos { 1 } else { 0 }));
    let covered = broken == 0 && footer.map_or(eos && at == bytes.len(), |tail| at == tail.start);
    if covered {
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
    if let Some(lines) = read_qoi(bytes) {
        return accept(FORMAT_QOI, lines);
    }
    if let Some(lines) = read_jp2(bytes) {
        return accept(FORMAT_JP2, lines);
    }
    if let Some(lines) = read_woff2(bytes) {
        return accept(FORMAT_WOFF2, lines);
    }
    if let Some(lines) = read_npy(bytes) {
        return accept(FORMAT_NPY, lines);
    }
    if let Some(lines) = read_h5(bytes) {
        return accept(FORMAT_H5, lines);
    }
    if let Some(lines) = read_avro(bytes) {
        return accept(FORMAT_AVRO, lines);
    }
    if let Some(lines) = read_arrow(bytes) {
        return accept(FORMAT_ARROW, lines);
    }
    reject(
        "not a tar, ar, deb, RIFF, TIFF, EBML, PDF, Netpbm, ASF, FLV, CAB, MPEG-TS, WebAssembly, font, icon, property-list, QOI, WOFF2, JPEG 2000, NumPy array, HDF5, Avro container or Arrow stream",
        -2,
    )
}
