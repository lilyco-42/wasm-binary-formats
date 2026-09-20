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
//!   heif  ISO base-media boxes (`ftyp` brand `heic`) whose `meta` carries the item
//!         inventory; `ispe` is the coded size and `clap` the visible one, which differ
//!   cfb   D0CF11E0A1B11AE1 + a 512-byte header naming the sector size as a shift, a FAT whose own
//!         sector list is the 109-slot DIFAT, 128-byte directory entries, and streams under the
//!         0x1000 cutoff chained through a second FAT inside the root entry's own data
//!   stl   no magic at all: 80 header bytes, u32 triangle count, 50 bytes per triangle, so
//!         84 + 50n == filesize is the only thing the format asserts about itself; a stored normal
//!         is listed as written and counted against the normal the three points imply
//!   emf   a record list where every record is `u32 type, u32 size`, including the first: the header
//!         states the file's byte count at 48 and its signature - " EMF" as a little-endian word - at
//!         40; bounds are device units, frame is the same rectangle in hundredths of a millimetre, and
//!         a pixels/mm pair states the resolution that relates the two - the ratio, not a table, is the
//!         claim, and it holds on both producers' output to within the pixel the extents round apart
//!   icc   u32be total size, and the only signature the format has: the constant "acsp" at 36, past
//!         the header fields it identifies. Big-endian throughout, 12-byte tag records from 132,
//!         each pointing at a payload whose own four-byte type is read from wherever the file says
//!         it is, which is why the table is checked against the length rather than trusted
//!   arrow no magic in the stream framing: 0xFFFFFFFF continuation, u32le metadata length, a
//!         flatbuffer, then a body whose length only the flatbuffer states; the file framing adds
//!         "ARROW1" at both ends with a Footer behind an int32 length before the trailing magic
//!   onnx   one protobuf message: tag varint of field number and wire type, then a varint,
//!         fixed 32/64 slot or a length-delimited region that is a string or a message only
//!         because this schema says so
//!   parquet "PAR1" at both ends, an int32 before the last one giving the size of the Thrift
//!         compact Footer that describes every row group in the file
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
        FORMAT_PARQUET => "parquet",
        FORMAT_ONNX => "onnx",
        FORMAT_HEIF => "heif",
        FORMAT_CFB => "cfb",
        FORMAT_STL => "stl",
        FORMAT_ICC => "icc",
        FORMAT_EMF => "emf",
        _ => "unknown",
    }
}

pub fn count() -> i32 {
    RESULT.with(|slot| slot.borrow().len() as i32)
}

pub fn at(index: i32) -> Option<String> {
    RESULT.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}

/// Endianness-aware field reader, because two families here are big-endian (TIFF and the ISO base
/// media boxes) while the rest are little-endian. One reader rather than a branch at every call site.
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

    fn u64(&self, at: usize) -> Option<i64> {
        if at + 8 > self.bytes.len() {
            return None;
        }
        let octet: [u8; 8] = self.bytes[at..at + 8].try_into().unwrap();
        Some(if self.little {
            u64::from_le_bytes(octet)
        } else {
            u64::from_be_bytes(octet)
        } as i64)
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
        let wide = if header == 16 { "\twide" } else { "" };
        entries.push(format!("box\t{kind}\t{size}\t{cursor}{wide}"));
        boxes += 1;
        let body = cursor + header;
        if kind == "moov" {
            let mut inner = body;
            let limit = cursor.saturating_add(size).min(bytes.len());
            while inner + 8 <= limit {
                let Some((inner_size, inner_header)) = box_extent(bytes, &be, inner) else {
                    break;
                };
                let inner_kind = fourcc(&bytes[inner + 4..inner + 8]);
                let inner_wide = if inner_header == 16 { "\twide" } else { "" };
                entries.push(format!(
                    "child\t{inner_kind}\t{inner_size}\t{inner}{inner_wide}"
                ));
                if inner_kind == "mvhd" {
                    let version = usize::from(bytes[inner + 8]);
                    let (timescale, duration) = if version == 1 {
                        (be.u32(inner + 28)?, be.u64(inner + 32)?)
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
                if inner_size < 8 || inner.saturating_add(inner_size) > limit {
                    break;
                }
                inner += inner_size;
            }
        }
        if size < 8 || cursor.saturating_add(size) > bytes.len() {
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
        // `test/fixtures/wide.mov` is the box this arm reads: 14496-12 puts the 64-bit length where
        // the 32-bit one was, *after* the type, and big-endian like every other integer in the
        // family. Two implementations here agree on that and neither is ours - the pinned Kaitai
        // reader does `len64 - 16` off a `readU8be`, and mutagen unpacks `">Q"` from box + 8. On the
        // fixture's bytes the little-endian reading mutagen computes is 3,458,764,513,820,540,928,
        // which is not a box in a 196-byte file.
        1 => Some((
            usize::try_from(be.u64(at + 8)?.max(0)).unwrap_or(usize::MAX),
            16,
        )),
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

/// Parquet: the Thrift-compact footer, which is the whole file's table of contents. 39, after Arrow
/// at 38.
///
/// A Parquet file is `PAR1`, the row groups, a Footer, an int32 giving the Footer's size, then `PAR1`
/// again - so unlike every other reader in this file the interesting part is read from the end, and it
/// is encoded in Thrift *compact* protocol rather than a bespoke layout: each field is a nibble-pair
/// header holding a delta from the previous field id and the value's type, ids are only recoverable by
/// summing the deltas, a zero byte closes a struct, and lists carry their own size and element type.
/// A field equal to its default is simply absent, so unknown fields have to be skipped *by type* -
/// that is the only behaviour that lets a file written by a newer parquet exist in these bytes without
/// breaking the rest of the walk.
///
/// The codec and physical-type names come from files pyarrow was told to write with those options
/// named (`scripts/make-parquet-fixtures.py` collects the pairs and refuses a value that maps to two
/// names); `ZSTD` turning out to be ordinal 6 rather than 5 is why nothing here is written from
/// memory. An encoding ordinal is never named at all: one file with a dictionary page and one without
/// pin down which ordinal belongs to a dictionary, and no more than that.
pub const FORMAT_PARQUET: i32 = 39;

const PARQUET_MAGIC: &[u8] = b"PAR1";
const PARQUET_DEPTH: usize = 12;
const PARQUET_COLUMNS: usize = 64;
const PARQUET_GROUPS: usize = 64;
const PARQUET_CHUNKS: usize = 128;

/// A byte cursor over a bounded region. Running off the end is a counted failure, never a guess.
struct PqCursor<'a> {
    bytes: &'a [u8],
    at: usize,
    stop: usize,
    bad: i64,
}

impl<'a> PqCursor<'a> {
    fn raw(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        if end > self.stop {
            self.bad += 1;
            return None;
        }
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn varint(&mut self) -> Option<i64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self.raw(1)?.first()?;
            result |= u64::from(byte & 0x7F).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(result as i64);
            }
            shift += 7;
            if shift > 63 {
                self.bad += 1;
                return None;
            }
        }
    }

    /// Zigzag: the compact protocol's only signed integer form.
    fn long(&mut self) -> Option<i64> {
        let raw = self.varint()? as u64;
        Some(((raw >> 1) as i64) ^ -((raw & 1) as i64))
    }

    fn binary(&mut self) -> Option<&'a [u8]> {
        let size = usize::try_from(self.varint()?).ok()?;
        self.raw(size)
    }

    fn list_header(&mut self) -> Option<(usize, u8)> {
        let head = *self.raw(1)?.first()?;
        let mut size = usize::from(head >> 4);
        let element = head & 0x0F;
        if size == 15 {
            size = usize::try_from(self.varint()?).ok()?;
        }
        Some((size, element))
    }

    fn skip(&mut self, kind: u8, depth: usize) {
        match kind {
            1 | 2 => {}
            3 => {
                self.raw(1);
            }
            4 | 5 | 6 => {
                self.varint();
            }
            7 => {
                self.raw(8);
            }
            8 => {
                let size = self.varint().and_then(|n| usize::try_from(n).ok());
                if let Some(size) = size {
                    self.raw(size);
                }
            }
            9 | 10 => {
                if let Some((size, element)) = self.list_header() {
                    for _ in 0..size.min(PARQUET_CHUNKS) {
                        self.skip(element, depth + 1);
                    }
                }
            }
            11 => {
                // A map states its size once and then carries every entry under the key/value types
                // of that header byte. None of parquet's own structures use one, but a footer written
                // by a future writer might.
                let Some(size) = self.varint() else { return };
                let Ok(size) = usize::try_from(size) else {
                    return;
                };
                if size == 0 {
                    return;
                }
                let Some(pair) = self.raw(1) else { return };
                let (key, value) = (pair[0] >> 4, pair[0] & 0x0F);
                for _ in 0..size.min(PARQUET_CHUNKS) {
                    self.skip(key, depth + 1);
                    self.skip(value, depth + 1);
                }
            }
            12 => {
                if depth > PARQUET_DEPTH {
                    self.bad += 1;
                    return;
                }
                loop {
                    let Some(head) = self.raw(1) else { return };
                    let head = head[0];
                    if head == 0 {
                        return;
                    }
                    if head >> 4 == 0 {
                        self.varint();
                    }
                    self.skip(head & 0x0F, depth + 1);
                }
            }
            _ => self.bad += 1,
        }
    }

    /// One struct field header: the delta from the previous id, and the value's type. None at the
    /// closing zero byte or a failed read.
    fn field(&mut self) -> Option<(i64, u8)> {
        let head = *self.raw(1)?.first()?;
        let delta = head >> 4;
        let kind = head & 0x0F;
        if delta == 0 && kind == 0 {
            return None;
        }
        Some((i64::from(delta), kind))
    }
}

/// The ordinals witnessed by the fixtures, and nothing else.
fn pq_codec(ordinal: i64) -> &'static str {
    match ordinal {
        0 => "uncompressed",
        1 => "snappy",
        2 => "gzip",
        6 => "zstd",
        _ => "unnamed",
    }
}

fn pq_physical(ordinal: i64) -> &'static str {
    match ordinal {
        0 => "boolean",
        1 => "int32",
        2 => "int64",
        4 => "float",
        5 => "double",
        6 => "byte_array",
        _ => "unnamed",
    }
}

#[derive(Default)]
struct PqColumn {
    name: String,
    kind: Option<i64>,
    length: Option<i64>,
    repetition: Option<i64>,
    children: Option<i64>,
    converted: Option<i64>,
}

#[derive(Default)]
struct PqStats {
    nulls: i64,
    low: Option<Vec<u8>>,
    high: Option<Vec<u8>>,
}

#[derive(Default)]
struct PqChunk {
    path: String,
    kind: i64,
    codec: i64,
    values: i64,
    uncompressed: i64,
    compressed: i64,
    data_page: Option<i64>,
    dict_page: Option<i64>,
    encodings: Vec<i64>,
    stats: Option<PqStats>,
}

#[derive(Default)]
struct PqGroup {
    rows: i64,
    bytes: i64,
    chunks: Vec<PqChunk>,
}

#[derive(Default)]
struct PqMeta {
    version: i64,
    rows: i64,
    columns: Vec<PqColumn>,
    groups: Vec<PqGroup>,
    created: String,
}

fn pq_text(value: Option<&[u8]>) -> String {
    printable(&String::from_utf8_lossy(value.unwrap_or(b"")))
}

fn read_statistics(cursor: &mut PqCursor<'_>) -> PqStats {
    let mut out = PqStats::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (1, 8) => out.high = cursor.binary().map(|v| v.to_vec()),
            (2, 8) => out.low = cursor.binary().map(|v| v.to_vec()),
            (3, 6) => out.nulls = cursor.long().unwrap_or(0),
            (5, 8) => out.high = cursor.binary().map(|v| v.to_vec()),
            (6, 8) => out.low = cursor.binary().map(|v| v.to_vec()),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            return out;
        }
    }
    out
}

fn read_column_metadata(cursor: &mut PqCursor<'_>) -> PqChunk {
    let mut out = PqChunk::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (1, 4 | 5) => out.kind = cursor.long().unwrap_or(0),
            (4, 4 | 5) => out.codec = cursor.long().unwrap_or(0),
            (5, 6) => out.values = cursor.long().unwrap_or(0),
            (6, 6) => out.uncompressed = cursor.long().unwrap_or(0),
            (7, 6) => out.compressed = cursor.long().unwrap_or(0),
            (9, 6) => out.data_page = cursor.long(),
            (11, 6) => out.dict_page = cursor.long(),
            (2, 9) => {
                if let Some((size, element)) = cursor.list_header() {
                    if !matches!(element, 4 | 5 | 6) {
                        cursor.bad += 1;
                        return out;
                    }
                    for _ in 0..size.min(PARQUET_CHUNKS) {
                        out.encodings.push(cursor.long().unwrap_or(0));
                    }
                }
            }
            (3, 9) => {
                if let Some((size, element)) = cursor.list_header() {
                    if element != 8 {
                        cursor.bad += 1;
                        return out;
                    }
                    let mut parts = Vec::new();
                    for _ in 0..size.min(PARQUET_COLUMNS) {
                        parts.push(pq_text(cursor.binary()));
                    }
                    out.path = parts.join("/");
                }
            }
            (12, 12) => out.stats = Some(read_statistics(cursor)),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            return out;
        }
    }
    out
}

fn read_column_chunk(cursor: &mut PqCursor<'_>) -> PqChunk {
    let mut out = PqChunk::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (3, 12) => out = read_column_metadata(cursor),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            return out;
        }
    }
    out
}

fn read_row_group(cursor: &mut PqCursor<'_>) -> PqGroup {
    let mut out = PqGroup::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (1, 9) => {
                if let Some((size, 12)) = cursor.list_header() {
                    for _ in 0..size.min(PARQUET_CHUNKS) {
                        out.chunks.push(read_column_chunk(cursor));
                    }
                }
            }
            (2, 6) => out.bytes = cursor.long().unwrap_or(0),
            (3, 6) => out.rows = cursor.long().unwrap_or(0),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            return out;
        }
    }
    out
}

fn read_schema_element(cursor: &mut PqCursor<'_>) -> PqColumn {
    let mut out = PqColumn::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (1, 4 | 5) => out.kind = cursor.long(),
            (2, 4 | 5) => out.length = cursor.long(),
            (3, 4 | 5) => out.repetition = cursor.long(),
            (4, 8) => out.name = pq_text(cursor.binary()),
            (5, 4 | 5) => out.children = cursor.long(),
            (6, 4 | 5) => out.converted = cursor.long(),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            return out;
        }
    }
    out
}

fn read_file_metadata(bytes: &[u8], start: usize, stop: usize) -> (PqMeta, usize, i64) {
    let mut cursor = PqCursor {
        bytes,
        at: start,
        stop,
        bad: 0,
    };
    let mut out = PqMeta::default();
    let mut id = 0i64;
    while let Some((delta, kind)) = cursor.field() {
        id = if delta != 0 {
            id + delta
        } else {
            cursor.long().unwrap_or(0)
        };
        match (id, kind) {
            (1, 4 | 5) => out.version = cursor.long().unwrap_or(0),
            (2, 9) => {
                if let Some((size, 12)) = cursor.list_header() {
                    for _ in 0..size.min(PARQUET_COLUMNS) {
                        out.columns.push(read_schema_element(&mut cursor));
                    }
                }
            }
            (3, 6) => out.rows = cursor.long().unwrap_or(0),
            (4, 9) => {
                if let Some((size, 12)) = cursor.list_header() {
                    for _ in 0..size.min(PARQUET_GROUPS) {
                        out.groups.push(read_row_group(&mut cursor));
                    }
                }
            }
            (6, 8) => out.created = pq_text(cursor.binary()),
            _ => cursor.skip(kind, 0),
        }
        if cursor.bad > 0 {
            break;
        }
    }
    (out, cursor.at, cursor.bad)
}

fn pq_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_parquet(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 12 || !bytes.starts_with(PARQUET_MAGIC) || !bytes.ends_with(PARQUET_MAGIC) {
        return None;
    }
    let limit = bytes.len();
    let length = usize::try_from(u32::from_le_bytes(
        bytes.get(limit - 8..limit - 4)?.try_into().ok()?,
    ))
    .ok()?;
    if length < 8 {
        return None;
    }
    let start = limit.checked_sub(8)?.checked_sub(length)?;
    if start < 4 {
        return None;
    }
    let (meta, ended, bad) = read_file_metadata(bytes, start, limit - 8);
    // A footer whose fields all default would carry no information at all; the version and the schema
    // are the two things every writer has to emit.
    if bad > 0 || meta.columns.is_empty() || meta.version > 2 {
        return None;
    }
    let leaves = meta
        .columns
        .iter()
        .filter(|c| c.children.unwrap_or(0) == 0)
        .count();
    let mut rows = vec![format!(
        "parquet\t{limit}\tfooter\t{start}\tbytes\t{length}\tgroups\t{}",
        meta.groups.len()
    )];
    rows.push(format!(
        "version\t{}\trows\t{}\tschema\t{}\tcolumns\t{leaves}",
        meta.version,
        meta.rows,
        meta.columns.len()
    ));
    rows.push(format!("created\t{}", meta.created));
    for (i, column) in meta.columns.iter().enumerate() {
        let mut line = format!("column\t{i}\t{}", column.name);
        if let Some(kind) = column.kind {
            line.push_str(&format!("\ttype\t{kind}\tname\t{}", pq_physical(kind)));
        }
        if let Some(length) = column.length {
            line.push_str(&format!("\tlength\t{length}"));
        }
        if let Some(repetition) = column.repetition {
            line.push_str(&format!("\trep\t{repetition}"));
        }
        if let Some(children) = column.children {
            line.push_str(&format!("\tchildren\t{children}"));
        }
        if let Some(converted) = column.converted {
            line.push_str(&format!("\tconverted\t{converted}"));
        }
        rows.push(line);
    }
    let mut chunks = Vec::new();
    for (i, group) in meta.groups.iter().enumerate() {
        rows.push(format!(
            "group\t{i}\trows\t{}\tbytes\t{}\tcolumns\t{}",
            group.rows,
            group.bytes,
            group.chunks.len()
        ));
        for chunk in &group.chunks {
            chunks.push((i, chunk));
        }
    }
    for (i, (group, chunk)) in chunks.into_iter().take(PARQUET_CHUNKS).enumerate() {
        let encodings: Vec<String> = chunk
            .encodings
            .iter()
            .map(|value| value.to_string())
            .collect();
        let mut line = format!(
            "chunk\t{i}\tpath\t{}\tgroup\t{group}\trows\t{}\ttype\t{}\tname\t{}\tcodec\t{}\tcodec_name\t{}\tuncompressed\t{}\tcompressed\t{}\tencodings\t{}",
            chunk.path,
            chunk.values,
            chunk.kind,
            pq_physical(chunk.kind),
            chunk.codec,
            pq_codec(chunk.codec),
            chunk.uncompressed,
            chunk.compressed,
            encodings.join(","),
        );
        if let Some(page) = chunk.data_page {
            line.push_str(&format!("\tdata\t{page}"));
        }
        if let Some(page) = chunk.dict_page {
            line.push_str(&format!("\tdict\t{page}"));
        }
        rows.push(line);
        if let Some(stats) = chunk.stats.as_ref() {
            rows.push(format!(
                "stats\t{i}\tnull\t{}\tmin\t{}\tmax\t{}",
                stats.nulls,
                pq_hex(stats.low.as_deref().unwrap_or(b"")),
                pq_hex(stats.high.as_deref().unwrap_or(b"")),
            ));
        }
    }
    rows.push(if ended == start + length {
        "walked\tend".to_owned()
    } else {
        format!("stopped\t{ended}\tbad\t{bad}")
    });
    Some(rows)
}

/// ONNX: one protobuf message that describes a model, read level by level. 40, after Parquet at 39.
///
/// An `.onnx` file has no magic and no framing of its own: it is a single `ModelProto` in protobuf
/// wire format, where each field is a tag varint carrying a number and a wire type followed by a value
/// that is a varint, a fixed 32/64-bit slot, or a length-delimited region. That region may be a string
/// or a nested message and *the wire does not say which*, so nothing here can be walked generically -
/// the reader has to know which fields are messages and descend into those alone, which is why the
/// accessors below are one per schema level instead of a generic tree printer.
///
/// The field numbers are the ones the fixtures write, verified in `scripts/make-onnx-fixtures.py`
/// against `onnx`'s own descriptor and by byte-for-byte equality with the sub-messages onnx serializes:
/// `producer_name` is 2 rather than 3, `graph` is 7 rather than 8, and inside a tensor `float_data` is
/// 4, `int32_data` 5 and `string_data` 6 - so a reader written from memory would label an int32 tensor
/// as a float one and never notice. Element-type names are limited to the nine the fixtures witness;
/// every other ordinal prints as a number.
///
/// A shape dimension is `dim_value`, or a named `dim_param`, or *neither*, and the three are reported
/// apart (`d3`, `pN`, `u`): collapsing an unknown axis to a zero would invent a rank that the file does
/// not state.
pub const FORMAT_ONNX: i32 = 40;

const ONNX_ITEMS: usize = 512;

enum PbItem {
    Number(i64),
    Region(usize, usize),
}

/// One protobuf message: its fields in file order, plus where it ended.
struct Pb<'a> {
    bytes: &'a [u8],
    items: Vec<(u32, PbItem)>,
    end: usize,
    bad: i64,
}

fn pb_varint(bytes: &[u8], at: usize, stop: usize) -> Option<(i64, usize)> {
    let mut result = 0u64;
    let mut cursor = at;
    let mut shift = 0u32;
    while cursor < stop {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        result |= u64::from(byte & 0x7F).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((result as i64, cursor));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

impl<'a> Pb<'a> {
    /// An empty message, for a field the file does not carry: its lifetime comes from the caller,
    /// because `&[]` is a slice of any buffer.
    fn empty() -> Pb<'a> {
        Pb {
            bytes: &[],
            items: Vec::new(),
            end: 0,
            bad: 0,
        }
    }

    fn read(bytes: &[u8], start: usize, stop: usize) -> Pb {
        let mut out = Pb {
            bytes,
            items: Vec::new(),
            end: start,
            bad: 0,
        };
        let mut at = start;
        while at < stop {
            let Some((tag, after)) = pb_varint(bytes, at, stop) else {
                out.bad += 1;
                break;
            };
            at = after;
            let field = u32::try_from(tag >> 3).unwrap_or(u32::MAX);
            let wire = tag & 0x07;
            if field == 0 {
                out.bad += 1;
                break;
            }
            match wire {
                0 => match pb_varint(bytes, at, stop) {
                    Some((value, after)) => {
                        at = after;
                        out.items.push((field, PbItem::Number(value)));
                    }
                    None => {
                        out.bad += 1;
                        break;
                    }
                },
                2 => match pb_varint(bytes, at, stop) {
                    Some((size, after)) => {
                        let size = usize::try_from(size).unwrap_or(usize::MAX);
                        let begin = after;
                        let Some(end) = begin.checked_add(size) else {
                            out.bad += 1;
                            break;
                        };
                        if end > stop {
                            out.bad += 1;
                            break;
                        }
                        out.items.push((field, PbItem::Region(begin, end)));
                        at = end;
                    }
                    None => {
                        out.bad += 1;
                        break;
                    }
                },
                5 => {
                    if at + 4 > stop {
                        out.bad += 1;
                        break;
                    }
                    let quad: [u8; 4] = bytes[at..at + 4].try_into().unwrap();
                    out.items
                        .push((field, PbItem::Number(i64::from(u32::from_le_bytes(quad)))));
                    at += 4;
                }
                1 => {
                    if at + 8 > stop {
                        out.bad += 1;
                        break;
                    }
                    let octet: [u8; 8] = bytes[at..at + 8].try_into().unwrap();
                    out.items
                        .push((field, PbItem::Number(u64::from_le_bytes(octet) as i64)));
                    at += 8;
                }
                _ => {
                    // Groups (3 and 4) are obsolete; anything else means the walk has lost its place.
                    out.bad += 1;
                    break;
                }
            }
            if out.items.len() > ONNX_ITEMS {
                out.bad += 1;
                break;
            }
        }
        out.end = at;
        out
    }

    fn numbers(&self, field: u32) -> Vec<i64> {
        self.items
            .iter()
            .filter(|(id, _)| *id == field)
            .filter_map(|(_, item)| match item {
                PbItem::Number(value) => Some(*value),
                PbItem::Region(..) => None,
            })
            .collect()
    }

    fn regions(&self, field: u32) -> Vec<(usize, usize)> {
        self.items
            .iter()
            .filter(|(id, _)| *id == field)
            .filter_map(|(_, item)| match item {
                PbItem::Region(begin, end) => Some((*begin, *end)),
                PbItem::Number(_) => None,
            })
            .collect()
    }

    fn count(&self, field: u32) -> usize {
        self.items.iter().filter(|(id, _)| *id == field).count()
    }

    fn one(&self, field: u32) -> Option<i64> {
        self.numbers(field).first().copied()
    }

    fn one_region(&self, field: u32) -> Option<(usize, usize)> {
        self.regions(field).first().copied()
    }

    fn text(&self, field: u32) -> Option<String> {
        let (begin, end) = self.one_region(field)?;
        Some(printable(&String::from_utf8_lossy(
            self.bytes.get(begin..end)?,
        )))
    }

    fn child(&self, field: u32) -> Option<Pb<'a>> {
        let (begin, end) = self.one_region(field)?;
        Some(Pb::read(self.bytes, begin, end))
    }

    fn children(&self, field: u32) -> Vec<Pb<'a>> {
        self.regions(field)
            .into_iter()
            .take(ONNX_ITEMS)
            .map(|(begin, end)| Pb::read(self.bytes, begin, end))
            .collect()
    }

    /// Every element of a repeated numeric field, whichever of the two legal encodings the writer
    /// used: unpacked values arrive one per tag, packed ones share one region that holds fixed-width
    /// words for `float`/`double` and varints for everything else.
    fn elements(&self, field: u32, width: usize) -> Vec<i64> {
        let mut out = self.numbers(field);
        for (begin, end) in self.regions(field) {
            let Some(blob) = self.bytes.get(begin..end) else {
                continue;
            };
            if width == 0 {
                let mut at = 0usize;
                while let Some((value, after)) = pb_varint(blob, at, blob.len()) {
                    out.push(value);
                    at = after;
                }
            } else {
                let mut at = 0usize;
                while at + width <= blob.len() {
                    if width == 4 {
                        let quad: [u8; 4] = blob[at..at + 4].try_into().unwrap();
                        out.push(i64::from(u32::from_le_bytes(quad)));
                    } else {
                        let octet: [u8; 8] = blob[at..at + 8].try_into().unwrap();
                        out.push(u64::from_le_bytes(octet) as i64);
                    }
                    at += width;
                }
            }
        }
        out
    }
}

/// The nine element types the fixtures witness, each named by onnx itself when reading the file that
/// carries it. Anything else is reported as its number.
fn onnx_element(ordinal: i64) -> &'static str {
    match ordinal {
        1 => "float",
        2 => "uint8",
        3 => "int8",
        6 => "int32",
        7 => "int64",
        8 => "string",
        9 => "bool",
        10 => "float16",
        11 => "double",
        _ => "unnamed",
    }
}

// ModelProto.
const ONNX_IR: u32 = 1;
const ONNX_PRODUCER: u32 = 2;
const ONNX_PRODUCER_VERSION: u32 = 3;
const ONNX_DOMAIN: u32 = 4;
const ONNX_MODEL_VERSION: u32 = 5;
const ONNX_DOC: u32 = 6;
const ONNX_GRAPH: u32 = 7;
const ONNX_OPSET: u32 = 8;
// OperatorSetIdProto, GraphProto, NodeProto, TensorProto, ValueInfo/Type/Shape/Dimension.
const OPSET_DOMAIN: u32 = 1;
const OPSET_VERSION: u32 = 2;
const GRAPH_NODES: u32 = 1;
const GRAPH_NAME: u32 = 2;
const GRAPH_TENSORS: u32 = 5;
const GRAPH_INPUTS: u32 = 11;
const GRAPH_OUTPUTS: u32 = 12;
const NODE_INPUTS: u32 = 1;
const NODE_OUTPUTS: u32 = 2;
const NODE_NAME: u32 = 3;
const NODE_OP: u32 = 4;
const TENSOR_DIMS: u32 = 1;
const TENSOR_TYPE: u32 = 2;
const TENSOR_FLOATS: u32 = 4;
const TENSOR_INT32S: u32 = 5;
const TENSOR_STRINGS: u32 = 6;
const TENSOR_INT64S: u32 = 7;
const TENSOR_NAME: u32 = 8;
const TENSOR_RAW: u32 = 9;
const TENSOR_DOUBLES: u32 = 10;
const TENSOR_UINT64S: u32 = 11;
const TENSOR_LOCATION: u32 = 14;
const INFO_NAME: u32 = 1;
const INFO_TYPE: u32 = 2;
const TYPE_TENSOR: u32 = 1;
const TENSOR_TYPE_ELEM: u32 = 1;
const TENSOR_TYPE_SHAPE: u32 = 2;
const SHAPE_DIMS: u32 = 1;
const DIM_VALUE: u32 = 1;
const DIM_PARAM: u32 = 2;

/// An absent string and an empty one are different facts in the bytes but the same one on screen:
/// onnx writes `domain = ''` for the default operator set, and the mirror prints `-` for both.
fn onnx_label(value: Option<String>) -> String {
    match value {
        Some(text) if !text.is_empty() => text,
        _ => "-".to_owned(),
    }
}

/// The dimensions of a graph input or output, keeping named, numeric and unknown axes apart.
fn onnx_dims(shape: &Pb<'_>) -> String {
    let mut parts = Vec::new();
    for dim in shape.children(SHAPE_DIMS) {
        if let Some(value) = dim.one(DIM_VALUE) {
            parts.push(format!("d{value}"));
        } else if let Some(name) = dim.text(DIM_PARAM) {
            parts.push(format!("p{name}"));
        } else {
            parts.push("u".to_owned());
        }
    }
    parts.join(",")
}

fn onnx_io(graph: &Pb<'_>, field: u32, which: &str, rows: &mut Vec<String>) {
    for (i, info) in graph.children(field).into_iter().enumerate() {
        let tensor = match info.child(INFO_TYPE).and_then(|t| t.child(TYPE_TENSOR)) {
            Some(tensor) => tensor,
            None => Pb::empty(),
        };
        let kind = tensor.one(TENSOR_TYPE_ELEM).unwrap_or(0);
        let shape = tensor.child(TENSOR_TYPE_SHAPE).unwrap_or_else(Pb::empty);
        let name = onnx_label(info.text(INFO_NAME));
        rows.push(format!(
            "{which}\t{i}\t{name}\ttype\t{kind}\ttype_name\t{}\tdims\t{}",
            onnx_element(kind),
            if onnx_dims(&shape).is_empty() {
                "-".to_owned()
            } else {
                onnx_dims(&shape)
            }
        ));
    }
}

fn read_onnx(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 {
        return None;
    }
    let model = Pb::read(bytes, 0, bytes.len());
    // Nothing identifies protobuf as ONNX, so the claim rests on structure: the whole buffer has to
    // parse, an ir_version has to be stated, a graph and an opset import have to be messages, and the
    // graph has to say something about a model.
    if model.bad > 0 || model.end != bytes.len() {
        return None;
    }
    if model.one(ONNX_IR).is_none() || model.one_region(ONNX_GRAPH).is_none() {
        return None;
    }
    let graph = model.child(ONNX_GRAPH)?;
    let opsets = model.children(ONNX_OPSET);
    if graph.bad > 0 || opsets.is_empty() || opsets.iter().any(|o| o.bad > 0) {
        return None;
    }
    if graph.count(GRAPH_NODES) == 0 && graph.count(GRAPH_INPUTS) == 0 {
        return None;
    }
    let nodes = graph.children(GRAPH_NODES);
    let tensors = graph.children(GRAPH_TENSORS);
    let first = opsets.first()?;
    let mut rows = vec![format!(
        "onnx\t{size}\tnodes\t{nodes}\ttensors\t{tensors}\topsets\t{opsets}\tbad\t{bad}",
        size = bytes.len(),
        nodes = nodes.len(),
        tensors = tensors.len(),
        opsets = opsets.len(),
        bad = model.bad,
    )];
    rows.push(format!(
        "ir\t{ir}\topset\t{domain}\tversion\t{version}",
        ir = model.one(ONNX_IR).unwrap_or(0),
        domain = onnx_label(first.text(OPSET_DOMAIN)),
        version = first.one(OPSET_VERSION).unwrap_or(0),
    ));
    let mut producer = format!(
        "producer\t{name}",
        name = onnx_label(model.text(ONNX_PRODUCER))
    );
    if let Some(value) = model.text(ONNX_PRODUCER_VERSION) {
        producer.push_str(&format!("\tversion\t{value}"));
    }
    if let Some(value) = model.text(ONNX_DOMAIN) {
        producer.push_str(&format!("\tdomain\t{value}"));
    }
    if let Some(value) = model.one(ONNX_MODEL_VERSION) {
        producer.push_str(&format!("\tmodel_version\t{value}"));
    }
    if let Some(value) = model.text(ONNX_DOC) {
        producer.push_str(&format!("\tdoc\t{value}"));
    }
    rows.push(producer);
    for (i, opset) in opsets.iter().enumerate() {
        rows.push(format!(
            "opset\t{i}\tdomain\t{domain}\tversion\t{version}",
            domain = onnx_label(opset.text(OPSET_DOMAIN)),
            version = opset.one(OPSET_VERSION).unwrap_or(0),
        ));
    }
    rows.push(format!(
        "graph\t{name}\tnodes\t{nodes}\tinputs\t{inputs}\toutputs\t{outputs}\ttensors\t{tensors}",
        name = onnx_label(graph.text(GRAPH_NAME)),
        nodes = nodes.len(),
        inputs = graph.count(GRAPH_INPUTS),
        outputs = graph.count(GRAPH_OUTPUTS),
        tensors = tensors.len(),
    ));
    for (i, node) in nodes.iter().enumerate() {
        rows.push(format!(
            "node\t{i}\top\t{op}\tname\t{name}\tinputs\t{inputs}\toutputs\t{outputs}",
            op = node.text(NODE_OP).unwrap_or_default(),
            name = onnx_label(node.text(NODE_NAME)),
            inputs = node.count(NODE_INPUTS),
            outputs = node.count(NODE_OUTPUTS),
        ));
    }
    onnx_io(&graph, GRAPH_INPUTS, "input", &mut rows);
    onnx_io(&graph, GRAPH_OUTPUTS, "output", &mut rows);
    for (i, tensor) in tensors.iter().enumerate() {
        let kind = tensor.one(TENSOR_TYPE).unwrap_or(0);
        let dims = tensor.elements(TENSOR_DIMS, 0);
        let dims: Vec<String> = dims.iter().map(|value| value.to_string()).collect();
        let mut line = format!(
            "tensor\t{i}\t{name}\ttype\t{kind}\ttype_name\t{}\tdims\t{dims}",
            onnx_element(kind),
            name = onnx_label(tensor.text(TENSOR_NAME)),
            dims = if dims.is_empty() {
                "-".to_owned()
            } else {
                dims.join("x")
            },
        );
        for (field, label, width) in [
            (TENSOR_FLOATS, "float", 4),
            (TENSOR_INT32S, "int32", 0),
            (TENSOR_INT64S, "int64", 0),
            (TENSOR_DOUBLES, "double", 8),
            (TENSOR_UINT64S, "uint64", 0),
        ] {
            let found = tensor.elements(field, width);
            if !found.is_empty() {
                line.push_str(&format!("\t{label}\t{n}", n = found.len()));
            }
        }
        let strings = tensor.count(TENSOR_STRINGS);
        if strings > 0 {
            line.push_str(&format!("\tbytes\t{strings}"));
        }
        let raw = match tensor.one_region(TENSOR_RAW) {
            Some((begin, end)) => end - begin,
            None => 0,
        };
        line.push_str(&format!("\traw\t{raw}"));
        if let Some(location) = tensor.one(TENSOR_LOCATION) {
            line.push_str(&format!("\tlocation\t{location}"));
        }
        rows.push(line);
    }
    rows.push("walked\tend".to_owned());
    Some(rows)
}

/// HEIF/HEIC: the item descriptions inside an ISO base-media container. 41, after ONNX at 40.
///
/// The container is the one this file already walks for MP4 - big-endian `size` then `type` - so what
/// earns a separate reader is the metadata: `ftyp` names a *brand* rather than a meaning, and `meta`
/// holds the item inventory (`iinf`/`infe`), the primary item (`pitm`), the properties items claim
/// (`iprp`/`ipco`/`ipma`) and where the payload lives (`iloc`, `mdat`).
///
/// The reason this is worth naming is that **the coded size and the visible size are different
/// numbers**. libheif codes in whole blocks, so `test/fixtures/photo.heic` - a 23x17 picture -
/// declares `ispe` 64x64 and crops it back to 23x17 in `clap`, whose values are signed numerators over
/// unsigned denominators. A reader that reports `ispe` prints a size the picture does not have, so both
/// are reported and labelled. Every number is compared against what pillow-heif's own reader says
/// about the same bytes (its size, bit depth, and the `nclx` primaries/transfer/matrix/range triple),
/// never against a reading of the specification.
pub const FORMAT_HEIF: i32 = 41;

/// Boxes whose payload is more boxes, and the header bytes to skip before them. `meta`, `iinf` and
/// friends are *full* boxes: the four bytes are a version and flags, not a box header.
const HEIF_CONTAINERS: [(&str, usize); 4] = [("meta", 4), ("iprp", 0), ("ipco", 0), ("iinf", 6)];
/// The brands the fixtures actually carry, plus the sibling HEVC still-image brands that share the
/// identical metadata. AVIF is deliberately absent: the existing BMFF reader answers for it.
const HEIF_BRANDS: [&str; 6] = ["heic", "heix", "heim", "heis", "mif1", "hevc"];
const HEIF_BOXES: usize = 256;
const HEIF_DEPTH: usize = 8;

fn heif_u32(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(u32::from_be_bytes(
        bytes.get(at..at + 4)?.try_into().ok()?,
    )))
}

/// The signed reading of the same four bytes: `clap` offsets and numerators are signed.
fn heif_i32(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(i32::from_be_bytes(
        bytes.get(at..at + 4)?.try_into().ok()?,
    )))
}

fn heif_u16(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(u16::from_be_bytes(
        bytes.get(at..at + 2)?.try_into().ok()?,
    )))
}

fn heif_byte(bytes: &[u8], at: usize) -> Option<i64> {
    Some(i64::from(*bytes.get(at)?))
}

fn heif_tag(bytes: &[u8], at: usize) -> Option<String> {
    Some(printable(&String::from_utf8_lossy(bytes.get(at..at + 4)?)))
}

fn heif_container(kind: &str) -> Option<usize> {
    HEIF_CONTAINERS
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, skip)| *skip)
}

/// The fields this reader names out of the boxes it walks.
#[derive(Default)]
struct HeifMeta {
    brand: String,
    compat: Vec<String>,
    handler: String,
    items: i64,
    primary: i64,
    descs: usize,
    coded: Option<(i64, i64)>,
    visible: Option<(i64, i64, i64, i64)>,
    depths: Vec<i64>,
    channels: i64,
    colour: Option<(i64, i64, i64, i64)>,
    payload: i64,
}

/// Walk one box list. `rows` collects the `box` lines in document order, `meta` the named fields, and
/// the result counts the structures that did not add up - a truncated or hostile file stops the walk
/// instead of panicking it.
fn heif_walk(
    bytes: &[u8],
    start: usize,
    stop: usize,
    depth: usize,
    rows: &mut Vec<String>,
    meta: &mut HeifMeta,
    index: &mut usize,
) -> i64 {
    let mut broken = 0i64;
    let mut at = start;
    while at + 8 <= stop {
        let Some(declared) = heif_u32(bytes, at) else {
            return broken + 1;
        };
        let Some(kind) = heif_tag(bytes, at + 4) else {
            return broken + 1;
        };
        let mut head = 8usize;
        let size = match declared {
            0 => match stop.checked_sub(at) {
                Some(rest) => rest,
                None => return broken + 1,
            },
            1 => {
                let Some(wide) = heif_u32(bytes, at + 8) else {
                    return broken + 1;
                };
                if wide < 16 {
                    return broken + 1;
                }
                head = 16;
                usize::try_from(wide).unwrap_or(usize::MAX)
            }
            other => usize::try_from(other).unwrap_or(usize::MAX),
        };
        let Some(end) = at.checked_add(size) else {
            return broken + 1;
        };
        if size < head || end > stop {
            return broken + 1;
        }
        let body = size - head;
        let here = at + head;
        rows.push(format!(
            "box\t{index}\t{kind}\tat\t{at}\tsize\t{size}\tdepth\t{depth}",
            index = *index
        ));
        *index += 1;
        match kind.as_str() {
            "ftyp" if body >= 12 => {
                meta.brand = heif_tag(bytes, here).unwrap_or_default();
                let mut cursor = here + 8;
                while cursor + 4 <= at + size {
                    if let Some(brand) = heif_tag(bytes, cursor) {
                        meta.compat.push(brand);
                    }
                    cursor += 4;
                }
            }
            "hdlr" if body >= 12 => {
                meta.handler = heif_tag(bytes, here + 8).unwrap_or_default();
            }
            "ispe" if body >= 12 => {
                if let (Some(width), Some(height)) =
                    (heif_u32(bytes, here + 4), heif_u32(bytes, here + 8))
                {
                    meta.coded = Some((width, height));
                }
            }
            "clap" if body >= 16 => {
                let width = heif_i32(bytes, here).unwrap_or(0);
                let width_ratio = heif_u32(bytes, here + 4).unwrap_or(1).max(1);
                let height = heif_i32(bytes, here + 8).unwrap_or(0);
                let height_ratio = heif_u32(bytes, here + 12).unwrap_or(1).max(1);
                meta.visible = Some((width, width_ratio, height, height_ratio));
            }
            "pixi" if body >= 5 => {
                meta.channels = heif_byte(bytes, here + 4).unwrap_or(0);
                let count = meta.channels.clamp(0, 8) as usize;
                meta.depths = (0..count)
                    .filter_map(|channel| heif_byte(bytes, here + 5 + channel))
                    .collect();
            }
            "colr" if body >= 11 => {
                if bytes.get(here..here + 4) == Some(&b"nclx"[..]) {
                    let primaries = heif_u16(bytes, here + 4).unwrap_or(0);
                    let transfer = heif_u16(bytes, here + 6).unwrap_or(0);
                    let matrix = heif_u16(bytes, here + 8).unwrap_or(0);
                    let range = heif_byte(bytes, here + 10).unwrap_or(0) >> 7;
                    meta.colour = Some((primaries, transfer, matrix, range));
                }
            }
            "pitm" if body >= 6 => {
                meta.primary = if heif_byte(bytes, here) == Some(0) {
                    heif_u16(bytes, here + 4).unwrap_or(0)
                } else {
                    heif_u32(bytes, here + 4).unwrap_or(0)
                };
            }
            "iinf" if body >= 5 => {
                meta.items = if heif_byte(bytes, here) == Some(0) {
                    heif_u16(bytes, here + 4).unwrap_or(0)
                } else {
                    heif_byte(bytes, here + 4).unwrap_or(0)
                };
            }
            "infe" => meta.descs += 1,
            "mdat" => meta.payload += body as i64,
            _ => {}
        }
        if let Some(skip) = heif_container(&kind) {
            if depth < HEIF_DEPTH {
                broken += heif_walk(bytes, here + skip, end, depth + 1, rows, meta, index);
            } else {
                broken += 1;
            }
        }
        if *index >= HEIF_BOXES {
            return broken;
        }
        at = end;
    }
    broken + i64::from(at != stop)
}

fn read_heif(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 16 || bytes.get(4..8) != Some(&b"ftyp"[..]) {
        return None;
    }
    let brand = heif_tag(bytes, 8)?;
    if !HEIF_BRANDS.contains(&brand.as_str()) {
        return None;
    }
    let mut rows = Vec::new();
    let mut meta = HeifMeta::default();
    let mut index = 0usize;
    let broken = heif_walk(bytes, 0, bytes.len(), 0, &mut rows, &mut meta, &mut index);
    // A brand alone is not a claim: without a declared image size this is some other ISO file that
    // happens to borrow the container.
    let (coded_width, coded_height) = meta.coded?;
    let compat: Vec<String> = meta
        .compat
        .iter()
        .filter(|value| !value.contains('?') && !value.trim_matches('\0').is_empty())
        .cloned()
        .collect();
    let mut entries = vec![format!(
        "heif\t{size}\tboxes\t{boxes}\tbroken\t{broken}\tbrand\t{brand}",
        size = bytes.len(),
        boxes = rows.len(),
        brand = meta.brand
    )];
    entries.push(format!(
        "compat\t{}",
        if compat.is_empty() {
            "-".to_owned()
        } else {
            compat.join(",")
        }
    ));
    entries.push(format!(
        "handler\t{}",
        if meta.handler.is_empty() {
            "?".to_owned()
        } else {
            meta.handler.clone()
        }
    ));
    entries.push(format!(
        "items\t{items}\tprimary\t{primary}\tdescs\t{descs}",
        items = meta.items,
        primary = meta.primary,
        descs = meta.descs
    ));
    entries.push(format!("coded\t{coded_width}x{coded_height}"));
    if let Some((width, width_ratio, height, height_ratio)) = meta.visible {
        entries.push(format!(
            "visible\t{width}/{width_ratio}x{height}/{height_ratio}"
        ));
    }
    if !meta.depths.is_empty() {
        let depths: Vec<String> = meta.depths.iter().map(|value| value.to_string()).collect();
        entries.push(format!(
            "depths\t{}\tchannels\t{channels}",
            depths.join(","),
            channels = meta.channels
        ));
    }
    if let Some((primaries, transfer, matrix, range)) = meta.colour {
        entries.push(format!(
            "colour\t{primaries}\ttransfer\t{transfer}\tmatrix\t{matrix}\trange\t{range}"
        ));
    }
    entries.push(format!("data\t{payload}", payload = meta.payload));
    entries.append(&mut rows);
    entries.push(if broken == 0 {
        "walked\tend".to_owned()
    } else {
        format!("stopped\tbroken\t{broken}")
    });
    Some(entries)
}

/// Compound File Binary - the OLE container the legacy Office formats and Windows installer packages
/// are built out of. Three linked tables are walked here: the sector FAT (whose own sector list is
/// the DIFAT), the directory of 128-byte entries, and for streams under the cutoff a second FAT and
/// a second stream carried inside the root entry's data.
///
/// Nothing inside a stream is interpreted; this says how the compound file is built, not what the
/// document says. Two header details carry the footnotes they earned, both confirmed against files
/// LibreOffice and xlwt wrote and olefile read back (`scripts/make-cfb-fixtures.py`): the word at
/// 0x38 is `Mini Stream Size` - always 0x1000 - and not a sector count, and the DIFAT array starts
/// at 0x4C, the only offset that leaves room for all 109 slots inside the 512-byte header.
pub const FORMAT_CFB: i32 = 42;

const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const CFB_HEADER: usize = 512;
const CFB_END: u32 = 0xFFFF_FFFE;
const CFB_FREE: u32 = 0xFFFF_FFFF;
const CFB_CUTOFF: u32 = 4096;
const CFB_ENTRIES: usize = 64;
const CFB_CHAIN: usize = 65_536;
const CFB_HOPS: usize = 1_024;

fn cfb_u16(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u32::from(u16::from_le_bytes(raw)))
}

fn cfb_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn cfb_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

/// One sector of the file, addressed the only way CFB addresses anything.
fn cfb_page(bytes: &[u8], sector: u32, size: usize) -> Option<&[u8]> {
    let offset = CFB_HEADER.checked_add((sector as usize).checked_mul(size)?)?;
    bytes.get(offset..offset.checked_add(size)?)
}

/// A chain of sector ids, ending the way a chain has to. Repeats are caught because a cycle would
/// otherwise turn a small file into a loop that never reports.
fn cfb_chain(table: &[u32], start: u32) -> (Vec<u32>, bool) {
    let mut seen = vec![false; table.len()];
    let mut list = Vec::new();
    let mut at = start;
    loop {
        if at == CFB_END || at == CFB_FREE {
            return (list, true);
        }
        let index = at as usize;
        if index >= table.len() || seen[index] || list.len() >= CFB_CHAIN {
            return (list, false);
        }
        seen[index] = true;
        list.push(at);
        at = table[index];
    }
}

/// Directory names are UTF-16LE with a length that counts the terminating NUL. Only printable
/// ASCII survives: a 0x01 or 0x05 stream prefix becomes a dot, which is how `.CompObj` gets its
/// name, and so does any character the report cannot carry. No fixture here has ever named a stream
/// with a non-ASCII character, so the reader does not pretend to decode one - it prints a dot.
fn cfb_name(bytes: &[u8], at: usize) -> String {
    let Some(length) = cfb_u16(bytes, at + 64) else {
        return String::new();
    };
    if length < 2 || length > 64 {
        return String::new();
    }
    let stop = at + length as usize - 2;
    let mut out = String::new();
    let mut walk = at;
    while walk < stop {
        // A character has to lie wholly inside the declared length; half of one does not exist.
        let value = if walk + 2 <= stop {
            cfb_u16(bytes, walk)
        } else {
            None
        };
        walk += 2;
        out.push(match value {
            Some(word) if (0x20..0x7F).contains(&word) => char::from(word as u8),
            _ => '.',
        });
    }
    out
}

/// Which document family the directory names, from the stream names this reader has seen written.
fn cfb_hint(name: &str) -> &'static str {
    let bare = name.trim_start_matches('.');
    if bare == "WordDocument" {
        "word"
    } else if bare == "Workbook" {
        "excel"
    } else {
        "-"
    }
}

fn read_cfb(bytes: &[u8]) -> Option<Vec<String>> {
    if !bytes.starts_with(&CFB_MAGIC) {
        return None;
    }
    if cfb_u16(bytes, 28)? != 0xFFFE {
        // Every compound file ever written is little-endian; a big-endian one is not worth guessing.
        return None;
    }
    let sector_shift = cfb_u16(bytes, 30)?;
    let mini_shift = cfb_u16(bytes, 32)?;
    if sector_shift < 9 || sector_shift > 16 || mini_shift > 16 {
        return None;
    }
    let ss = 1usize << sector_shift;
    let mss = 1usize << mini_shift;
    if mss > ss || bytes.len() <= CFB_HEADER + ss {
        return None;
    }
    let top = (bytes.len() - CFB_HEADER) / ss;
    let first_dir = cfb_u32(bytes, 48)?;
    let per = ss / 4;

    // The DIFAT keeps its slot positions even when a slot is free: slot k describes the sectors
    // numbered k*per .. (k+1)*per, so dropping a free slot would shift every later one.
    let mut difat: Vec<u32> = Vec::with_capacity(109);
    for i in 0..109 {
        difat.push(cfb_u32(bytes, 76 + i * 4).unwrap_or(CFB_FREE));
    }
    let mut broken = 0usize;
    let declared_difat = cfb_u32(bytes, 72)?;
    let mut at = cfb_u32(bytes, 68)?;
    let mut hops = 0usize;
    while at != CFB_END && at != CFB_FREE {
        let Some(page) = cfb_page(bytes, at, ss) else {
            broken += 1;
            break;
        };
        for i in 0..per.saturating_sub(1) {
            difat.push(u32::from_le_bytes(page[i * 4..i * 4 + 4].try_into().ok()?));
        }
        at = u32::from_le_bytes(page[(per - 1) * 4..per * 4].try_into().ok()?);
        hops += 1;
        if hops >= CFB_HOPS {
            broken += 1;
            break;
        }
    }

    let mut fat = vec![CFB_FREE; top];
    let mut fat_sectors = 0usize;
    for (pos, sector) in difat.iter().enumerate() {
        if *sector == CFB_FREE {
            continue;
        }
        fat_sectors += 1;
        let Some(page) = cfb_page(bytes, *sector, ss) else {
            broken += 1;
            continue;
        };
        for i in 0..per {
            let Some(index) = pos.checked_mul(per).and_then(|base| base.checked_add(i)) else {
                break;
            };
            if index >= fat.len() {
                break;
            }
            fat[index] = u32::from_le_bytes(page[i * 4..i * 4 + 4].try_into().ok()?);
        }
    }

    let (dir_sectors, dir_ok) = cfb_chain(&fat, first_dir);
    if !dir_ok {
        broken += 1;
    }
    if dir_sectors.is_empty() {
        return None;
    }
    let per_entry = ss / 128;
    let entry_at = |index: usize| -> Option<&[u8]> {
        let sector = *dir_sectors.get(index / per_entry)?;
        let base = CFB_HEADER.checked_add((sector as usize).checked_mul(ss)?)?;
        let start = base.checked_add((index % per_entry).checked_mul(128)?)?;
        bytes.get(start..start.checked_add(128)?)
    };

    // The root entry is both the storage that owns everything and the header of the mini stream.
    let root = entry_at(0)?;
    if root[66] != 5 {
        return None;
    }
    let root_start = cfb_u32(root, 116)?;
    let root_size = cfb_u64(root, 120)?;

    let mut mini_fat: Vec<u32> = Vec::new();
    let mut mini_sectors = 0usize;
    let first_mini = cfb_u32(bytes, 60)?;
    if first_mini != CFB_END && first_mini != CFB_FREE {
        let (list, ok) = cfb_chain(&fat, first_mini);
        if !ok {
            broken += 1;
        }
        mini_sectors = list.len();
        mini_fat = vec![CFB_FREE; mini_sectors * per];
        for (pos, sector) in list.iter().enumerate() {
            let Some(page) = cfb_page(bytes, *sector, ss) else {
                broken += 1;
                continue;
            };
            for i in 0..per {
                if pos * per + i < mini_fat.len() {
                    mini_fat[pos * per + i] =
                        u32::from_le_bytes(page[i * 4..i * 4 + 4].try_into().ok()?);
                }
            }
        }
    }
    // The one structural promise a compound file makes: no sector belongs to two owners. Chains are
    // linked lists, so sector numbers interleave freely - a repeat is the file contradicting itself.
    let mut owners = vec![0u8; top];
    let mut mini_owners = vec![0u8; mini_fat.len()];
    let mut collisions = 0usize;
    let root_row = if root_size > 0 {
        let (list, ok) = cfb_chain(&fat, root_start);
        if !ok {
            broken += 1;
        }
        for sector in &list {
            let slot = &mut owners[*sector as usize];
            *slot += 1;
            collisions += usize::from(*slot > 1);
        }
        (list.len(), list.len() * ss)
    } else {
        (0, 0)
    };
    let cutoff = cfb_u32(bytes, 56)
        .filter(|value| *value > 0)
        .unwrap_or(CFB_CUTOFF);

    let mut rows: Vec<String> = Vec::new();
    let mut streams = 0usize;
    let mut storages = 0usize;
    let mut free = 0usize;
    let mut total = 0u64;
    let mut hint = "-";
    for index in 1..CFB_ENTRIES {
        let Some(entry) = entry_at(index) else {
            break;
        };
        let kind = entry[66];
        let name = cfb_name(entry, 0);
        let start = cfb_u32(entry, 116)?;
        let size = cfb_u64(entry, 120)?;
        match kind {
            0 => free += 1,
            1 => {
                storages += 1;
                let child = cfb_u32(entry, 76)?;
                rows.push(format!("storage\t{index}\t{name}\tchild\t{child}"));
            }
            2 => {
                streams += 1;
                total = total.saturating_add(size);
                let named = cfb_hint(&name);
                if named != "-" && hint == "-" {
                    hint = named;
                }
            }
            // Only 0, 1, 2 and 5 exist, and a second root entry is a container lying about itself.
            _ => broken += 1,
        }
        if kind != 2 || size == 0 {
            continue;
        }
        let below = size < u64::from(cutoff);
        let (list, ok) = if below {
            cfb_chain(&mini_fat, start)
        } else {
            cfb_chain(&fat, start)
        };
        if !ok {
            broken += 1;
        }
        for sector in &list {
            let slot = if below {
                mini_owners.get_mut(*sector as usize)
            } else {
                owners.get_mut(*sector as usize)
            };
            if let Some(cell) = slot {
                *cell += 1;
                collisions += usize::from(*cell > 1);
            }
        }
        rows.push(format!(
            "stream\t{index}\t{name}\tsize\t{size}\tstart\t{start}\twhere\t{}\tsectors\t{}\tholds\t{}",
            if below { "mini" } else { "regular" },
            list.len(),
            list.len() * if below { mss } else { ss }
        ));
    }
    let clsid = root
        .get(80..96)
        .map(|value| {
            if value.iter().all(|byte| *byte == 0) {
                "-".to_owned()
            } else {
                value.iter().map(|byte| format!("{byte:02X}")).collect()
            }
        })
        .unwrap_or_else(|| "?".to_owned());
    rows.push(format!(
        "inventory\tstreams\t{streams}\tstorages\t{storages}\tfree\t{free}\tbytes\t{total}\tcollisions\t{collisions}\thint\t{hint}"
    ));
    broken += collisions;
    rows.insert(
        0,
        format!(
            "root\tstart\t{root_start}\tsize\t{root_size}\tsectors\t{}\tholds\t{}\tmini\t{}\tclsid\t{clsid}",
            root_row.0,
            root_row.1,
            root_size / mss as u64
        ),
    );
    rows.insert(
        0,
        format!(
            "layout\tfat\t{fat_sectors}\tdifat\t{declared_difat}\tdir\t{}\tminifat\t{mini_sectors}\tsectors\t{top}",
            dir_sectors.len()
        ),
    );
    rows.insert(
        0,
        format!(
            "cfb\t{}\tbroken\t{broken}\tversion\t{}.{}\tsector\t{ss}\tmini\t{mss}",
            bytes.len(),
            bytes[26],
            cfb_u16(bytes, 24)?
        ),
    );
    if broken == 0 {
        rows.push("walked\tend".to_owned());
    } else {
        rows.push(format!("stopped\tbroken\t{broken}"));
    }
    Some(rows)
}

/// Binary STL: 80 header bytes, a u32 triangle count, then exactly 50 bytes per triangle.
///
/// The format has no magic, so the only self-statement a file can make is the arithmetic - and that
/// is necessary, not sufficient, so the reader also requires the first and last readable triangle's
/// coordinates to be finite numbers before it claims the file. The stored normal is not trusted: it
/// is listed as written and counted against the normal the three points imply, because writers differ
/// and some leave it zeroed.
pub const FORMAT_STL: i32 = 43;

const STL_HEAD: usize = 80;
const STL_TRI: usize = 50;
const STL_LISTED: usize = 16;
const STL_MAX_TRIS: u32 = 200_000_000;

fn stl_f32(bytes: &[u8], at: usize) -> Option<f32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(f32::from_le_bytes(raw))
}

fn stl_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn stl_u16(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u32::from(u16::from_le_bytes(raw)))
}

/// The 80-byte header is free text; anything that is not printable becomes a dot, and only the dots
/// the padding produced are trimmed off the end.
fn stl_text(bytes: &[u8]) -> String {
    let text: String = bytes[..STL_HEAD]
        .iter()
        .map(|byte| {
            if (0x20..0x7F).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect();
    let trimmed = text.trim_end_matches('.');
    if trimmed.is_empty() {
        "-".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn stl_trio(bytes: &[u8], at: usize) -> Option<String> {
    let parts: Vec<String> = (0..3)
        .filter_map(|axis| stl_f32(bytes, at + axis * 4))
        .map(|value| format!("{value:.6}"))
        .collect();
    if parts.len() == 3 {
        Some(parts.join(","))
    } else {
        None
    }
}

/// True when the nine coordinates of one triangle are all real numbers. The normal is three floats at
/// the triangle's start and the coordinates nine more from its twelfth byte; reaching past the ninth
/// coordinate reads the attribute bytes, and off the end of the last triangle in the file.
fn stl_triangle_sane(bytes: &[u8], base: usize) -> bool {
    (0..9).all(|axis| stl_f32(bytes, base + 12 + axis * 4).map_or(false, |value| value.is_finite()))
}

/// A binary STL's stored normal is a unit vector - or zero, which plenty of writers emit. Text bytes
/// read as three denormal floats, so this is what keeps an ASCII STL from being reported as a binary
/// one whose triangles happen to line up.
fn stl_normal_plausible(bytes: &[u8], base: usize) -> bool {
    let parts: Vec<f32> = (0..3)
        .filter_map(|axis| stl_f32(bytes, base + axis * 4))
        .collect();
    if parts.len() != 3 {
        return false;
    }
    let length = parts.iter().map(|part| part * part).sum::<f32>().sqrt();
    length == 0.0 || (0.5..1.5).contains(&length)
}

/// The unit normal the three points imply, as a cross product; `None` when the points are collinear.
fn stl_implied(points: [f32; 9]) -> Option<[f32; 3]> {
    let a = &points[0..3];
    let b = &points[3..6];
    let c = &points[6..9];
    let u = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
    let v = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
    let cross = [
        u[1] * v[2] - u[2] * v[1],
        u[2] * v[0] - u[0] * v[2],
        u[0] * v[1] - u[1] * v[0],
    ];
    let length = (cross[0] * cross[0] + cross[1] * cross[1] + cross[2] * cross[2]).sqrt();
    if length == 0.0 {
        return None;
    }
    Some([cross[0] / length, cross[1] / length, cross[2] / length])
}

fn read_stl(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < STL_HEAD + 4 + STL_TRI {
        return None;
    }
    let count = stl_u32(bytes, STL_HEAD)?;
    if count == 0 || count > STL_MAX_TRIS {
        return None;
    }
    // The identity has to hold, not merely be close. A file that claims more triangles than it holds
    // cannot be checked at all, and without this gate any blob whose 80th byte happens to be small
    // enough reads as a mesh: a real HDF5 superblock was claimed exactly that way.
    let declared = 84usize.checked_add(count as usize * STL_TRI)?;
    if declared != bytes.len() {
        return None;
    }
    let listed = usize::try_from(count).unwrap_or(usize::MAX).min(STL_LISTED);
    let mut rows = Vec::new();
    let mut low = [f32::MAX; 3];
    let mut high = [f32::MIN; 3];
    let mut zeroed = 0usize;
    let mut wrong = 0usize;
    for index in 0..count as usize {
        let base = STL_HEAD + 4 + index * STL_TRI;
        if !stl_triangle_sane(bytes, base) || !stl_normal_plausible(bytes, base) {
            return None;
        }
        let normal: [f32; 3] = [
            stl_f32(bytes, base)?,
            stl_f32(bytes, base + 4)?,
            stl_f32(bytes, base + 8)?,
        ];
        let mut points = [0f32; 9];
        for slot in 0..9 {
            points[slot] = stl_f32(bytes, base + 12 + slot * 4)?;
        }
        for corner in 0..3 {
            for axis in 0..3 {
                let value = points[corner * 3 + axis];
                low[axis] = low[axis].min(value);
                high[axis] = high[axis].max(value);
            }
        }
        if normal.iter().all(|part| *part == 0.0) {
            zeroed += 1;
        } else if stl_implied(points).map_or(true, |implied| {
            (0..3).any(|axis| (normal[axis] - implied[axis]).abs() > 1e-3)
        }) {
            wrong += 1;
        }
        if index < listed {
            rows.push(format!(
                "tri\t{index}\tnormal\t{}\tv0\t{}\tv1\t{}\tv2\t{}\tattr\t{}",
                stl_trio(bytes, base)?,
                stl_trio(bytes, base + 12)?,
                stl_trio(bytes, base + 24)?,
                stl_trio(bytes, base + 36)?,
                stl_u16(bytes, base + 48)?
            ));
        }
    }
    if (count as usize) > listed {
        rows.push(format!("cut\ttris\t{count}"));
    }
    rows.push(format!(
        "box\tmin\t{}\tmax\t{}",
        low.iter()
            .map(|value| format!("{value:.6}"))
            .collect::<Vec<_>>()
            .join(","),
        high.iter()
            .map(|value| format!("{value:.6}"))
            .collect::<Vec<_>>()
            .join(",")
    ));
    rows.insert(
        0,
        format!(
            "sizes\tdeclared\t{declared}\tactual\t{}\tfit\texact",
            bytes.len()
        ),
    );
    rows.push(format!(
        "normals\tzero\t{zeroed}\twrong\t{wrong}\tcounted\t{count}"
    ));
    rows.insert(
        0,
        format!(
            "stl\t{}\ttris\t{count}\tsolid\t{}",
            bytes.len(),
            stl_text(bytes)
        ),
    );
    rows.push("walked\tend".to_owned());
    Some(rows)
}

/// ICC colour profile: a big-endian header, `acsp` at 36, and a tag table that points into the same
/// buffer the header declares the length of.
///
/// The self-statement is the same shape as binary STL's - the first four bytes are the size of the
/// whole file - and the signature has to be at 36, so a claim needs both. A profile whose stated
/// length disagrees with the buffer is still read and reported, because the disagreement is the useful
/// fact; but a tag table that would run past the bytes is refused, since everything beyond the real
/// end is payload and reading it as a directory would invent rows. Pointers that leave the declared
/// length are counted, not followed. Nothing here interprets a colour transform; the types are named
/// as the file spells them.
pub const FORMAT_ICC: i32 = 44;

const ICC_TAGS: usize = 48;
const ICC_INTENTS: [(u32, &str); 4] = [
    (0, "perceptual"),
    (1, "relative"),
    (2, "saturation"),
    (3, "absolute"),
];

fn icc_be(bytes: &[u8], at: usize, wide: usize) -> Option<u64> {
    let stop = at.checked_add(wide)?;
    let slice = bytes.get(at..stop)?;
    let mut value = 0u64;
    for byte in slice {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

/// Four-byte ICC signatures are space padded, so `RGB ` and `RGB` name the same space; anything that
/// is not printable at all answers as `?`.
fn icc_token(bytes: &[u8], at: usize) -> String {
    let Some(stop) = at.checked_add(4) else {
        return "?".to_owned();
    };
    let Some(slice) = bytes.get(at..stop) else {
        return "?".to_owned();
    };
    let text: String = slice
        .iter()
        .filter(|byte| (0x20..0x7F).contains(*byte))
        .map(|byte| char::from(*byte))
        .collect();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "?".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn read_icc(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 132 || &bytes[36..40] != b"acsp" {
        return None;
    }
    let declared = icc_be(bytes, 0, 4)? as usize;
    let tags = icc_be(bytes, 128, 4)?;
    let records = usize::try_from(tags).unwrap_or(usize::MAX);
    let table_end = 132usize.checked_add(records.checked_mul(12)?)?;
    // The table has to be inside the file. A count that outruns the bytes is not believed, because
    // everything past the real end is tag payload, and reading it as a directory would be reporting
    // numbers the profile never wrote.
    if table_end > bytes.len() {
        return None;
    }
    let mut broken = usize::from(declared != bytes.len()) + usize::from(table_end > declared);
    let listed = records.min(ICC_TAGS);
    let mut rows = Vec::new();
    let mut end = table_end;
    let mut outside = 0usize;

    for index in 0..listed {
        let base = 132 + index * 12;
        let signature = icc_token(bytes, base);
        let at = icc_be(bytes, base + 4, 4)?;
        let size = icc_be(bytes, base + 8, 4)?;
        let stop = at.checked_add(size)?;
        // A pointer that leaves the declared length is counted and not followed: reading a type from
        // bytes that are not part of this profile would invent a tag, and on a 32-bit target a wide
        // offset would truncate into one that is, so the two builds would disagree about the file.
        let inside = usize::try_from(stop).ok().filter(|stop| *stop <= declared);
        if inside.is_none() || usize::try_from(at).map_or(true, |start| start < 128) {
            outside += 1;
        }
        if let Some(furthest) = inside.filter(|stop| *stop > end) {
            end = furthest;
        }
        rows.push(format!(
            "tag\t{index}\t{signature}\tsig\t{}\tat\t{at}\tlen\t{size}",
            icc_token(bytes, usize::try_from(at).unwrap_or(usize::MAX))
        ));
    }
    if records > listed {
        rows.push(format!("cut\ttags\t{tags}"));
    }
    broken += usize::from(outside > 0);
    let intent = icc_be(bytes, 64, 4)?;
    rows.push(format!(
        "table\ttags\t{tags}\tlisted\t{listed}\toutside\t{outside}\tdata_end\t{end}\ttail\t{}",
        declared.saturating_sub(end)
    ));
    rows.insert(
        0,
        format!(
            "profile\tclass\t{}\tspace\t{}\tpcs\t{}\tintent\t{}\tcreator\t{}",
            icc_token(bytes, 12),
            icc_token(bytes, 16),
            icc_token(bytes, 20),
            ICC_INTENTS
                .iter()
                .find(|(value, _)| u64::from(*value) == intent)
                .map_or_else(|| intent.to_string(), |(_, name)| (*name).to_owned()),
            icc_token(bytes, 80)
        ),
    );
    rows.insert(
        0,
        format!(
            "icc\t{}\tdeclared\t{declared}\tbroken\t{broken}\tversion\t{}.{}\tcmm\t{}",
            bytes.len(),
            bytes[8],
            (bytes[9] >> 4) & 0x0F,
            icc_token(bytes, 4)
        ),
    );
    if broken == 0 {
        rows.push("walked\tend".to_owned());
    } else {
        rows.push(format!("stopped\tbroken\t{broken}"));
    }
    Some(rows)
}

/// Windows Enhanced Metafile: a header record followed by a flat list of `u32 type, u32 size` records.
///
/// The claim is the header's own word - `' EMF'` at 40, since the first eight bytes are the record
/// type and size like every other record's - and everything after that is arithmetic the file has to
/// satisfy: the header states the byte count, and the walk has to land on it. The record *count* is
/// not trusted, because the two producers whose output is committed here disagree about it: GDI's says
/// 5 and the walk finds 5, LibreOffice's says 22 and the walk finds 23 (the header itself). Both
/// numbers are printed side by side and neither is called right.
///
/// What the reader deliberately does not do is name record types. `cab`'s folder area set the
/// precedent: a number whose meaning has not been witnessed stays a number. Type 14 closes both
/// fixtures, so it is reported as `last`, which is a fact about position rather than a claim about the
/// specification. Two rectangles are printed rather than reconciled: bounds in device units, frame in
/// hundredths of a millimetre, and the pixels/mm pair that states the resolution between them - which
/// is a different rectangle again on a file whose device is a screen rather than a page.
pub const FORMAT_EMF: i32 = 45;

/// The signature is the ASCII of ` EMF` read as a little-endian word, exactly as GDI writes it.
const EMF_SIGNATURE: u32 = 0x464D_4520;
const EMF_HEADER: usize = 96;
const EMF_LISTED: usize = 24;
const EMF_KINDS: usize = 128;

fn emf_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn emf_i32(bytes: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(emf_u32(bytes, at)?.to_le_bytes()))
}

/// Hundredths of a millimetre, said out loud: `189.99` rather than a bare 18999, because the unit is
/// the only reason the field is not a pixel count.
fn emf_micrometres(data: f64) -> String {
    format!("{:.2}", data)
}

fn read_emf(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < EMF_HEADER || emf_u32(bytes, 0)? != 1 || emf_u32(bytes, 40)? != EMF_SIGNATURE {
        return None;
    }
    let n_size = emf_u32(bytes, 4)?;
    let version = emf_u32(bytes, 44)?;
    let claimed_bytes = emf_u32(bytes, 48)? as usize;
    let claimed_records = emf_u32(bytes, 52)?;
    let bounds: Vec<i32> = (0..4)
        .filter_map(|slot| emf_i32(bytes, 8 + slot * 4))
        .collect();
    let frame: Vec<i32> = (0..4)
        .filter_map(|slot| emf_i32(bytes, 24 + slot * 4))
        .collect();
    let device: Vec<u32> = (0..2)
        .filter_map(|slot| emf_u32(bytes, 72 + slot * 4))
        .collect();
    let millimetres: Vec<u32> = (0..2)
        .filter_map(|slot| emf_u32(bytes, 80 + slot * 4))
        .collect();
    if bounds.len() != 4 || frame.len() != 4 || device.len() != 2 || millimetres.len() != 2 {
        return None;
    }

    // The walk honours each record's own length, which is what makes a lying header visible: the first
    // record's size is the step off position zero, so a header that mis-states itself desynchronises
    // everything after it.
    let mut at = 0usize;
    let mut listed: Vec<String> = Vec::new();
    let mut kinds: Vec<u32> = Vec::new();
    let mut counted = 0usize;
    let mut last = -1i64;
    let mut complete = false;
    while at + 8 <= bytes.len() {
        let kind = emf_u32(bytes, at)?;
        let size = emf_u32(bytes, at + 4)? as usize;
        if size < 8 || at.saturating_add(size) > bytes.len() {
            break;
        }
        if !kinds.contains(&kind) && kinds.len() < EMF_KINDS {
            kinds.push(kind);
        }
        if counted < EMF_LISTED {
            listed.push(format!("record\t{counted}\ttype\t{kind}\tsize\t{size}"));
        }
        last = i64::from(kind);
        counted += 1;
        at += size;
    }
    complete = at == bytes.len();

    let broken = usize::from(claimed_bytes != bytes.len()) + usize::from(!complete);
    let dpi = if millimetres[0] == 0 {
        "?".to_owned()
    } else {
        emf_micrometres(f64::from(device[0]) * 25.4 / f64::from(millimetres[0]))
    };
    let mut rows = vec![format!(
        "emf\t{}\tbroken\t{broken}\tversion\t{}.{}\tnsize\t{n_size}\trecords\t{claimed_records}\twalked\t{counted}",
        bytes.len()
    , version >> 16, version & 0xFFFF)];
    rows.push(format!(
        "bounds\t{}\t{}\t{}\t{}\twh\t{}x{}",
        bounds[0],
        bounds[1],
        bounds[2],
        bounds[3],
        bounds[2].saturating_sub(bounds[0]),
        bounds[3].saturating_sub(bounds[1])
    ));
    rows.push(format!(
        "frame\t{}\t{}\t{}\t{}\tmm\t{}x{}",
        frame[0],
        frame[1],
        frame[2],
        frame[3],
        emf_micrometres(f64::from(frame[2].saturating_sub(frame[0])) / 100.0),
        emf_micrometres(f64::from(frame[3].saturating_sub(frame[1])) / 100.0)
    ));
    rows.push(format!(
        "device\tpx\t{}x{}\tmm\t{}x{}\tdpi\t{dpi}",
        device[0], device[1], millimetres[0], millimetres[1]
    ));
    rows.append(&mut listed);
    if counted > EMF_LISTED {
        rows.push(format!("cut\trecords\t{counted}"));
    }
    rows.push(format!(
        "types\tcounted\t{counted}\tdistinct\t{}\tlast\t{last}",
        kinds.len()
    ));
    if complete {
        rows.push("walked\tend".to_owned());
    } else {
        rows.push(format!("stopped\tat\t{at}"));
    }
    Some(rows)
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
    // Before the generic ISO base-media walk: a HEIF file is BMFF too, and the richer read of its
    // item properties has to win for the brands it knows.
    if let Some(lines) = read_heif(bytes) {
        return accept(FORMAT_HEIF, lines);
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
    if let Some(lines) = read_parquet(bytes) {
        return accept(FORMAT_PARQUET, lines);
    }
    if let Some(lines) = read_onnx(bytes) {
        return accept(FORMAT_ONNX, lines);
    }
    if let Some(lines) = read_cfb(bytes) {
        return accept(FORMAT_CFB, lines);
    }
    // Before STL, which has no signature at all: `acsp` at 36 is ICC's only self-assertion besides
    // its length, so a file that spells it is claimed here rather than left to arithmetic.
    if let Some(lines) = read_icc(bytes) {
        return accept(FORMAT_ICC, lines);
    }
    if let Some(lines) = read_emf(bytes) {
        return accept(FORMAT_EMF, lines);
    }
    // Last, because nothing here has a magic: an STL is only recognised by the arithmetic its own
    // triangle count implies, so every container with a real signature gets to answer first.
    if let Some(lines) = read_stl(bytes) {
        return accept(FORMAT_STL, lines);
    }
    reject(
        "not a tar, ar, deb, RIFF, TIFF, EBML, PDF, Netpbm, ASF, FLV, CAB, MPEG-TS, WebAssembly, font, icon, property-list, QOI, WOFF2, JPEG 2000, NumPy array, HDF5, Avro container, Arrow stream, Parquet file, ONNX model, HEIF image, compound file, ICC profile, enhanced metafile or binary STL",
        -2,
    )
}
