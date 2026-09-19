//! Header readers for the audio containers that no Kaitai spec in the pinned bundle covers
//! properly: FLAC, MPEG audio (MP3), Ogg and WAVE.
//!
//! Like the other readers here this is framing plus named header fields - sample rate, channel
//! count, block and frame sizes, page and frame walks - and no decoding of a single sample. Every
//! accessor is bounds-checked, so a truncated or hostile file yields an error code rather than a
//! panic, and nothing is written anywhere.
//!
//! Layouts, each one confirmed against a file written by ffmpeg before this code was written:
//!   FLAC  "fLaC" then metadata blocks: byte0 = last-flag<<7 | type, bytes1..4 = 24-bit length.
//!         STREAMINFO (type 0, 34 bytes): minBlock u16, maxBlock u16, minFrame u24, maxFrame u24,
//!         then 64 bits packed as sampleRate(20) channels-1(3) bitsPerSample-1(5) totalSamples(36),
//!         then a 128-bit MD5.
//!   MP3   an optional ID3v2 header ("ID3", ver, rev, flags, 4x7-bit synchsafe size) then MPEG
//!         audio frames. A frame header's bits, most significant first: sync(11)=0x7ff,
//!         version(2) where 3=MPEG1 and 2=MPEG2 and 0=MPEG2.5, layer(2) where 1=Layer III,
//!         protection(1), bitrate index(4), sample-rate index(2), padding(1), private(1),
//!         channel mode(2). Layer III frame length = 144*bitrate/samplerate + padding.
//!   Ogg   "OggS", version, header type, granule position i64le, bitstream serial u32le, page
//!         sequence u32le, checksum u32le, segment count u8, then that many bytes of segment
//!         lengths; the page is 27 + count + their sum bytes long. The Vorbis identification
//!         packet that follows is type 1, "vorbis", version u32le, channels u8, sample rate u32le,
//!         bitrate maximum i32le, bitrate nominal i32le.
//!   WAVE  "RIFF", total-8 u32le, "WAVE", then chunks; the fmt chunk body is audio format u16le,
//!         channels u16le, sample rate u32le, byte rate u32le, block align u16le, bits u16le.
//!
//! The MPEG audio case is why the frame walk reports what it walked instead of a single bitrate:
//! the first frame of a LAME-encoded file advertises a different bitrate index from the ones after
//! it, so a reader that trusted frame zero would report a rate the rest of the file does not use.

use std::cell::RefCell;

pub const FORMAT_FLAC: i32 = 12;
pub const FORMAT_MP3: i32 = 13;
pub const FORMAT_OGG: i32 = 14;
pub const FORMAT_WAVE: i32 = 15;

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

/// The family name beside the code, next to the constants rather than in a caller's table.
pub fn name() -> &'static str {
    match kind() {
        FORMAT_FLAC => "flac",
        FORMAT_MP3 => "mpeg-audio",
        FORMAT_OGG => "ogg",
        FORMAT_WAVE => "wave",
        _ => "unknown",
    }
}

pub fn count() -> i32 {
    RESULT.with(|slot| slot.borrow().len() as i32)
}

pub fn at(index: i32) -> Option<String> {
    RESULT.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}

fn field(name: &str, value: impl std::fmt::Display) -> String {
    format!("{name}\t{value}")
}

fn be24(bytes: &[u8]) -> i64 {
    i64::from(bytes[0]) << 16 | i64::from(bytes[1]) << 8 | i64::from(bytes[2])
}

fn le32(bytes: &[u8], at: usize) -> Option<i64> {
    let end = at.checked_add(4)?;
    let part = bytes.get(at..end)?;
    Some(i64::from(u32::from_le_bytes([
        part[0], part[1], part[2], part[3],
    ])))
}

fn le64(bytes: &[u8], at: usize) -> Option<i64> {
    let part = bytes.get(at..at.checked_add(8)?)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(part);
    Some(i64::try_from(u64::from_le_bytes(buf)).unwrap_or(i64::MAX))
}

fn read_flac(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 42 || &bytes[0..4] != b"fLaC" {
        return None;
    }
    let flags = bytes[4];
    if flags & 0x7f != 0 {
        return None;
    }
    if be24(&bytes[5..8]) != 34 {
        return None;
    }
    let info = bytes.get(8..42)?;
    let packed = u64::from_be_bytes(info[10..18].try_into().ok()?);
    let sample_rate = (packed >> 44) & 0xfffff;
    let channels = ((packed >> 41) & 7) + 1;
    let bits = ((packed >> 36) & 31) + 1;
    let total_samples = packed & ((1 << 36) - 1);
    let mut lines = vec![
        field("min_block", u16::from_be_bytes(info[0..2].try_into().ok()?)),
        field("max_block", u16::from_be_bytes(info[2..4].try_into().ok()?)),
        field("min_frame", be24(&info[4..7])),
        field("max_frame", be24(&info[7..10])),
        field("sample_rate", sample_rate),
        field("channels", channels),
        field("bits_per_sample", bits),
        field("total_samples", total_samples),
    ];
    let seconds = if sample_rate > 0 {
        total_samples as f64 / sample_rate as f64
    } else {
        0.0
    };
    lines.push(field("duration_ms", (seconds * 1000.0).round() as i64));
    // The metadata blocks after STREAMINFO are walked by their own declared lengths, which is what
    // proves the read is on the block boundaries rather than just on the first header.
    let mut at = 42usize;
    let mut blocks = 0i64;
    while at + 4 <= bytes.len() && blocks < 64 {
        let last = bytes[at] >> 7;
        let Some(kind_value) = bytes.get(at).map(|b| i64::from(*b & 0x7f)) else {
            break;
        };
        let length = be24(&bytes[at + 1..at + 4]) as usize;
        if at + 4 + length > bytes.len() {
            break;
        }
        lines.push(format!("block\t{kind_value}\t{length}\t{at}\t{last}"));
        blocks += 1;
        at += 4 + length;
        if last == 1 {
            break;
        }
    }
    // Everything after the last metadata block is the frame area, so this is where the first FLAC
    // frame header has to start.
    lines.push(field("frames_start", at.min(bytes.len())));
    Some(lines)
}

const MPEG1_L3: [i64; 16] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
];
const MPEG2_L3: [i64; 16] = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
];

fn read_mp3(bytes: &[u8]) -> Option<Vec<String>> {
    let mut at = 0usize;
    let mut tag = 0i64;
    if bytes.len() > 10 && &bytes[0..3] == b"ID3" {
        tag = i64::from(bytes[6] & 0x7f) << 21
            | i64::from(bytes[7] & 0x7f) << 14
            | i64::from(bytes[8] & 0x7f) << 7
            | i64::from(bytes[9] & 0x7f);
        at = 10 + tag as usize;
    }
    let head = bytes.get(at..at + 4)?;
    let header = u32::from_be_bytes(head.try_into().ok()?);
    if header >> 21 != 0x7ff {
        return None;
    }
    let version = (header >> 19) & 3;
    let layer = (header >> 17) & 3;
    if version == 2 || layer != 1 {
        // Only MPEG 1/2/2.5 Layer III is walked; the other layers differ in frame length and
        // would be reported with the wrong stride.
        return None;
    }
    let rates: [i64; 3] = if version == 3 {
        [44100, 48000, 32000]
    } else {
        [22050, 24000, 16000]
    };
    let table: [i64; 16] = if version == 3 { MPEG1_L3 } else { MPEG2_L3 };
    let sample_rate_index = ((header >> 10) & 3) as usize;
    let first_rate = *rates.get(sample_rate_index)?;
    let mut lines = vec![
        field("id3v2_bytes", tag),
        field("mpeg_version", version),
        field("layer", 3),
        field("sample_rate", first_rate),
        field("channel_mode", (header >> 6) & 3),
        field("crc_protected", (header >> 16) & 1),
    ];
    let mut cursor = at;
    let mut frames = 0i64;
    let mut samples: i64 = 0;
    let mut bitrates = vec![0i64; 16];
    let mut distinct_rates = 0i64;
    let mut last_rate = first_rate;
    while cursor + 4 <= bytes.len() && frames < 200_000 {
        let head = &bytes[cursor..cursor + 4];
        let word = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if word >> 21 != 0x7ff {
            break;
        }
        let frame_version = (word >> 19) & 3;
        if frame_version == 2 || (word >> 17) & 3 != 1 {
            break;
        }
        let index = ((word >> 12) & 15) as usize;
        let bitrate = if frame_version == 3 {
            MPEG1_L3[index]
        } else {
            MPEG2_L3[index]
        };
        let frame_rates: [i64; 3] = if frame_version == 3 {
            [44100, 48000, 32000]
        } else {
            [22050, 24000, 16000]
        };
        let Some(&rate) = frame_rates.get(((word >> 10) & 3) as usize) else {
            break;
        };
        if bitrate <= 0 {
            break;
        }
        let padding = i64::from((word >> 9) & 1);
        let length = 144 * bitrate * 1000 / rate + padding;
        if length < 4 || cursor as i64 + length > bytes.len() as i64 {
            break;
        }
        bitrates[index] += 1;
        if rate != last_rate {
            distinct_rates += 1;
            last_rate = rate;
        }
        frames += 1;
        samples += 1152;
        cursor += length as usize;
    }
    lines.push(field("frames", frames));
    lines.push(field("samples", samples));
    let duration_ms = if first_rate > 0 {
        (samples as f64 / first_rate as f64 * 1000.0).round() as i64
    } else {
        0
    };
    lines.push(field("duration_ms", duration_ms));
    for (index, seen) in bitrates.iter().enumerate() {
        if *seen > 0 {
            lines.push(format!("bitrate\t{index}\t{}\t{seen}", table[index]));
        }
    }
    lines.push(field("rate_switches", distinct_rates));
    lines.push(field("bytes_after_frames", cursor));
    Some(lines)
}

fn read_ogg(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 58 || &bytes[0..4] != b"OggS" {
        return None;
    }
    let segments = usize::from(bytes[26]);
    let mut pages = 0i64;
    let mut at = 0usize;
    let mut payload = 0i64;
    let mut last_granule = -1i64;
    let mut serial = -1;
    let mut sequence_mismatch = 0i64;
    let mut expected_sequence = 0u32;
    while at + 27 <= bytes.len() {
        if &bytes[at..at + 4] != b"OggS" {
            break;
        }
        let count = usize::from(bytes[at + 26]);
        if at + 27 + count > bytes.len() {
            break;
        }
        let body: i64 = bytes[at + 27..at + 27 + count]
            .iter()
            .map(|b| i64::from(*b))
            .sum();
        let size = 27 + count as i64 + body;
        if at as i64 + size > bytes.len() as i64 {
            break;
        }
        if pages == 0 {
            serial = le32(bytes, at + 14)?;
        } else if le32(bytes, at + 14)? != serial {
            break;
        }
        if le32(bytes, at + 18)? != i64::from(expected_sequence) {
            sequence_mismatch += 1;
        }
        expected_sequence = expected_sequence.wrapping_add(1);
        last_granule = le64(bytes, at + 6)?;
        pages += 1;
        payload += body;
        at += size as usize;
        if pages > 4096 {
            break;
        }
    }
    if pages < 1 {
        return None;
    }
    let mut lines = vec![
        field("version", bytes[4]),
        field("first_header_type", bytes[5]),
        field("bitstream_serial", serial),
        field("pages", pages),
        field("payload_bytes", payload),
        field("last_granule", last_granule),
        field("sequence_gaps", sequence_mismatch),
        field("bytes_after_pages", at),
    ];
    // The Vorbis identification packet, when this is Ogg/Vorbis: sample rate and channel count are
    // the fields a caller actually needs, and they are at fixed offsets inside the first page body.
    let body = 27 + segments;
    if bytes.len() > body + 24 && bytes[body] == 1 && &bytes[body + 1..body + 7] == b"vorbis" {
        let channels = i64::from(bytes[body + 11]);
        let rate = le32(bytes, body + 12)?;
        lines.push(field("codec", "vorbis"));
        lines.push(field("version", le32(bytes, body + 7)?));
        lines.push(field("channels", channels));
        lines.push(field("sample_rate", rate));
        lines.push(field("bitrate_max", le32(bytes, body + 16)?));
        lines.push(field("bitrate_nominal", le32(bytes, body + 20)?));
    }
    Some(lines)
}

fn read_wave(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let mut at = 12usize;
    let mut lines = vec![field("declared", le32(bytes, 4)? + 8)];
    let mut sample_rate = 0i64;
    let mut block_align = 0i64;
    let mut data_bytes = 0i64;
    while at + 8 <= bytes.len() {
        let id = String::from_utf8_lossy(&bytes[at..at + 4]).into_owned();
        let Some(size) = le32(bytes, at + 4) else {
            break;
        };
        let body = at + 8;
        if id == "fmt " {
            let fmt = bytes.get(body..body + size.max(0) as usize)?;
            if fmt.len() < 16 {
                return None;
            }
            let format = i64::from(u16::from_le_bytes([fmt[0], fmt[1]]));
            let channels = i64::from(u16::from_le_bytes([fmt[2], fmt[3]]));
            sample_rate = le32(fmt, 4)?;
            let byte_rate = le32(fmt, 8)?;
            block_align = i64::from(u16::from_le_bytes([fmt[12], fmt[13]]));
            let bits = i64::from(u16::from_le_bytes([fmt[14], fmt[15]]));
            lines.push(field("format", format));
            lines.push(field("channels", channels));
            lines.push(field("sample_rate", sample_rate));
            lines.push(field("byte_rate", byte_rate));
            lines.push(field("block_align", block_align));
            lines.push(field("bits_per_sample", bits));
        } else if id == "data" {
            data_bytes = size;
            lines.push(field("data_bytes", size));
            lines.push(field("data_offset", body));
        } else {
            lines.push(format!("chunk\t{id}\t{size}\t{body}"));
        }
        let step = size.max(0) as usize + (size.max(0) as usize & 1);
        if body + step > bytes.len() {
            break;
        }
        at = body + step;
    }
    if sample_rate > 0 && block_align > 0 && data_bytes > 0 {
        let seconds = f64::from(i32::try_from(data_bytes / block_align).unwrap_or(i32::MAX))
            / f64::from(i32::try_from(sample_rate).unwrap_or(1));
        lines.push(field("duration_ms", (seconds * 1000.0).round() as i64));
    }
    if lines.len() > 1 {
        Some(lines)
    } else {
        None
    }
}

/// -1 buffer too small to identify, -2 no supported audio format. Otherwise the FORMAT_* code.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < 44 {
        return reject("too small to identify an audio header", -1);
    }
    for (code, reader) in [
        (FORMAT_FLAC, read_flac as fn(&[u8]) -> Option<Vec<String>>),
        (FORMAT_OGG, read_ogg),
        (FORMAT_WAVE, read_wave),
        (FORMAT_MP3, read_mp3),
    ] {
        if let Some(lines) = reader(bytes) {
            return accept(code, lines);
        }
    }
    reject("not FLAC, MP3, Ogg or WAVE", -2)
}
