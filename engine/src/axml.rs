//! Android binary XML (`AndroidManifest.xml`) string pool.
//!
//! A compiled manifest is a `RES_XML_TYPE` chunk whose first child is a `RES_STRING_POOL_TYPE`
//! chunk. Recovering that pool is what makes the file legible - class names, permission names and
//! the package string are all in it. Attribute-level decoding is deliberately not attempted here:
//! it needs the style/entry tables from `resources.arsc`, and guessing at them would report a
//! package name that is wrong some of the time.

use crate::scan::Le;
use std::cell::RefCell;

const RES_XML_TYPE: i32 = 0x0003;
const RES_STRING_POOL_TYPE: i32 = 0x0001;
const UTF8_FLAG: i64 = 0x0100;

thread_local! {
    static POOL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static POOL_META: RefCell<(i32, i64)> = const { RefCell::new((0, 0)) };
}

fn fail(message: &str, code: i32) -> i32 {
    crate::set_error(message);
    POOL.with(|slot| slot.borrow_mut().clear());
    POOL_META.with(|slot| *slot.borrow_mut() = (0, 0));
    code
}

fn read_utf8(bytes: &[u8]) -> String {
    // Two length prefixes (chars, then bytes), each 1 or 2 bytes with the high bit marking a
    // second byte; the string itself is NUL terminated.
    let mut at = 0usize;
    for _ in 0..2 {
        if at >= bytes.len() {
            break;
        }
        let skip = if bytes[at] & 0x80 != 0 { 2 } else { 1 };
        at = (at + skip).min(bytes.len());
    }
    let end = bytes[at..]
        .iter()
        .position(|b| *b == 0)
        .map_or(bytes.len(), |p| at + p);
    String::from_utf8_lossy(&bytes[at..end.min(bytes.len())]).into_owned()
}

fn read_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                0
            }
        })
        .collect();
    if units.is_empty() {
        return String::new();
    }
    // One length unit up front (two when the high bit marks a string longer than 32767 units),
    // then the characters, then a NUL terminator.
    let mut at = 1usize;
    if units[0] & 0x8000 != 0 {
        at = 2
    }
    if at > units.len() {
        return String::new();
    }
    let payload = &units[at..];
    let end = payload
        .iter()
        .position(|u| *u == 0)
        .unwrap_or(payload.len());
    String::from_utf16_lossy(&payload[..end])
}

/// -1 too small, -2 not a binary XML chunk, -3 no string pool where it must be.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < 16 {
        return fail("too small to be binary XML", -1);
    }
    let file = Le(bytes);
    if file.u16(0) != Some(RES_XML_TYPE) {
        return fail("not a RES_XML_TYPE chunk", -2);
    }
    let pool_at = file.u16(2).unwrap_or(8) as usize;
    let pool = match file.at(pool_at) {
        Some(chunk) => chunk,
        None => return fail("string pool header is past the end", -3),
    };
    if pool.u16(0) != Some(RES_STRING_POOL_TYPE) {
        return fail("no string pool at the expected offset", -3);
    }
    let count = pool.u32(8).unwrap_or(0).max(0);
    let flags = pool.u32(12).unwrap_or(0);
    let strings_start = pool.u32(16).unwrap_or(28).max(0) as usize;
    let chunk_size = pool.u32(4).unwrap_or(0).max(0) as usize;
    let available = chunk_size.min(bytes.len() - pool_at);
    let utf8 = flags & UTF8_FLAG != 0;

    let mut strings = Vec::new();
    for index in 0..count.min(4096) {
        // Offset table starts right after the 28-byte pool header.
        let Some(offset) = pool.u32(28 + index as usize * 4) else {
            break;
        };
        let start = strings_start + offset.max(0) as usize;
        if start >= available {
            break;
        }
        let tail = match bytes.get(pool_at + start..) {
            Some(slice) => slice,
            None => break,
        };
        let slice = if utf8 {
            tail
        } else {
            &tail[..(tail.len() - tail.len() % 2).min(tail.len())]
        };
        strings.push(if utf8 {
            read_utf8(slice)
        } else {
            read_utf16(slice)
        });
    }
    POOL.with(|slot| *slot.borrow_mut() = strings);
    POOL_META.with(|slot| *slot.borrow_mut() = (count as i32, flags));
    0
}

pub fn count() -> i32 {
    POOL.with(|slot| slot.borrow().len() as i32)
}

pub fn declared() -> i32 {
    POOL_META.with(|slot| slot.borrow().0)
}

pub fn flags() -> i64 {
    POOL_META.with(|slot| slot.borrow().1)
}

pub fn at(index: i32) -> Option<String> {
    POOL.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}
