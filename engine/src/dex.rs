//! DEX (Dalvik executable) header inspection - the `classes.dex` inside an APK.
//!
//! Read-only, like the PE reader: everything reported comes from the fixed 0x70-byte header, and
//! nothing here attempts to decode bytecode. Offsets follow the DEX format in the Android source:
//! magic[8] at 0, checksum 0x08, signature[20] 0x0C, file_size 0x20, header_size 0x24,
//! endian_tag 0x28, map_off 0x34, string_ids_size 0x38, type_ids_size 0x40, field_ids_size 0x50,
//! method_ids_size 0x58, class_defs_size 0x60.

use crate::scan::Le;
use std::cell::RefCell;

const ENDIAN_CONSTANT: i64 = 0x1234_5678;
const HEADER_SIZE: i64 = 0x70;

#[derive(Default, Clone)]
struct Header {
    version: String,
    checksum: i64,
    file_size: i64,
    header_size: i64,
    map_off: i64,
    string_ids: i64,
    type_ids: i64,
    method_ids: i64,
    class_defs: i64,
}

thread_local! {
    static DEX: RefCell<Option<Header>> = const { RefCell::new(None) };
}

fn fail(message: &str, code: i32) -> i32 {
    crate::set_error(message);
    DEX.with(|slot| *slot.borrow_mut() = None);
    code
}

/// -1 too small, -2 bad magic, -3 bad endian constant, -4 unexpected header size.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < HEADER_SIZE as usize {
        return fail("too small to hold a DEX header", -1);
    }
    let file = Le(bytes);
    if file.bytes(0, 4) != Some(&b"dex\n"[..]) {
        return fail("missing dex\\n magic", -2);
    }
    if file.u32(0x28) != Some(ENDIAN_CONSTANT) {
        return fail("unexpected endian constant", -3);
    }
    let header_size = match file.u32(0x24) {
        Some(size) => size,
        None => return fail("truncated header size", -1),
    };
    if header_size != HEADER_SIZE {
        return fail("header size is not 0x70", -4);
    }
    let version = match file.bytes(4, 3) {
        Some(v) => crate::scan::utf8_or_hex(v),
        None => String::new(),
    };
    DEX.with(|slot| {
        *slot.borrow_mut() = Some(Header {
            version,
            checksum: file.u32(0x08).unwrap_or_default(),
            file_size: file.u32(0x20).unwrap_or_default(),
            header_size,
            map_off: file.u32(0x34).unwrap_or_default(),
            string_ids: file.u32(0x38).unwrap_or_default(),
            type_ids: file.u32(0x40).unwrap_or_default(),
            method_ids: file.u32(0x58).unwrap_or_default(),
            class_defs: file.u32(0x60).unwrap_or_default(),
        })
    });
    0
}

fn with<T: Copy>(default: T, read: impl Fn(&Header) -> T) -> T {
    DEX.with(|slot| slot.borrow().as_ref().map_or(default, read))
}

pub fn version() -> String {
    with(String::new(), |header| header.version.clone())
}
pub fn checksum() -> i64 {
    with(0, |header| header.checksum)
}
pub fn file_size() -> i64 {
    with(0, |header| header.file_size)
}
pub fn header_size() -> i64 {
    with(0, |header| header.header_size)
}
pub fn map_off() -> i64 {
    with(0, |header| header.map_off)
}
pub fn string_ids() -> i64 {
    with(0, |header| header.string_ids)
}
pub fn type_ids() -> i64 {
    with(0, |header| header.type_ids)
}
pub fn method_ids() -> i64 {
    with(0, |header| header.method_ids)
}
pub fn class_defs() -> i64 {
    with(0, |header| header.class_defs)
}
