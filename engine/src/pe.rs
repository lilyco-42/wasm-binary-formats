//! Minimal, read-only PE header inspection for `.exe` / `.dll` files.
//!
//! This deliberately does not execute anything: running the guest needs an x86 machine, and
//! the two projects cited in the README that provide one cannot run Win32 PE in a browser.
//! What is achievable and useful is answering "what is this file" - machine, subsystem,
//! sections, DLL or not, .NET or not - without trusting any declared size.
//!
//! ABI (call after `parse_pe` returns 0):
//!
//!   parse_pe(ptr, len) -> i32      // 0 ok, negative = see the codes below
//!   pe_machine() -> i32            // IMAGE_FILE_MACHINE_* as a number, 0 if unset
//!   pe_magic() -> i32              // 0x10b PE32, 0x20b PE32+
//!   pe_entry_rva() -> i64
//!   pe_image_base() -> i64
//!   pe_subsystem() -> i32
//!   pe Characteristics() -> i32
//!   pe_sections(buf, cap) -> i32   // "name\trva\tvsize\trawsize\trawptr\tchars" per line
//!   pe_cli_rva() -> i64            // > 0 means a .NET assembly

use std::cell::RefCell;

const MACHINE_UNKNOWN: i32 = 0;

#[derive(Default, Clone)]
struct Header {
    machine: i32,
    magic: i32,
    entry_rva: i64,
    image_base: i64,
    subsystem: i32,
    characteristics: i32,
    cli_rva: i64,
    sections: Vec<Section>,
}

#[derive(Default, Clone)]
struct Section {
    name: String,
    virtual_address: i64,
    virtual_size: i64,
    raw_size: i64,
    raw_pointer: i64,
    characteristics: i64,
}

thread_local! {
    static PE: RefCell<Option<Header>> = const { RefCell::new(None) };
}

fn fail(message: &str, code: i32) -> i32 {
    crate::set_error(message);
    PE.with(|slot| *slot.borrow_mut() = None);
    code
}

struct Le<'a>(&'a [u8]);

impl Le<'_> {
    fn at(&self, offset: usize) -> Option<Self> {
        if offset <= self.0.len() {
            Some(Self(&self.0[offset..]))
        } else {
            None
        }
    }

    fn u16(&self, offset: usize) -> Option<i32> {
        let end = offset.checked_add(2)?;
        if end > self.0.len() {
            return None;
        }
        Some(i32::from(u16::from_le_bytes(
            self.0[offset..end].try_into().unwrap(),
        )))
    }

    fn u32(&self, offset: usize) -> Option<i64> {
        let end = offset.checked_add(4)?;
        if end > self.0.len() {
            return None;
        }
        Some(i64::from(u32::from_le_bytes(
            self.0[offset..end].try_into().unwrap(),
        )))
    }

    fn u64(&self, offset: usize) -> Option<i64> {
        let end = offset.checked_add(8)?;
        if end > self.0.len() {
            return None;
        }
        Some(u64::from_le_bytes(self.0[offset..end].try_into().unwrap()) as i64)
    }
}

fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end])
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// -1 empty input, -2 not MZ, -3 no PE signature, -4 optional header truncated,
/// -5 e_lfanew out of range.
pub fn parse(bytes: &[u8]) -> i32 {
    if bytes.len() < 64 {
        return fail("too small to be a PE file", -1);
    }
    let file = Le(bytes);
    if file.u16(0) != Some(0x5a4d) {
        return fail("missing MZ signature", -2);
    }
    let Some(lfanew) = file.u32(0x3c) else {
        return fail("truncated DOS header", -1);
    };
    if lfanew < 64 || lfanew + 24 > bytes.len() as i64 {
        return fail("e_lfanew points outside the file", -5);
    }
    let lfanew = lfanew as usize;
    let Some(pe) = file.at(lfanew) else {
        return fail("e_lfanew out of range", -5);
    };
    if pe.u32(0).map(|v| v & 0xffff) != Some(0x4550) {
        return fail("missing PE\\0\\0 signature", -3);
    }
    let magic = pe.u16(24).unwrap_or_default();
    if magic != 0x10b && magic != 0x20b {
        return fail("unknown optional header magic", -4);
    }
    let size_of_optional = pe.u16(16).unwrap_or_default() as usize;
    let dirs = if magic == 0x10b { 24 + 96 } else { 24 + 112 };
    let header = Header {
        machine: pe.u16(4).unwrap_or(MACHINE_UNKNOWN),
        characteristics: pe.u16(18).unwrap_or_default(),
        magic,
        // AddressOfEntryPoint and Subsystem sit at the same offset in both optional header
        // flavours; only ImageBase moves. Offsets below are from the start of the NT headers,
        // which are 24 bytes of signature + file header before the optional header.
        entry_rva: pe.u32(40).unwrap_or_default(),
        image_base: if magic == 0x10b {
            pe.u32(52).unwrap_or_default()
        } else {
            pe.u64(48).unwrap_or_default()
        },
        subsystem: pe.u16(92).unwrap_or_default(),
        // COM descriptor directory is index 14 of the data directories, eight bytes each.
        cli_rva: if size_of_optional >= dirs - 24 + 15 * 8 {
            pe.u32(dirs + 14 * 8).unwrap_or_default()
        } else {
            0
        },
        sections: Vec::new(),
    };

    // Section table follows the optional header. Its offset is derived from the declared
    // optional-header size, which is attacker controlled, so every read is bounds-checked.
    let sections_at = 24 + size_of_optional;
    let count = pe.u16(6).unwrap_or_default().max(0) as usize;
    let mut sections = Vec::new();
    if let Some(start) = lfanew.checked_add(sections_at) {
        for index in 0..count {
            let Some(entry) = file.at(start + index * 40) else {
                break;
            };
            if entry.0.len() < 40 {
                break;
            }
            let name = section_name(&entry.0[..8]);
            sections.push(Section {
                virtual_address: entry.u32(12).unwrap_or_default(),
                virtual_size: entry.u32(8).unwrap_or_default(),
                raw_size: entry.u32(16).unwrap_or_default(),
                raw_pointer: entry.u32(20).unwrap_or_default(),
                characteristics: entry.u32(36).unwrap_or_default(),
                name,
            });
        }
    }
    header.sections = sections;
    PE.with(|slot| *slot.borrow_mut() = Some(header));
    0
}

fn with_header<T: Copy>(default: T, read: impl Fn(&Header) -> T) -> T {
    PE.with(|slot| slot.borrow().as_ref().map_or(default, read))
}

pub fn machine() -> i32 {
    with_header(MACHINE_UNKNOWN, |header| header.machine)
}
pub fn magic() -> i32 {
    with_header(0, |header| header.magic)
}
pub fn entry_rva() -> i64 {
    with_header(0, |header| header.entry_rva)
}
pub fn image_base() -> i64 {
    with_header(0, |header| header.image_base)
}
pub fn subsystem() -> i32 {
    with_header(0, |header| header.subsystem)
}
pub fn characteristics() -> i32 {
    with_header(0, |header| header.characteristics)
}
pub fn cli_rva() -> i64 {
    with_header(0, |header| header.cli_rva)
}

pub fn sections() -> String {
    with_header(String::new(), |header| {
        header
            .sections
            .iter()
            .map(|section| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    section.name,
                    section.virtual_address,
                    section.virtual_size,
                    section.raw_size,
                    section.raw_pointer,
                    section.characteristics
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}
