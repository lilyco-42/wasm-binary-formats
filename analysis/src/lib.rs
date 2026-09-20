//! Optional analysis module: the section and symbol tables of a compiled binary.
//!
//! This crate is deliberately *not* linked into `apk-lens.wasm`. The structural readers there answer
//! for hundreds of formats in a module every visitor downloads; a real object-file analyser is a
//! different order of magnitude, and most visitors never look at a PE or an ELF. So this builds its
//! own module - `apk-lens-analysis.wasm` - which the page fetches only when the analysis row is
//! clicked, and which reports its own exports and byte size once it is there.
//!
//! What it says is the layout, not the meaning: the container's own section table, its symbol table,
//! and the counts the two add up to. Nothing is loaded into memory, nothing is relocated, and no byte
//! of a section is executed or interpreted as an instruction - instruction decoding is a separate
//! module with its own download.

use object::{Object, ObjectSection, ObjectSymbol};
use std::cell::RefCell;

/// Rows past this are counted but not listed, so a 4 000-section file cannot make the report huge.
const MAX_LISTED: usize = 64;

thread_local! {
    static REPORT: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

/// Names come out of the file, and the report is tab-separated: a tab or a newline in a section name
/// would invent a column that the bytes do not have.
fn clean(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' => ' ',
            other => other,
        })
        .collect()
}

/// The reader's own enum naming, lower-cased, so a row says `elf` and `dynamic` rather than the
/// Debug spelling of whichever variant the crate happens to have.
fn label<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
        .chars()
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

/// A symbol row. Static and dynamic tables share the shape but not the lifetime, so both come
/// through here; the reader's symbol trait is parameterised over the input's lifetime.
fn symbol_row<'data, T: ObjectSymbol<'data>>(prefix: &str, index: usize, symbol: &T) -> String {
    format!(
        "{prefix}\t{index}\t{}\taddr\t{}\tsize\t{}\tkind\t{}\tsection\t{}",
        clean(symbol.name().unwrap_or("?")),
        symbol.address(),
        symbol.size(),
        label(&symbol.kind()),
        symbol
            .section_index()
            .map_or("-".to_owned(), |id| id.0.to_string())
    )
}

pub fn analyse(bytes: &[u8]) -> Option<Vec<String>> {
    let file = object::File::parse(bytes).ok()?;
    let mut rows = Vec::new();
    let mut sections = 0usize;
    let mut symbols = 0usize;
    let mut imported = 0usize;

    for (index, section) in file.sections().enumerate() {
        sections += 1;
        if index >= MAX_LISTED {
            continue;
        }
        rows.push(format!(
            "section\t{index}\t{}\taddr\t{}\toff\t{}\tsize\t{}\talign\t{}",
            clean(section.name().unwrap_or("?")),
            section.address(),
            // The file offset, not just the address: the disassembler module is handed bytes from
            // here, and an address says nothing about where the section lies in the file.
            section.offset().unwrap_or(u64::MAX),
            section.size(),
            section.align()
        ));
    }
    if sections > MAX_LISTED {
        rows.push(format!("cut\tsections\t{sections}"));
    }

    // Two tables, because a distribution binary is usually stripped: `.symtab` may be empty while
    // every import and export is still in `.dynsym`. Reading only the first would report a real
    // program as having no symbols at all.
    for (index, symbol) in file.symbols().enumerate() {
        symbols += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("symbol", index, &symbol));
        }
    }
    for (index, symbol) in file.dynamic_symbols().enumerate() {
        imported += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("dynsym", index, &symbol));
        }
    }
    if symbols > MAX_LISTED {
        rows.push(format!("cut\tsymbols\t{symbols}"));
    }
    if imported > MAX_LISTED {
        rows.push(format!("cut\tdynsym\t{imported}"));
    }

    rows.insert(
        0,
        format!(
            "file\t{}\tbits\t{}\tendian\t{}\tkind\t{}\tmachine\t{}\tsections\t{sections}\tsymbols\t{symbols}\tdynsym\t{imported}\tentry\t{}",
            label(&file.format()),
            if file.is_64() { 64 } else { 32 },
            if file.is_little_endian() { "little" } else { "big" },
            label(&file.kind()),
            // Named by the reader's own enum, lower-cased: the disassembler module has to be told
            // which instruction set to open, and this is the only place that says so.
            label(&file.machine()),
            file.entry()
        ),
    );
    Some(rows)
}

fn report_len() -> i32 {
    REPORT.with(|rows| rows.borrow().len() as i32)
}

fn copy(text: &str, out: *mut u8, cap: i32) -> i32 {
    // The full length comes back either way, so a caller that ran out of room can ask again with
    // more, the same contract `apk-lens` uses.
    let bytes = text.as_bytes();
    let room = cap.max(0) as usize;
    let keep = bytes.len().min(room);
    if !out.is_null() && keep > 0 {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, keep) };
    }
    bytes.len() as i32
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> *mut u8 {
    let size = len.max(0) as usize;
    let mut buffer: Vec<u8> = vec![0; size + 1];
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: i32) {
    if ptr.is_null() {
        return;
    }
    unsafe { drop(Vec::from_raw_parts(ptr, 0, len.max(0) as usize + 1)) };
}

/// -2 for a file this reader cannot open at all; 0 once the report is standing by.
#[no_mangle]
pub extern "C" fn analyse_run(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len < 0 {
        REPORT.with(|rows| rows.borrow_mut().clear());
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    match analyse(bytes) {
        Some(rows) => {
            REPORT.with(|stored| *stored.borrow_mut() = rows);
            0
        }
        None => {
            REPORT.with(|stored| stored.borrow_mut().clear());
            -2
        }
    }
}

#[no_mangle]
pub extern "C" fn analyse_count() -> i32 {
    report_len()
}

#[no_mangle]
pub extern "C" fn analyse_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    REPORT.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// Bumped whenever the row contract changes, so a page that was built against another build of this
/// module can say so instead of rendering rows it does not understand.
#[no_mangle]
pub extern "C" fn abi_version() -> i32 {
    1
}

/// Present so the loader has something to call the moment the module is instantiated: it answers the
/// question "did a real object file come through this ABI" without the page having to pick a fixture.
#[no_mangle]
pub extern "C" fn self_test() -> i32 {
    // The header of an ELF64 executable with a single string table of its own, built here so the
    // module is not depending on a file the browser may or may not hand it.
    analyse(&sample_elf()).map_or(-1, |rows| rows.len() as i32)
}

/// An ELF64 shared object in 199 bytes: a header, the null section, one string-table section that
/// names itself, and the name it names. `self_test` and the host tests both read it, so the number
/// the page reports after loading is the number this file is known to produce.
pub fn sample_elf() -> Vec<u8> {
    let mut out = vec![0u8; 64];
    out[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&3u16.to_le_bytes());
    out[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[40..48].copy_from_slice(&64u64.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&2u16.to_le_bytes());
    out[62..64].copy_from_slice(&1u16.to_le_bytes());
    // Section 0 is the null entry at 64; section 1 is the string table at 128 that names itself,
    // and its bytes are what follows at 192.
    out.extend_from_slice(&[0u8; 64]);
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(&1u32.to_le_bytes());
    header[4..8].copy_from_slice(&3u32.to_le_bytes());
    header[24..32].copy_from_slice(&192u64.to_le_bytes());
    header[32..40].copy_from_slice(&7u64.to_le_bytes());
    header[48..56].copy_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(b"\0.text\0");
    out
}
