//! Optional analysis module: the section and symbol tables of a compiled binary.
//!
//! This crate is deliberately *not* linked into `apk-lens.wasm`. The structural readers there answer
//! for hundreds of formats in a module every visitor downloads; a real object-file analyser is a
//! different order of magnitude, and most visitors never look at a PE or an ELF. So this builds its
//! own module - `apk-lens-analysis.wasm` - which the page fetches only when the analysis row is
//! clicked, and which reports its own exports and byte size once it is there.
//!
//! What it says is the layout, not the meaning: the container's own section table, its symbol table,
//! the counts the two add up to, and an index from address to name over those tables. Nothing is loaded
//! into memory, nothing is relocated, and no byte of a section is executed or interpreted as an
//! instruction - instruction decoding is a separate module with its own download.
//!
//! The address index is the part an analyser is named for. A symbol table is a list; a disassembly
//! needs the other direction, so [`name_for`] answers what `objdump -d` prints beside an instruction -
//! `answer` at a symbol, `helper+0x9` nine bytes into one. It covers the formats the object reader
//! covers, which is images *and* a `clang -c` object: `object`'s `read` feature includes COFF, and its
//! file-kind dispatch keys on the machine field at byte zero, so a relocatable object comes back with
//! `kind relocatable` and section-relative symbol addresses - the same basis the disassembler is handed
//! for one of those files.

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use std::cell::RefCell;

/// Rows past this are counted but not listed, so a 4 000-section file cannot make the report huge.
const MAX_LISTED: usize = 64;

thread_local! {
    static REPORT: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// The address index behind [`name_for`], rebuilt by every call to [`analyse`]. Sorted by address,
    /// so it is the last file's: the rows and the names always describe the same bytes.
    static NAMES: RefCell<Vec<(u64, String)>> = RefCell::new(Vec::new());
    /// The byte-region map of the same file, in file order. Rows rather than spans, because the page only
    /// ever asks for one at a time: a colour per range, and a count of the bytes no range claims.
    static REGIONS: RefCell<Vec<String>> = RefCell::new(Vec::new());
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

/// A name the address index can carry, or `None` for a symbol that does not own an address.
///
/// Two exclusions, both from what the row already says: a *section* symbol names a range rather than a
/// point (and an object file has one per section, all at offset zero), and a *file* symbol names a
/// compilation unit. A symbol with no section is left out too - an import, an absolute value like
/// clang's `@feat.00`, or a debug entry - because its address column is a zero the reader invented
/// rather than a place something lives.
fn name_pair<'data, T: ObjectSymbol<'data>>(symbol: &T) -> Option<(u64, String)> {
    if symbol.section_index().is_none() || symbol.is_undefined() {
        return None;
    }
    if matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File) {
        return None;
    }
    let name = clean(symbol.name().unwrap_or(""));
    if name.trim().is_empty() {
        return None;
    }
    Some((symbol.address(), name))
}

/// The name an address answers with, in the spelling `objdump -d` uses: `answer` at the symbol itself,
/// `helper+0x9` nine bytes past one. The nearest name *below* the address wins, with no bound on the
/// distance - which is what objdump does, and what an object file permits, since a symbol there carries
/// no size to stop it.
pub fn name_for(address: u64) -> Option<String> {
    NAMES.with(|names| {
        let names = names.borrow();
        let last = names
            .partition_point(|(at, _)| *at <= address)
            .checked_sub(1)?;
        let (at, name) = &names[last];
        Some(if *at == address {
            name.clone()
        } else {
            format!("{name}+0x{:x}", address - at)
        })
    })
}

/// How many addresses the index carries, which is not the number of symbols the file has.
pub fn names_len() -> usize {
    NAMES.with(|names| names.borrow().len())
}

pub fn analyse(bytes: &[u8]) -> Option<Vec<String>> {
    // A file that is not an object file leaves no names standing either, for the same reason it leaves
    // no rows: the panel would otherwise show the previous file's answers under this file's rows.
    NAMES.with(|slot| slot.borrow_mut().clear());
    let file = object::File::parse(bytes).ok()?;
    let mut rows = Vec::new();
    let mut named: Vec<(u64, String)> = Vec::new();
    let mut sections = 0usize;
    let mut symbols = 0usize;
    let mut imported = 0usize;

    for (index, section) in file.sections().enumerate() {
        sections += 1;
        if index >= MAX_LISTED {
            continue;
        }
        let range = section.file_range();
        rows.push(format!(
            "section\t{index}\t{}\taddr\t{}\toff\t{}\tsize\t{}\tdisk\t{}\talign\t{}",
            clean(section.name().unwrap_or("?")),
            section.address(),
            // The on-disk position and length, not just the address: the disassembler module is
            // handed bytes from here, and an address says nothing about where they lie in the file.
            range.map_or(u64::MAX, |(at, _)| at),
            section.size(),
            range.map_or(0, |(_, size)| size),
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
        // The index is not capped by MAX_LISTED: a name is worth finding precisely when the table is
        // too long to read as a list.
        named.extend(name_pair(&symbol));
    }
    for (index, symbol) in file.dynamic_symbols().enumerate() {
        imported += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("dynsym", index, &symbol));
        }
        named.extend(name_pair(&symbol));
    }
    if symbols > MAX_LISTED {
        rows.push(format!("cut\tsymbols\t{symbols}"));
    }
    if imported > MAX_LISTED {
        rows.push(format!("cut\tdynsym\t{imported}"));
    }

    // Two names for one address are the file's ambiguity, not the reader's: `sort_by` is stable, so the
    // table's own order decides and the first listing keeps the name.
    named.sort_by(|left, right| left.0.cmp(&right.0));
    named.dedup_by(|later, earlier| later.0 == earlier.0);
    NAMES.with(|slot| *slot.borrow_mut() = named);
    REGIONS.with(|slot| *slot.borrow_mut() = region_rows(bytes));

    rows.insert(
        0,
        format!(
            "file\t{}\tbits\t{}\tendian\t{}\tkind\t{}\tmachine\t{}\tsections\t{sections}\tsymbols\t{symbols}\tdynsym\t{imported}\tentry\t{}",
            label(&file.format()),
            if file.is_64() { 64 } else { 32 },
            if file.is_little_endian() { "little" } else { "big" },
            label(&file.kind()),
            // Named by the reader's own enum, lower-cased: the disassembler module has to be told
            // which instruction set to open, and this is the only place that says so. The row calls
            // it `machine`, the way the header field does, while this reader's method is
            // `architecture`.
            label(&file.architecture()),
            file.entry()
        ),
    );
    Some(rows)
}

/// One byte range the file names for itself, and what it says it is.
///
/// The section table gives this reader its rows; the map needs the *header* tables too, because the
/// question a colour answers is "does anything read these bytes", and that is decided by every table the
/// file points at plus the segments it asks the loader to map - not by the sections alone.
#[derive(Clone)]
struct Span {
    start: u64,
    length: u64,
    kind: &'static str,
    name: String,
    note: String,
}

fn span(start: u64, length: u64, kind: &'static str, name: &str, note: &str) -> Option<Span> {
    if length == 0 {
        return None;
    }
    Some(Span {
        start,
        length,
        kind,
        name: name.to_owned(),
        note: note.to_owned(),
    })
}

fn half_at(raw: &[u8], at: usize, little: bool) -> Option<u64> {
    let pair: [u8; 2] = raw.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    } as u64)
}

fn word_at(raw: &[u8], at: usize, little: bool) -> Option<u64> {
    let four: [u8; 4] = raw.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(four)
    } else {
        u32::from_be_bytes(four)
    } as u64)
}

fn addr_at(raw: &[u8], at: usize, wide: bool, little: bool) -> Option<u64> {
    if !wide {
        return word_at(raw, at, little);
    }
    let eight: [u8; 8] = raw.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(eight)
    } else {
        u64::from_be_bytes(eight)
    })
}

fn cstr_at(raw: &[u8], at: usize) -> String {
    let end = raw.get(at..).map_or(at, |rest| {
        rest.iter().position(|byte| *byte == 0).map_or(at, |found| at + found)
    });
    String::from_utf8_lossy(raw.get(at..end).unwrap_or(&[]))
        .chars()
        .map(|each| if each == '\t' || each == '\n' || each.is_control() { '?' } else { each })
        .collect()
}

fn elf_spans(raw: &[u8]) -> Option<(Vec<Span>, Vec<(u64, u64)>)> {
    if raw.len() < 64 || !raw.starts_with(b"\x7fELF") {
        return None;
    }
    let wide = raw[4] == 2;
    let little = raw[5] == 1;
    // e_ident is sixteen bytes in both classes, so `e_entry` sits at 24 either way and every pointer-wide
    // field after it shifts the two-byte tail of the header from 40 to 52.
    let (phoff, shoff) = (addr_at(raw, if wide { 32 } else { 28 }, wide, little)?,
                          addr_at(raw, if wide { 40 } else { 32 }, wide, little)?);
    let (phentsize, phnum) = (
        half_at(raw, if wide { 54 } else { 42 }, little)?,
        half_at(raw, if wide { 56 } else { 44 }, little)?,
    );
    let (shentsize, shnum) = (
        half_at(raw, if wide { 58 } else { 46 }, little)?,
        half_at(raw, if wide { 60 } else { 48 }, little)?,
    );
    let shstrndx = half_at(raw, if wide { 62 } else { 50 }, little)?;
    let strtab_at = {
        // A file that points its own string table off the end still gets its sections listed - they come
        // back named by what the table should have said, which is nothing.
        let entry = shoff.checked_add(shstrndx.checked_mul(shentsize)?)?;
        let at = entry as usize + if wide { 24 } else { 16 };
        addr_at(raw, at, wide, little).unwrap_or(0)
    };
    let mut spans = Vec::new();
    let first = if phoff == 0 {
        shoff
    } else if shoff == 0 {
        phoff
    } else {
        phoff.min(shoff)
    };
    spans.extend(span(0, first, "header", "elf header", ""));
    spans.extend(span(phoff, phentsize.checked_mul(phnum)?, "tables", "program headers", ""));
    spans.extend(span(shoff, shentsize.checked_mul(shnum)?, "tables", "section headers", ""));
    let mut loaded = Vec::new();
    let mut index = 0u64;
    while index < phnum.min(64) {
        // Each entry is read or the walk stops: a file whose program headers run off its own end still
        // has a header, a section table and gaps worth showing, and voiding the map for that would hide
        // them behind one bad count.
        let at = match phoff.checked_add(index.checked_mul(phentsize)) {
            Some(at) => match usize::try_from(at) {
                Ok(value) => value,
                Err(_) => break,
            },
            None => break,
        };
        index += 1;
        if word_at(raw, at, little).unwrap_or(0) != PT_LOAD {
            continue;
        }
        let pair = if wide {
            match (addr_at(raw, at + 8, true, little), addr_at(raw, at + 32, true, little)) {
                (Some(one), Some(other)) => (one, other),
                _ => break,
            }
        } else {
            match (word_at(raw, at + 4, little), word_at(raw, at + 16, little)) {
                (Some(one), Some(other)) => (one, other),
                _ => break,
            }
        };
        match pair.0.checked_add(pair.1) {
            Some(stop) => loaded.push((pair.0, stop)),
            None => break,
        }
    }
    let mut index = 0u64;
    while index < shnum.min(256) {
        let at = match shoff.checked_add(index.checked_mul(shentsize)) {
            Some(at) => match usize::try_from(at) {
                Ok(value) => value,
                Err(_) => break,
            },
            None => break,
        };
        index += 1;
        let name_off = match word_at(raw, at, little) {
            Some(value) => value as usize,
            None => break,
        };
        let sh_type = match word_at(raw, at + 4, little) {
            Some(value) => value,
            None => break,
        };
        let sh_flags = match addr_at(raw, at + 8, wide, little) {
            Some(value) => value,
            None => break,
        };
        let fields = if wide {
            match (
                addr_at(raw, at + 16, true, little),
                addr_at(raw, at + 24, true, little),
                addr_at(raw, at + 32, true, little),
            ) {
                (Some(one), Some(other), Some(third)) => (one, other, third),
                _ => break,
            }
        } else {
            match (
                word_at(raw, at + 12, little),
                word_at(raw, at + 16, little),
                word_at(raw, at + 20, little),
            ) {
                (Some(one), Some(other), Some(third)) => (one, other, third),
                _ => break,
            }
        };
        let (sh_addr, sh_off, sh_size) = fields;
        let name = match strtab_at.checked_add(name_off as u64) {
            Some(where_at) => cstr_at(raw, where_at as usize),
            None => cstr_at(raw, 0),
        };
        if sh_type == SHT_NULL || sh_type == SHT_NOBITS || sh_size == 0 {
            continue;
        }
        let allocated = sh_flags & SHF_ALLOC != 0;
        let note = if allocated {
            format!("loaded at {:#x}", sh_addr)
        } else {
            "not loaded".to_owned()
        };
        let meta = !allocated
            || META_TYPES.contains(&sh_type)
            || name.starts_with(".debug")
            || name.starts_with(".zdebug")
            || name.starts_with(".comment")
            || name.starts_with(".note")
            || name.starts_with(".rel")
            || name.starts_with(".symtab")
            || name.starts_with(".strtab");
        let kind = if meta {
            "meta"
        } else if sh_flags & SHF_EXECINSTR != 0 || name.starts_with(".text") || name.starts_with(".plt") {
            "code"
        } else if sh_flags & SHF_WRITE != 0 {
            "data"
        } else {
            "rodata"
        };
        spans.extend(span(sh_off, sh_size, kind, &name, &note));
    }
    Some((spans, loaded))
}

const PT_LOAD: u64 = 1;
const SHT_NULL: u64 = 0;
const SHT_NOBITS: u64 = 8;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
/// Section types that hold structure a tool reads rather than data the program runs on.
const META_TYPES: &[u64] = &[2, 3, 4, 5, 6, 7, 9, 0x6FFF_FF00, 0x6FFF_FFFF];

fn pe_spans(raw: &[u8]) -> Option<Vec<Span>> {
    if raw.len() < 0x40 || !raw.starts_with(b"MZ") {
        return None;
    }
    let lfanew = word_at(raw, 0x3c, true)? as usize;
    if raw.get(lfanew..).map_or(true, |rest| !rest.starts_with(b"PE\0\0")) {
        return None;
    }
    let nsec = half_at(raw, lfanew + 6, true)?;
    let symtab = word_at(raw, lfanew + 12, true)?;
    let nsyms = word_at(raw, lfanew + 16, true)?;
    let optsz = half_at(raw, lfanew + 20, true)? as usize;
    let opt = lfanew.checked_add(24)?;
    let magic = half_at(raw, opt, true)?;
    let plus = magic == 0x20b;
    let dirs_at = opt.checked_add(if plus { 112 } else { 96 })?;
    let size_of_headers = word_at(raw, opt + 60, true)?;
    let mut spans = Vec::new();
    spans.extend(span(0, size_of_headers, "header", "ms-dos stub and nt headers", ""));
    let table = opt.checked_add(optsz)?;
    spans.extend(span(table as u64, nsec.checked_mul(40)?, "tables", "section headers", ""));
    if symtab != 0 && nsyms != 0 {
        spans.extend(span(symtab, nsyms.checked_mul(18)?, "meta", "coff symbols", "not loaded"));
    }
    let mut index = 0u64;
    while index < nsec.min(192) {
        let at = match table.checked_add(usize::try_from(index.checked_mul(40)).unwrap_or(usize::MAX)) {
            Some(at) => at,
            None => break,
        };
        index += 1;
        let bytes = match raw.get(at..at.checked_add(8)?) {
            Some(value) => value,
            None => break,
        };
        let trimmed = match bytes.iter().position(|byte| *byte == 0) {
            Some(end) => &bytes[..end],
            None => bytes,
        };
        let name = String::from_utf8_lossy(trimmed).into_owned();
        let (vsize, vaddr, rawsize, roff, chars) = match (
            word_at(raw, at + 8, true),
            word_at(raw, at + 12, true),
            word_at(raw, at + 16, true),
            word_at(raw, at + 20, true),
            word_at(raw, at + 36, true),
        ) {
            (Some(one), Some(two), Some(three), Some(four), Some(five)) => {
                (one, two, three, four, five)
            }
            _ => break,
        };
        if rawsize == 0 {
            continue;
        }
        // Only the bytes the section states it *uses* are named; what is left of its raw span is file
        // alignment, and the merge below colours that as a gap rather than letting the section claim it.
        let used = if vsize == 0 { rawsize } else { rawsize.min(vsize) };
        let note = format!("vaddr {:#x}, raw {:#x} in file", vaddr, rawsize);
        spans.extend(span(roff, used, pe_kind(&name, chars), &name, &note));
    }
    let directories = if optsz >= dirs_at - opt {
        word_at(raw, dirs_at - 4, true).unwrap_or(0)
    } else {
        0
    };
    if directories > 4 {
        let (rva, size) = (
            word_at(raw, dirs_at + 32, true)?,
            word_at(raw, dirs_at + 36, true)?,
        );
        // The certificate directory is the one entry that holds a file offset rather than an RVA, so it
        // can be coloured without translating anything.
        spans.extend(span(rva, size, "cert", "authenticode", "a file offset, not an rva"));
    }
    Some(spans)
}

fn pe_kind(name: &str, chars: u64) -> &'static str {
    const CNT_CODE: u64 = 0x0020;
    const CNT_INIT: u64 = 0x0040;
    const MEM_EXECUTE: u64 = 0x2000_0000;
    const MEM_WRITE: u64 = 0x8000_0000;
    let structure = name.starts_with(".debug")
        || name.starts_with(".reloc")
        || name.starts_with(".pdata")
        || name.starts_with(".xdata");
    if structure && chars & CNT_CODE == 0 {
        "meta"
    } else if chars & MEM_EXECUTE != 0 {
        "code"
    } else if chars & MEM_WRITE != 0 {
        "data"
    } else if chars & CNT_CODE != 0 && chars & CNT_INIT == 0 {
        "code"
    } else if name == ".rdata" || name == ".rodata" || chars & CNT_INIT != 0 {
        "rodata"
    } else {
        "meta"
    }
}

/// The map: every range the file names, in order, with what falls between them called what it is -
/// padding inside a segment the loader maps, or bytes no table and no segment reaches at all.
fn region_rows(raw: &[u8]) -> Vec<String> {
    let (mut spans, loaded) = match elf_spans(raw) {
        Some(found) => (found.0, found.1),
        None => (match pe_spans(raw) {
            Some(found) => (found, Vec::new()),
            None => return Vec::new(),
        }),
    };
    spans.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| rank(left).cmp(&rank(right)))
            .then_with(|| left.name.cmp(&right.name))
    });
    fn rank(each: &Span) -> u8 {
        if each.kind == "gap" {
            1
        } else {
            0
        }
    }
    let mut merged: Vec<Span> = Vec::new();
    let mut cursor = 0u64;
    let mut unloaded = 0u64;
    let mut idle_mapped = 0u64;
    let total = raw.len() as u64;
    let annotate = |note: &str, extra: &str| {
        if note.is_empty() {
            extra.to_owned()
        } else {
            format!("{} {}", note, extra)
        }
    };
    for each in spans {
        let mut start = each.start;
        let mut length = each.length;
        if start >= total {
            // A table that points off the end of the file claims nothing, so it does not get a colour
            // either: the overlay row below covers what is left and the map still tiles the file.
            break;
        }
        if start < cursor {
            let drop = cursor - start;
            if drop >= length {
                continue;
            }
            start = cursor;
            length -= drop;
        }
        if start > cursor {
            let gap = start - cursor;
            let inside = loaded
                .iter()
                .any(|(at, stop)| *at <= cursor && start <= *stop);
            if inside {
                idle_mapped += gap;
            } else {
                unloaded += gap;
            }
            merged.push(Span {
                start: cursor,
                length: gap,
                kind: "gap",
                name: if inside { "alignment padding" } else { "unreferenced" }.to_owned(),
                note: if inside { "loaded but unaddressed" } else { "not loaded" }.to_owned(),
            });
        }
        let stop = match start.checked_add(length) {
            Some(stop) => stop,
            None => break,
        };
        // A table that states a span reaching past the end of the file is clipped and says so, rather
        // than leaving the map with a range whose colour would have to be invented.
        let (length, note) = if stop > total {
            (total - start, annotate(&each.note, "beyond end of file"))
        } else if start != each.start {
            (length, annotate(&each.note, "overlaps"))
        } else {
            (length, each.note)
        };
        if length == 0 {
            continue;
        }
        merged.push(Span {
            start,
            length,
            kind: each.kind,
            name: each.name,
            note,
        });
        // `length` is either the file's own span, which was just checked to end inside the file, or the
        // clipped remainder - so this addition cannot overflow in either branch.
        cursor = cursor.max(start + length);
    }
    if cursor < raw.len() as u64 {
        let tail = raw.len() as u64 - cursor;
        unloaded += tail;
        merged.push(Span {
            start: cursor,
            length: tail,
            kind: "overlay",
            name: "after the last table".to_owned(),
            note: "not loaded".to_owned(),
        });
    }
    let listed = merged.len().min(MAX_REGIONS);
    // The totals describe the whole map, not the screenful the rows list.
    let claimed: u64 = merged
        .iter()
        .filter(|each| each.kind != "gap" && each.kind != "overlay")
        .map(|each| each.length)
        .sum();
    let mut rows = vec![format!(
        "regions\t{}\tfile\t{}\tclaimed\t{claimed}\tunloaded\t{unloaded}\tloaded-unaddressed\t{idle_mapped}",
        merged.len(),
        raw.len()
    )];
    if merged.len() > listed {
        rows.push(format!("cut\tregions\t{}", merged.len()));
    }
    for each in merged.iter().take(listed) {
        rows.push(format!(
            "region\t{}\t{}\t{}\t{}\t{}",
            each.start,
            each.length,
            each.kind,
            each.name,
            if each.note.is_empty() { "-" } else { &each.note }
        ));
    }
    rows
}

/// Regions listed before the report says it stopped. A stripped binary needs a dozen; a debug build with
/// a hundred sections and their relocations does not need all of them on one screen.
const MAX_REGIONS: usize = 256;

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
            REGIONS.with(|stored| stored.borrow_mut().clear());
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

/// How many addresses the index carries. This is not `symbols` from the header row: the table lists
/// every symbol, the index keeps the ones that own an address.
#[no_mangle]
pub extern "C" fn names_count() -> i32 {
    names_len() as i32
}

/// The name of the nearest address at or below `address`, objdump's spelling, or -1 when the index is
/// empty - which is what a stripped binary leaves it as.
#[no_mangle]
pub extern "C" fn name_at(address: i64, out: *mut u8, cap: i32) -> i32 {
    if address < 0 {
        return -1;
    }
    match name_for(address as u64) {
        Some(text) => copy(&text, out, cap),
        None => -1,
    }
}

/// How many ranges the map holds for the last file analysed, including the gaps between them.
#[no_mangle]
pub extern "C" fn region_count() -> i32 {
    REGIONS.with(|rows| rows.borrow().len() as i32)
}

/// One range: `region`, then start, length, kind, name and note tab-separated, with row zero the
/// totals. The kind
/// is what the page colours by; `note` says whether the bytes are unreferenced because nothing names
/// them or because no segment reaches them at all.
#[no_mangle]
pub extern "C" fn region_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    REGIONS.with(|rows| match rows.borrow().get(index as usize) {
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
