//! Optional analysis module: the section and symbol tables of a compiled binary.
//!
//! This crate is deliberately *not* linked into `apk-lens.wasm`. The structural readers there answer
//! for hundreds of formats in a module every visitor downloads; a real object-file analyser is a
//! different order of magnitude, and most visitors never look at a PE or an ELF. So this builds its
//! own module - `apk-lens-analysis.wasm` - which the page fetches only when the analysis row is
//! clicked, and which reports its own exports and byte size once it is there.
//!
//! What it says is the layout, not the meaning: the container's own section table, its symbol table,
//! the counts the two add up to, an index from address to name over those tables, and a map of the file's
//! byte regions - header, tables, code, data, structure, signature, and the gaps none of them reaches -
//! which is what the page colours by. Nothing is loaded
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

mod demangle;

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
    /// The string list for the same file again, over the ranges the map calls loaded data. Kept apart
    /// from the map because a page that wants one should not have to read the other.
    static STRINGS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// The CodeView type records of the same file, from `.debug$T` if it has one. A row per record, the
    /// same shape as the other two: the page asks for one at a time.
    static TYPES: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// What a PE hands out: its export directory, one row per slot of the address table. Only a PE has
    /// one, so an ELF or a Mach-O leaves this empty - its exported names are already in the symbol rows.
    static EXPORTS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// What a PE asks for instead: its import directory, a row per DLL and a row per name. The other half
    /// of the same window, and empty for the same reason.
    static IMPORTS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    /// The C++ names in the same file's symbol tables and what this reader can say about them: one line
    /// of totals, then a line per mangled name in table order. Only names that begin `_Z` are listed,
    /// because that prefix is the whole of how an Itanium mangled name announces itself.
    static DEMANGLED: RefCell<Vec<String>> = RefCell::new(Vec::new());
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

/// A name to ask the C++ demangler about: the `_Z` prefix, and only the characters that prefix's
/// grammar is written with. A name carrying anything else - a `$` from a local label, a `.` from a
/// compiler-generated one - stays out of the list, because there is no reading of it this module can
/// defend.
fn mangled_name<'data, T: ObjectSymbol<'data>>(symbol: &T) -> Option<String> {
    let name = symbol.name().ok()?;
    if name.len() < 3 || !name.starts_with("_Z") {
        return None;
    }
    if !name.bytes().all(|byte| {
        matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'$')
    }) {
        return None;
    }
    Some(clean(name))
}

/// What the demangler makes of one name, with no file in the way. `None` means the same thing a row's
/// `out\t-` means: no spelling that two demanglers agree on was found for it.
pub fn demangle_name(name: &str) -> Option<String> {
    demangle::demangle(name)
}

/// The report on those names: totals, then one line per name in the order the symbol tables list them.
///
/// A name the demangler stops on is answered with `-` and the reason the reader can actually give - that
/// no two-witness spelling was found for it - rather than with a guess. `cxx.o`'s `_Z4varsPcPKwDn` is
/// that row: binutils writes `decltype(nullptr)` where LLVM writes `std::nullptr_t`, so neither is a
/// fact about the bytes.
fn demangle_rows(names: &[String]) -> Vec<String> {
    let solved = names
        .iter()
        .filter(|one| demangle::demangle(one).is_some())
        .count();
    let mut out = vec![format!(
        "demangle\tmangled\t{}\tdemangled\t{solved}\trefused\t{}\twitnesses\ttwo",
        names.len(),
        names.len() - solved
    )];
    for (index, name) in names.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        match demangle::demangle(name) {
            Some(text) => out.push(format!("sym\t{index}\tin\t{name}\tout\t{}", clean(&text))),
            None => out.push(format!(
                "sym\t{index}\tin\t{name}\tout\t-\twhy\tnot in the two-witness subset"
            )),
        }
    }
    if names.len() > MAX_LISTED {
        out.push(format!("cut\tdemangle\t{}", names.len()));
    }
    out
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
    // no rows: the panel would otherwise show the previous file's answers under this file's rows. The map
    // is cleared here too, because this function can give up before it reaches the point where it would
    // have been replaced - and a stale colour strip is exactly as wrong as a stale name.
    NAMES.with(|slot| slot.borrow_mut().clear());
    REGIONS.with(|slot| slot.borrow_mut().clear());
    STRINGS.with(|slot| slot.borrow_mut().clear());
    TYPES.with(|slot| slot.borrow_mut().clear());
    EXPORTS.with(|slot| slot.borrow_mut().clear());
    IMPORTS.with(|slot| slot.borrow_mut().clear());
    DEMANGLED.with(|slot| slot.borrow_mut().clear());
    if let Some((summary, listed)) = msf_types(bytes) {
        // A program database is not an object file - `object` refuses it, and with good reason - but
        // what a linker leaves beside an executable is the type stream, which is the answer a visitor
        // opening a `.pdb` came for. The region map and string list stay empty, because a PDB has no
        // loaded segments to map and no data a program runs.
        TYPES.with(|slot| *slot.borrow_mut() = listed);
        return Some(vec![summary]);
    }
    let file = object::File::parse(bytes).ok()?;
    let mut rows = Vec::new();
    let mut named: Vec<(u64, String)> = Vec::new();
    let mut mangled: Vec<String> = Vec::new();
    let mut types: Vec<String> = Vec::new();
    let mut sections = 0usize;
    let mut symbols = 0usize;
    let mut imported = 0usize;

    for (index, section) in file.sections().enumerate() {
        sections += 1;
        // Types live in a section a stripped file, or one carrying DWARF instead, does not have at all,
        // and it is the only section whose *contents* matter here rather than where they lie - so it is
        // taken by name, before the cap on listed sections could hide it in a file with many of them.
        if section.name().unwrap_or("") == ".debug$T" {
            if let Ok(body) = section.data() {
                types = type_rows(body);
            }
        }
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
        mangled.extend(mangled_name(&symbol));
    }
    for (index, symbol) in file.dynamic_symbols().enumerate() {
        imported += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("dynsym", index, &symbol));
        }
        named.extend(name_pair(&symbol));
        mangled.extend(mangled_name(&symbol));
    }
    if symbols > MAX_LISTED {
        rows.push(format!("cut\tsymbols\t{symbols}"));
    }
    if imported > MAX_LISTED {
        rows.push(format!("cut\tdynsym\t{imported}"));
    }

    let (exports, export_names) = export_rows(bytes);
    let (imports, import_names) = import_rows(bytes);
    EXPORTS.with(|slot| *slot.borrow_mut() = exports);
    IMPORTS.with(|slot| *slot.borrow_mut() = imports);
    let names = demangle_rows(&mangled);
    DEMANGLED.with(|slot| *slot.borrow_mut() = names);
    // The file's own symbol names come first, then the export table's, then the imports: an address a
    // linker named is still called that by the symbol table, and what is left to name is the exported
    // body and the slot the loader fills in.
    named.extend(export_names);
    named.extend(import_names);
    // Two names for one address are the file's ambiguity, not the reader's: `sort_by` is stable, so the
    // table's own order decides and the first listing keeps the name.
    named.sort_by(|left, right| left.0.cmp(&right.0));
    named.dedup_by(|later, earlier| later.0 == earlier.0);
    NAMES.with(|slot| *slot.borrow_mut() = named);
    let (regions, strings) = map_rows(bytes);
    REGIONS.with(|slot| *slot.borrow_mut() = regions);
    STRINGS.with(|slot| *slot.borrow_mut() = strings);
    TYPES.with(|slot| *slot.borrow_mut() = types);

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
        let at = match phoff.checked_add(index.checked_mul(phentsize).unwrap_or(u64::MAX)) {
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
        let at = match shoff.checked_add(index.checked_mul(shentsize).unwrap_or(u64::MAX)) {
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
    // The loader's basis, so an address in this map is comparable with an address a disassembly names:
    // `objdump -h` prints its VMA column the same way, and that is the column the fixture generator
    // checks the map against. Eight bytes wide in PE32+, four in PE32.
    let image_base = if plus {
        addr_at(raw, opt + 24, true, true)?
    } else {
        word_at(raw, opt + 28, true)?
    };
    let mut spans = Vec::new();
    spans.extend(span(0, size_of_headers, "header", "ms-dos stub and nt headers", ""));
    let table = opt.checked_add(optsz)?;
    spans.extend(span(table as u64, nsec.checked_mul(40)?, "tables", "section headers", ""));
    if symtab != 0 && nsyms != 0 {
        spans.extend(span(symtab, nsyms.checked_mul(18)?, "meta", "coff symbols", "not loaded"));
    }
    let mut index = 0u64;
    while index < nsec.min(192) {
        let step = index.checked_mul(40).unwrap_or(u64::MAX);
        let at = match table.checked_add(usize::try_from(step).unwrap_or(usize::MAX)) {
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
        let note = format!("vaddr {:#x}, raw {:#x} in file", image_base + vaddr, rawsize);
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

/// The header facts an RVA has to be walked through: the image base, the sections and where the data
/// directories begin. `pe_spans` reads the same fields for the map; this exists for the readers that
/// need to turn an address the file states into a byte position, which is a question the map never asks.
struct Pe {
    image_base: u64,
    dirs: usize,
    wide: bool,
    sections: Vec<(u64, u64, u64, String)>,
}

impl Pe {
    fn parse(raw: &[u8]) -> Option<Pe> {
        if raw.len() < 0x40 || !raw.starts_with(b"MZ") {
            return None;
        }
        let lfanew = word_at(raw, 0x3c, true)? as usize;
        if raw.get(lfanew..).map_or(true, |rest| !rest.starts_with(b"PE\0\0")) {
            return None;
        }
        let nsec = half_at(raw, lfanew + 6, true)?;
        let optsz = half_at(raw, lfanew + 20, true)? as usize;
        let opt = lfanew.checked_add(24)?;
        // The optional-header magic, and with it the width of one thunk in the import tables.
        let wide = half_at(raw, opt, true)? == 0x20b;
        let dirs = opt.checked_add(if wide { 112 } else { 96 })?;
        let image_base = if wide {
            addr_at(raw, opt + 24, true, true)?
        } else {
            word_at(raw, opt + 28, true)?
        };
        let table = opt.checked_add(optsz)?;
        let mut sections = Vec::new();
        for each in 0..nsec.min(192) {
            let step = usize::try_from(each.checked_mul(40).unwrap_or(u64::MAX)).ok()?;
            let at = table.checked_add(step)?;
            let name = raw.get(at..at + 8)?.split(|byte| *byte == 0).next()?;
            let (vsize, vaddr, rawsize, roff) = (
                word_at(raw, at + 8, true)?,
                word_at(raw, at + 12, true)?,
                word_at(raw, at + 16, true)?,
                word_at(raw, at + 20, true)?,
            );
            if rawsize == 0 {
                continue;
            }
            // The span an RVA can fall in: a section's virtual size is what it claims to hold, and its
            // raw size is what the file gives it. Either can be the larger one, so the map takes the
            // wider - which is what lets a byte past the declared end still resolve to a section.
            sections.push((vaddr, vsize.max(rawsize), roff, String::from_utf8_lossy(name).into_owned()));
        }
        Some(Pe { image_base, dirs, wide, sections })
    }

    /// Where an RVA lies: a file offset and the section that owns it. `None` is the honest answer for
    /// an address no section covers, and a caller must not turn that into an offset of its own.
    fn at(&self, rva: u64) -> Option<(usize, &str)> {
        for (base, span, offset, name) in self.sections.iter() {
            if *base <= rva && rva < base.checked_add(*span)? {
                let where_ = offset.checked_add(rva - base)?;
                return Some((usize::try_from(where_).ok()?, name.as_str()));
            }
        }
        None
    }
}

/// IDA's Exports window: what a PE hands out, by ordinal and by name.
///
/// Every address in the directory is an RVA, so each one is walked through the sections before it names
/// a byte. The three kinds of slot are told apart the way the format does it: a zero is an empty slot,
/// an RVA that falls inside the directory's own span is a forwarder whose payload is the text of another
/// module's name, and anything else is the address of a body. The row order is the table's own - by
/// ordinal - which is why a file with two names on one address shows it twice, and why `hint` is printed
/// where it comes from: the name table's index, not the ordinal.
/// The names that go with them: an exported body's address keeps the name the table gives
/// it, and an import slot is named `dll!name` (or `dll#ordinal`, where the file states no
/// name at all) because that is what a call through the slot reaches.
fn export_rows(raw: &[u8]) -> (Vec<String>, Vec<(u64, String)>) {
    let mut found_names: Vec<(u64, String)> = Vec::new();
    let pe = match Pe::parse(raw) {
        Some(found) => found,
        None => return (Vec::new(), Vec::new()),
    };
    let (dir_rva, dir_size) = match (word_at(raw, pe.dirs, true), word_at(raw, pe.dirs + 4, true)) {
        (Some(one), Some(two)) => (one, two),
        _ => return (Vec::new(), Vec::new()),
    };
    // No directory, or one too short to hold its own fixed header, is not a file with no exports - it
    // is a file that says nothing here, which an ELF also does. Both answer with no rows.
    if dir_rva == 0 || dir_size < 40 {
        return (Vec::new(), Vec::new());
    }
    let (at, section) = match pe.at(dir_rva) {
        Some(found) => found,
        None => return (Vec::new(), Vec::new()),
    };
    let at = match usize::try_from(at).ok().filter(|each| raw.get(*each..*each + 40).is_some()) {
        Some(where_) => where_,
        None => return (Vec::new(), Vec::new()),
    };
    let (name_rva, base, functions, names) = (
        match word_at(raw, at + 12, true) {
            Some(value) => value,
            None => return (Vec::new(), Vec::new()),
        },
        match word_at(raw, at + 16, true) {
            Some(value) => value,
            None => return (Vec::new(), Vec::new()),
        },
        match word_at(raw, at + 20, true) {
            Some(value) => value,
            None => return (Vec::new(), Vec::new()),
        },
        match word_at(raw, at + 24, true) {
            Some(value) => value,
            None => return (Vec::new(), Vec::new()),
        },
    );
    let (eat_at, names_at, ordinals_at): (usize, usize, usize) = match (
        word_at(raw, at + 28, true).and_then(|value| pe.at(value)),
        word_at(raw, at + 32, true).and_then(|value| pe.at(value)),
        word_at(raw, at + 36, true).and_then(|value| pe.at(value)),
    ) {
        (Some(one), Some(two), Some(three)) => (one.0, two.0, three.0),
        _ => return (Vec::new(), Vec::new()),
    };
    // The name table is read first, because a slot's name is only known through it: entry `i` of that
    // table holds the i-th hint, the index into the name list, which is why the rows print `hint` and
    // not something derived from the ordinal.
    let entries: Vec<(u32, u64)> = (0..names)
        .filter_map(|each| {
            let step = usize::try_from(each.checked_mul(4)?).ok()?;
            let rva = word_at(raw, names_at.checked_add(step)?, true)?;
            let step = usize::try_from(each.checked_mul(2)?).ok()?;
            Some((half_at(raw, ordinals_at.checked_add(step)?, true)? as u32, rva))
        })
        .collect();
    let dll = cstr_at(raw, pe.at(name_rva).map(|(where_, _)| where_).unwrap_or(0));
    let mut rows = vec![format!(
        "exports\trva\t{:#x}\tbytes\t{}\toff\t{}\tsection\t{}\tdll\t{}\tbase\t{}\tfunctions\t{}\tnames\t{}",
        dir_rva, dir_size, at, clean(section), clean(&dll), base, functions, names
    )];
    for index in 0..functions {
        let ordinal = match base.checked_add(index) {
            Some(value) => value,
            None => break,
        };
        let slot = u32::try_from(index).unwrap_or(u32::MAX);
        let hint = entries.iter().position(|(owner, _)| *owner == slot);
        let name = match hint {
            Some(where_) => match pe.at(entries[where_].1) {
                Some((where_, _)) => cstr_at(raw, where_),
                None => String::new(),
            },
            None => String::new(),
        };
        let name = clean(&name);
        let label = if name.is_empty() { "-" } else { &name };
        let rva = match usize::try_from(index.saturating_mul(4))
            .ok()
            .and_then(|step| eat_at.checked_add(step))
            .and_then(|where_| word_at(raw, where_, true))
        {
            Some(value) => value,
            None => {
                rows.push(format!("broken\texports\t{index}"));
                break;
            }
        };
        if rows.len() > MAX_LISTED {
            rows.push(format!("cut\texports\t{functions}"));
            break;
        }
        if rva == 0 {
            rows.push(format!("export\t{ordinal}\t-\thole"));
            continue;
        }
        // An RVA inside the directory's own span is a forwarder: the bytes there are the text of
        // another module's export name, and no body of this file's.
        if dir_rva <= rva && rva < dir_rva.checked_add(dir_size).unwrap_or(u64::MAX) {
            let target = match pe.at(rva) {
                Some((where_, _)) => clean(&cstr_at(raw, where_)),
                None => String::new(),
            };
            match hint {
                Some(where_) => rows.push(format!(
                    "export\t{ordinal}\t{label}\tforward\t{target}\thint\t{where_}")),
                None => rows.push(format!("export\t{ordinal}\t{label}\tforward\t{target}\tnoname")),
            }
            continue;
        }
        let (offset, section) = match pe.at(rva) {
            Some(found) => found,
            None => {
                rows.push(format!("export\t{ordinal}\t{label}\trva\t{:#x}\tunmapped", rva));
                continue;
            }
        };
        let tail = match hint {
            Some(where_) => format!("hint\t{where_}"),
            None => "noname".to_string(),
        };
        rows.push(format!(
            "export\t{ordinal}\t{label}\trva\t{:#x}\taddr\t{}\toff\t{}\tsection\t{}\t{tail}",
            rva,
            pe.image_base + rva,
            offset,
            clean(section)
        ));
        if !name.is_empty() {
            found_names.push((pe.image_base + rva, name.clone()));
        }
    }
    (rows, found_names)
}

/// IDA's Imports window: what a PE asks the loader to hand it, DLL by DLL.
///
/// The directory is a run of 20-byte descriptors that ends at an all-zero one, and each one names a DLL,
/// a table of thunks to look names up in (the ILT), and the table the loader overwrites with the real
/// addresses (the IAT). A thunk with the high bit set is an import by ordinal and the low sixteen bits
/// are the number; anything else is the RVA of a two-byte hint and a name. A descriptor with no ILT is
/// not broken - the names then have to be read out of the IAT, which is the same list before the loader
/// touched it. Both readers called that out, and the fixtures here hold both shapes.
fn import_rows(raw: &[u8]) -> (Vec<String>, Vec<(u64, String)>) {
    let mut found_names: Vec<(u64, String)> = Vec::new();
    let pe = match Pe::parse(raw) {
        Some(found) => found,
        None => return (Vec::new(), Vec::new()),
    };
    let (dir_rva, dir_size) = match (word_at(raw, pe.dirs + 8, true), word_at(raw, pe.dirs + 12, true)) {
        (Some(one), Some(two)) => (one, two),
        _ => return (Vec::new(), Vec::new()),
    };
    if dir_rva == 0 || dir_size < 20 {
        return (Vec::new(), Vec::new());
    }
    let (at, section) = match pe.at(dir_rva) {
        Some(found) => found,
        None => return (Vec::new(), Vec::new()),
    };
    let width = if pe.wide { 8 } else { 4 };
    let flag = 1u64 << if pe.wide { 63 } else { 31 };
    let mut detail: Vec<String> = Vec::new();
    let mut dlls = 0u64;
    let mut thunks = 0u64;
    // Two guards against a file whose tables never end, because a browser waits for this walk: a
    // descriptor array of 256 and a thunk array of 1 024 are both far past any real import table.
    let mut truncated = false;
    for step in 0..256u64 {
        truncated |= step == 255;
        let base = match at.checked_add(usize::try_from(step * 20).unwrap_or(usize::MAX)) {
            Some(where_) => where_,
            None => break,
        };
        let (ilt, stamp, chain, name_at, iat) = match (
            word_at(raw, base, true),
            word_at(raw, base + 4, true),
            word_at(raw, base + 8, true),
            word_at(raw, base + 12, true),
            word_at(raw, base + 16, true),
        ) {
            (Some(one), Some(two), Some(three), Some(four), Some(five)) => (one, two, three, four, five),
            _ => break,
        };
        if (ilt, stamp, chain, name_at, iat) == (0, 0, 0, 0, 0) {
            break;
        }
        let dll = cstr_at(raw, match pe.at(name_at) {
            Some((where_, _)) => where_,
            None => break,
        });
        dlls += 1;
        if detail.len() < MAX_LISTED {
            detail.push(format!(
                "import\t{}\tilt\t{:#x}\tiat\t{:#x}\tnames\t{}\tstamp\t{}\tforward\t{}",
                clean(&dll),
                ilt,
                iat,
                if ilt == 0 { "iat" } else { "ilt" },
                stamp,
                chain
            ));
        }
        // The loader overwrites the IAT in place, so the ILT is the list to read names from - and when
        // the file has no ILT, the IAT is the only copy left, which is what `names\tiat` says.
        let source = if ilt == 0 { iat } else { ilt };
        for slot in 0..1024u64 {
            truncated |= slot == 1023;
            let where_ = match pe.at(source + slot * width) {
                Some((where_, _)) => where_,
                None => break,
            };
            let value = if pe.wide {
                match addr_at(raw, where_, true, true) {
                    Some(found) => found,
                    None => break,
                }
            } else {
                match word_at(raw, where_, true) {
                    Some(found) => found,
                    None => break,
                }
            };
            if value == 0 {
                break;
            }
            thunks += 1;
            if detail.len() >= MAX_LISTED {
                continue;
            }
            if value & flag != 0 {
                let number = value & 0xffff;
                detail.push(format!(
                    "thunk\t{}\t-\tordinal\t{}\tslot\t{:#x}",
                    clean(&dll),
                    number,
                    iat + slot * width
                ));
                found_names.push((
                    pe.image_base + iat + slot * width,
                    format!("{}#{}", clean(&dll), number),
                ));
                continue;
            }
            let entry = match pe.at(value) {
                Some((where_, _)) => where_,
                None => {
                    detail.push(format!(
                        "thunk\t{}\t-\tunmapped\tslot\t{:#x}",
                        clean(&dll),
                        iat + slot * width
                    ));
                    continue;
                }
            };
            let hint = half_at(raw, entry, true).unwrap_or(0);
            let symbol = clean(&cstr_at(raw, entry + 2));
            detail.push(format!(
                "thunk\t{}\t{}\thint\t{}\tslot\t{:#x}\tname\t{:#x}",
                clean(&dll),
                symbol,
                hint,
                iat + slot * width,
                value
            ));
            if !symbol.is_empty() {
                found_names.push((
                    pe.image_base + iat + slot * width,
                    format!("{}!{}", clean(&dll), symbol),
                ));
            }
        }
    }
    let planned = dlls + thunks;
    let mut rows = vec![format!(
        "imports\trva\t{:#x}\tbytes\t{}\toff\t{}\tsection\t{}\tdlls\t{}\tthunks\t{}",
        dir_rva, dir_size, at, clean(section), dlls, thunks
    )];
    rows.append(&mut detail);
    if truncated || planned as usize > rows.len() - 1 {
        rows.push(format!("cut\timports\t{planned}"));
    }
    (rows, found_names)
}

/// The map: every range the file names, in order, with what falls between them called what it is -
/// padding inside a segment the loader maps, or bytes no table and no segment reaches at all.
/// The map and the string list, from the same walk of the same bytes.
fn map_rows(raw: &[u8]) -> (Vec<String>, Vec<String>) {
    let (mut spans, loaded) = match elf_spans(raw) {
        Some(found) => (found.0, found.1),
        None => match pe_spans(raw) {
            Some(found) => (found, Vec::new()),
            None => return (Vec::new(), Vec::new()),
        },
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
        if stop > total {
            // A table whose stated span does not fit the file is not clipped into a partial claim: what is
            // left of the file is the overlay row below, which says the same thing more honestly.
            break;
        }
        let note = if start != each.start {
            annotate(&each.note, "overlaps")
        } else {
            each.note
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
        // `stop` was computed and bounds-checked above, so this cannot overflow.
        cursor = cursor.max(stop);
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
    let (found, scanned, ranges) = string_runs(raw, &merged);
    let listed_strings = found.len().min(MAX_STRINGS);
    let mut strings = vec![format!(
        "strings\t{}\tmin\t{MIN_PRINTABLE}\tscanned\t{scanned}\tranges\t{ranges}",
        found.len()
    )];
    if found.len() > listed_strings {
        strings.push(format!("cut\tstrings\t{}", found.len()));
    }
    strings.extend(found.into_iter().take(listed_strings));
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
    (rows, strings)
}

/// Printable runs of at least this many bytes, which is binutils' `strings` default and IDA's.
const MIN_PRINTABLE: u64 = 4;
/// Strings listed before the report says it stopped.
const MAX_STRINGS: usize = 128;

/* ---------------------------------------------------------------------------------
 * CodeView type records: the leaves of `.debug$T`, which are also the records of a PDB's
 * TPI stream and the thing IDA calls its type list.
 * --------------------------------------------------------------------------------- */

/// Leaf numbers read out of LLVM's own `CodeViewTypes.def`, not recalled: an invented number decodes
/// someone else's record, and nothing in the file would complain.
const LF_MODIFIER: u16 = 0x1001;
const LF_POINTER: u16 = 0x1002;
const LF_PROCEDURE: u16 = 0x1008;
const LF_ARGLIST: u16 = 0x1201;
const LF_FIELDLIST: u16 = 0x1203;
const LF_ENUMERATE: u16 = 0x1502;
const LF_CLASS: u16 = 0x1504;
const LF_STRUCTURE: u16 = 0x1505;
const LF_UNION: u16 = 0x1506;
const LF_ENUM: u16 = 0x1507;
const LF_MEMBER: u16 = 0x150d;

/// Primitive type indices the fixture's witness names, and only those. Anything else prints as
/// `?(0x…)`: a guessed type name would be worse than a missing one, because a reader would repeat it.
const PRIMITIVES: &[(u32, &str)] = &[
    (0x03, "void"),
    (0x10, "signed char"),
    (0x11, "short"),
    (0x12, "long"),
    (0x13, "__int64"),
    (0x20, "unsigned char"),
    (0x21, "unsigned short"),
    (0x22, "unsigned long"),
    (0x40, "float"),
    (0x41, "double"),
    (0x70, "char"),
    (0x74, "int"),
    (0x75, "unsigned"),
    (0x622, "unsigned long*"),
];

/// Records listed before the report says it stopped.
const MAX_TYPES: usize = 256;

fn hex(value: u32) -> String {
    format!("0x{value:x}")
}

/// A type index spelled the way the rows spell it. At or above `0x1000` it names another record in the
/// same stream; below it, one of the primitives above.
fn type_label(index: u32) -> String {
    if index >= 0x1000 {
        return hex(index);
    }
    match PRIMITIVES.iter().find(|(value, _)| *value == index) {
        Some((_, name)) => format!("{name}({})", hex(index)),
        None => format!("?({})", hex(index)),
    }
}

fn cv_u16(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(raw.get(at..at + 2)?.try_into().ok()?))
}

fn cv_u32(raw: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?))
}

/// A NUL-terminated name and the offset just past its terminator.
fn cv_name(raw: &[u8], at: usize) -> Option<(String, usize)> {
    let tail = raw.get(at..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(&tail[..end]).unwrap_or("?");
    Some((clean(text), at + end + 1))
}

/// The rows of one type stream.
///
/// A record's length counts its kind and its data but not the length field itself, so a record is
/// `length + 2` bytes wide. The stream opens with a four-byte header that is reported rather than
/// interpreted - what it means has never been checked here, only that the records start after it. Every
/// field order below is the order the generator found in clang's bytes and then confirmed against
/// `llvm-pdbutil dump -types` on the PDB `lld-link` built from that same object, in both directions:
/// a record the walk names and the witness does not is as much a failure as the other way round.
fn type_rows(data: &[u8]) -> Vec<String> {
    // A COFF `.debug$T` section opens with a four-byte header and numbers its records from 0x1000.
    type_records(data, 4, 0x1000, 4)
}

/// The same walk from any start, base index and header size, because a PDB's TPI stream is the same
/// records behind a different header: its first index and header length are fields of that stream,
/// not constants - and the `header` column reports whichever one was skipped, so a reader can see
/// which of the two it is looking at.
fn type_records(data: &[u8], first: usize, base: u32, header: u32) -> Vec<String> {
    if data.len() < first {
        return Vec::new();
    }
    let header_value = header;
    let mut rows = Vec::new();
    let mut at = first;
    let mut index: u32 = base;
    let mut records = 0usize;
    let mut listed = 0usize;
    while at + 4 <= data.len() {
        let length = match cv_u16(data, at) {
            Some(value) => usize::from(value),
            None => break,
        };
        let leaf = match cv_u16(data, at + 2) {
            Some(value) => value,
            None => break,
        };
        // Counted before the two checks below, because a record that lies about its own size is still
        // one record read, and the totals row has to say how many were attempted.
        records += 1;
        if length < 4 {
            // A record shorter than its own kind field cannot hold anything: reading it as an empty
            // body would invent a row for bytes that are not a record.
            rows.push(format!(
                "type\t{}\tbroken\tlength {length} is shorter than a kind",
                hex(index)
            ));
            break;
        }
        let body = match data.get(at + 4..at + length + 2) {
            Some(window) => window,
            None => {
                rows.push(format!(
                    "type\t{}\tbroken\tlength {length} at {at} passes the end",
                    hex(index)
                ));
                break;
            }
        };
        if listed < MAX_TYPES {
            listed += 1;
            rows.extend(type_record(index, leaf, body));
        }
        // `length` was bounds-checked against the stream just above, so this cannot overflow.
        at += length + 2;
        index += 1;
    }
    if records > MAX_TYPES {
        // The cap is the only reason rows are missing, so a walk that stopped early because a record
        // lied says so in its own row rather than looking like a truncated list.
        rows.push(format!("cut\ttypes\t{records}"));
    }
    rows.insert(0, format!("types\t{records}\theader\t{header_value}"));
    rows
}

/// The TPI stream of an MSF 7.00 program database, as the rows of a type list plus one line naming
/// what was read.
///
/// The engine's container reader answers a `.pdb`'s table; this is the part of it that only the
/// analysis module can do, and it is the same record walk - a TPI stream is the header fields plus
/// the leaves an object's `.debug$T` holds, with the first index and the header length read from the
/// stream instead of assumed. A file that is not a PDB, or one whose directory cannot be reached,
/// answers `None` and the caller says so.
fn msf_types(bytes: &[u8]) -> Option<(String, Vec<String>)> {
    const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
    if !bytes.starts_with(MAGIC) {
        return None;
    }
    let page = usize::try_from(cv_u32(bytes, 32)?).ok()?;
    if page < 64 || page % 64 != 0 || page > bytes.len() {
        return None;
    }
    let dir_bytes = usize::try_from(cv_u32(bytes, 44)?).ok()?;
    let want = dir_bytes.checked_add(page - 1)? / page;
    if dir_bytes < 8 || want == 0 || want > 4096 {
        return None;
    }
    let held = |index: usize| -> bool {
        match index.checked_mul(page) {
            Some(at) => at.saturating_add(page) <= bytes.len(),
            None => false,
        }
    };
    let mut pages: Vec<usize> = Vec::new();
    for slot in [48usize, 56] {
        if let Some(value) = cv_u32(bytes, slot) {
            let index = usize::try_from(value).ok()?;
            if index > 0 {
                pages.push(index);
            }
        }
    }
    if pages.len() < want {
        let list = usize::try_from(cv_u32(bytes, 52)?).ok()?;
        if !held(list) {
            return None;
        }
        for n in pages.len()..want {
            let index = usize::try_from(cv_u32(bytes, list * page + 4 * n)?).ok()?;
            if index == 0 {
                return None;
            }
            pages.push(index);
        }
    }
    pages.truncate(want);
    if !pages.iter().all(|each| held(*each)) {
        return None;
    }
    let mut dir: Vec<u8> = Vec::with_capacity(dir_bytes);
    for each in &pages {
        dir.extend_from_slice(bytes.get(each * page..each * page + page)?);
    }
    dir.truncate(dir_bytes);
    let count = usize::try_from(cv_u32(&dir, 0)?).ok()?;
    if count < 3 || count > 4096 || 4 + 4 * count + 4 > dir_bytes {
        return None;
    }
    // Stream 2 is the type stream by position, which is what llvm-pdbutil's table calls `TPI Stream`.
    // The block list follows the size list, one entry per page each stream needs, so the offset of
    // stream 2's blocks is the size list plus every block counted before it.
    let mut blocks: Vec<Vec<usize>> = Vec::with_capacity(count);
    let mut seen = 0usize;
    for index in 0..count {
        let size = usize::try_from(cv_u32(&dir, 4 + 4 * index)?).ok()?;
        let used = size.checked_add(page - 1)? / page;
        let start = 4 + 4 * count + 4 * seen;
        if start + 4 * used > dir_bytes {
            return None;
        }
        let mut found: Vec<usize> = Vec::with_capacity(used);
        for n in 0..used {
            found.push(usize::try_from(cv_u32(&dir, start + 4 * n)?).ok()?);
        }
        seen += used;
        blocks.push(found);
    }
    let stream = match blocks.get(2) {
        Some(found) => {
            let mut out: Vec<u8> = Vec::new();
            for each in found {
                if !held(*each) {
                    return None;
                }
                out.extend_from_slice(bytes.get(each * page..each * page + page)?);
            }
            out
        }
        None => return None,
    };
    if stream.len() < 20 {
        return None;
    }
    let version = cv_u32(&stream, 0)?;
    let header = usize::try_from(cv_u32(&stream, 4)?).ok()?;
    let first = cv_u32(&stream, 8)?;
    let last = cv_u32(&stream, 12)?;
    let total = usize::try_from(cv_u32(&stream, 16)?).ok()?;
    if header.checked_add(total)? > stream.len() {
        return None;
    }
    // Walk the declared records and nothing past them: the stream is padded to a page boundary, and
    // reading those pad bytes as a record would invent a type with an index no one refers to.
    let rows = type_records(&stream[..header + total], header, first, cv_u32(&stream, 4)?);
    let summary = format!(
        "msf\tpdb\tstreams\t{count}\ttpi\tversion\t{version}\tindexes\t0x{first:x}..0x{last:x}\tbytes\t{total}"
    );
    Some((summary, rows))
}

/// One record's rows: usually a single row, and a field list one row per member it can read.
fn type_record(index: u32, leaf: u16, body: &[u8]) -> Vec<String> {
    let head = hex(index);
    let mut rows = Vec::new();
    match leaf {
        LF_ARGLIST => {
            let count = cv_u32(body, 0).unwrap_or(0);
            let mut args: Vec<String> = Vec::new();
            for each in 0..count.min(64) {
                let value = cv_u32(body, 4 + 4 * usize::try_from(each).unwrap_or(0));
                args.push(type_label(value.unwrap_or(0)));
            }
            // The joiner, not the list: an empty argument list still leaves the tab behind, which is
            // how `void f(void)`'s row reads against the witness.
            rows.push(format!("type\t{head}\targlist\t{count}\t{}", args.join("\t")));
        }
        LF_PROCEDURE => {
            let returns = type_label(cv_u32(body, 0).unwrap_or(0));
            let count = cv_u16(body, 6).unwrap_or(0);
            let args = hex(cv_u32(body, 8).unwrap_or(0));
            rows.push(format!(
                "type\t{head}\tprocedure\treturns\t{returns}\targs\t{count}\t{args}"
            ));
        }
        LF_POINTER => {
            let target = hex(cv_u32(body, 0).unwrap_or(0));
            match cv_u32(body, 4) {
                Some(attr) => rows.push(format!("type\t{head}\tpointer\tto\t{target}\tattr\t{}", hex(attr))),
                None => rows.push(format!("type\t{head}\tpointer\tto\t{target}\tattr\tno room")),
            }
        }
        LF_MODIFIER => {
            let target = hex(cv_u32(body, 0).unwrap_or(0));
            let constants = hex(u32::from(cv_u16(body, 4).unwrap_or(0)));
            rows.push(format!("type\t{head}\tmodifier\tof\t{target}\tconst\t{constants}"));
        }
        LF_STRUCTURE | LF_CLASS | LF_UNION | LF_ENUM => {
            let count = cv_u16(body, 0).unwrap_or(0);
            let options = hex(u32::from(cv_u16(body, 2).unwrap_or(0)));
            if leaf == LF_ENUM {
                let base = type_label(cv_u32(body, 4).unwrap_or(0));
                let name = cv_name(body, 12).map(|(text, _)| text).unwrap_or_default();
                rows.push(format!(
                    "type\t{head}\tenum\t{name}\tcount\t{count}\tbase\t{base}\topts\t{options}"
                ));
            } else {
                // A union names its field list where a struct names its derived class: reading the
                // struct's fields past the list is what made a union report a type index as its size.
                let (size_at, name_at, kind) = if leaf == LF_UNION {
                    (8, 10, "union")
                } else {
                    (16, 18, if leaf == LF_CLASS { "class" } else { "structure" })
                };
                let size = cv_u16(body, size_at).unwrap_or(0);
                let name = cv_name(body, name_at).map(|(text, _)| text).unwrap_or_default();
                rows.push(format!(
                    "type\t{head}\t{kind}\t{name}\tcount\t{count}\tsize\t{size}\topts\t{options}"
                ));
            }
        }
        LF_FIELDLIST => {
            let mut at = 0usize;
            while at + 2 <= body.len() {
                let marker = body[at];
                if (0xf0..=0xf7).contains(&marker) {
                    // A pad marker stands for `marker - 0xf0` bytes in all, itself included; clang
                    // writes a descending chain (0xf3, 0xf2, 0xf1) for a three-byte gap.
                    at += usize::from(marker - 0xf0).max(1);
                    continue;
                }
                let kind = match cv_u16(body, at) {
                    Some(value) => value,
                    None => break,
                };
                if kind == LF_MEMBER {
                    let ty = type_label(cv_u32(body, at + 4).unwrap_or(0));
                    let offset = cv_u16(body, at + 8).unwrap_or(0);
                    match cv_name(body, at + 10) {
                        Some((name, next)) => {
                            rows.push(format!("field\t{head}\t{name}\t{ty}\t{offset}"));
                            at = next;
                        }
                        None => break,
                    }
                    continue;
                }
                if kind == LF_ENUMERATE {
                    let value = cv_u16(body, at + 4).unwrap_or(0);
                    match cv_name(body, at + 6) {
                        Some((name, next)) => {
                            rows.push(format!("field\t{head}\t{name}\t{value}"));
                            at = next;
                        }
                        None => break,
                    }
                    continue;
                }
                // A member record carries no length of its own, so the walk cannot step over one it
                // does not know: the row says where it stopped instead of guessing at the next name.
                rows.push(format!("field\t{head}\tstopped\t{kind:#06x}"));
                break;
            }
        }
        _ => rows.push(format!("type\t{head}\taux\tleaf\t0x{leaf:04x}\tnot decoded")),
    }
    rows
}

/// The first `0x…` in a region's note, which is where the map keeps the section's own virtual base.
fn note_base(note: &str) -> u64 {
    let at = match note.find("0x") {
        Some(where_at) => where_at + 2,
        None => return 0,
    };
    let digits = note[at..]
        .chars()
        .take_while(|each| each.is_ascii_hexdigit())
        .collect::<String>();
    u64::from_str_radix(&digits, 16).unwrap_or(0)
}

/// The string list, over the ranges the map itself calls loaded data.
///
/// Scanning only those is what separates a string list from a dump of the file: the executable bytes, the
/// headers and the symbol tables are all full of printable accidents, and a Strings window is about data.
/// The address is the section's virtual base plus the offset into it - the same basis the section table
/// reports, an RVA for a PE - and every run is one `strings -t x -a` prints at the same file offset.
fn string_runs(raw: &[u8], merged: &[Span]) -> (Vec<String>, u64, usize) {
    let mut found = Vec::new();
    let mut scanned = 0u64;
    let mut ranges = 0usize;
    for each in merged {
        if each.kind != "data" && each.kind != "rodata" {
            continue;
        }
        ranges += 1;
        scanned += each.length;
        let stop = match each.start.checked_add(each.length) {
            Some(stop) => stop as usize,
            None => continue,
        };
        let bytes = match raw.get(each.start as usize..stop) {
            Some(window) => window,
            None => continue,
        };
        let base = note_base(&each.note);
        let mut at = 0usize;
        while at < bytes.len() {
            if !(0x20..=0x7E).contains(&bytes[at]) {
                at += 1;
                continue;
            }
            let mut end = at;
            while end < bytes.len() && (0x20..=0x7E).contains(&bytes[end]) {
                end += 1;
            }
            if (end - at) as u64 >= MIN_PRINTABLE {
                found.push(format!(
                    "string\t{:#x}\t{}\t{}\t{}\t{}",
                    // `at` is already relative to the region's start, and `base` is that region's own
                    // virtual address, so the sum is the address the loader will use.
                    base + at as u64,
                    each.start as usize + at,
                    end - at,
                    String::from_utf8_lossy(&bytes[at..end]),
                    each.name
                ));
            }
            at = end;
        }
    }
    (found, scanned, ranges)
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
            STRINGS.with(|stored| stored.borrow_mut().clear());
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

/// How many string rows the last file produced, including its totals row. Zero means the file had no
/// loaded data ranges to scan - a COFF object, or a file the map refused to draw.
#[no_mangle]
pub extern "C" fn string_count() -> i32 {
    STRINGS.with(|rows| rows.borrow().len() as i32)
}

/// One string: `string`, then its address in the section's own basis, its file offset, its length, the
/// text and the section it came out of. Row zero is the totals.
#[no_mangle]
pub extern "C" fn string_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    STRINGS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// How many type rows the last file produced, including its totals row. Zero means it carried no
/// CodeView type stream at all - a stripped binary, or one with DWARF instead.
#[no_mangle]
pub extern "C" fn type_count() -> i32 {
    TYPES.with(|rows| rows.borrow().len() as i32)
}

/// One row: `type` or `field`, then the index the other records refer to it by, and what the record
/// says about itself. Row zero is the totals. A `field` row belongs to the `type` row above it.
#[no_mangle]
pub extern "C" fn type_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    TYPES.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// How many export rows the last file produced, including its totals row. Zero means the file had
/// nothing to say here: an ELF, a Mach-O, or a PE with no export directory.
#[no_mangle]
pub extern "C" fn export_count() -> i32 {
    EXPORTS.with(|rows| rows.borrow().len() as i32)
}

/// One row: `export`, then the ordinal, then the name the file gives it - or `-` where it has none - and
/// what the slot holds: an address, a forwarded name, or nothing at all. Row zero is the totals.
#[no_mangle]
pub extern "C" fn export_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    EXPORTS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// How many import rows the last file produced, including its totals row.
#[no_mangle]
pub extern "C" fn import_count() -> i32 {
    IMPORTS.with(|rows| rows.borrow().len() as i32)
}

/// One row: `import` and then the DLL, or `thunk` with the DLL, the name (or `-` and an ordinal) and the
/// address-table slot the loader fills in. Row zero is the totals.
#[no_mangle]
pub extern "C" fn import_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    IMPORTS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// How many demangled-name rows the last file produced, including its totals row. Zero means its symbol
/// tables held no `_Z` name at all - which is what an object built from C, or a stripped one, gives.
#[no_mangle]
pub extern "C" fn demangle_count() -> i32 {
    DEMANGLED.with(|rows| rows.borrow().len() as i32)
}

/// One row: `sym`, the name's position in the symbol tables' own order, the name as the file spells it
/// and what this reader says it means - or `-` with the reason it stopped. Row zero is the totals.
#[no_mangle]
pub extern "C" fn demangle_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    DEMANGLED.with(|rows| match rows.borrow().get(index as usize) {
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
