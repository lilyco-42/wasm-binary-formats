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
    /// The base-relocation directory of the same file, block by block and fixup by fixup. A PE's only
    /// answer to "which addresses does the loader intend to rewrite", and empty for an ELF or a
    /// Mach-O, which carry their fixups as relocation records instead.
    static RELOCS: RefCell<Vec<String>> = RefCell::new(Vec::new());
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
    RELOCS.with(|slot| slot.borrow_mut().clear());
    FUNCTIONS.with(|slot| slot.borrow_mut().clear());
    NAMED.with(|slot| slot.borrow_mut().clear());
    SEGMENTS.with(|slot| slot.borrow_mut().clear());
    RESOURCES.with(|slot| slot.borrow_mut().clear());
    VERSION.with(|slot| slot.borrow_mut().clear());
    DYNAMIC.with(|slot| slot.borrow_mut().clear());
    SYMVER.with(|slot| slot.borrow_mut().clear());
    DEBUG.with(|slot| slot.borrow_mut().clear());
    TLS.with(|slot| slot.borrow_mut().clear());
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
    let mut funcs: Vec<(u64, u64, String, String)> = Vec::new();
    let mut window: Vec<(u64, String, String, String)> = Vec::new();
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
    // A function the file names for itself, and where. A symbol has to say `function`, be defined, and
    // own a section: an import's address is a slot the loader fills rather than a body, and a section
    // symbol names a range rather than a point.
    fn function_pair<'data, T: ObjectSymbol<'data>>(
        file: &object::File<'_>,
        symbol: &T,
    ) -> Option<(u64, u64, String, String)> {
        if !matches!(symbol.kind(), SymbolKind::Text) || symbol.is_undefined() {
            return None;
        }
        let id = symbol.section_index()?;
        let raw = clean(symbol.name().unwrap_or(""));
        if raw.trim().is_empty() {
            return None;
        }
        let where_ = file
            .section_by_index(id)
            .ok()
            .map_or_else(|| id.0.to_string(), |one| clean(one.name().unwrap_or("?")));
        Some((symbol.address(), symbol.size(), where_, raw))
    }

    // A name the file attaches to an address. Undefined symbols are left out - an import's value is a
    // slot in someone else's image, not a place this file names - and a section or file symbol stays in,
    // because it does carry an address and a reader asking "what is called at 0x1000" wants the whole
    // list, kinds and all.
    fn name_entry<'data, T: ObjectSymbol<'data>>(symbol: &T, from: &'static str) -> Option<(u64, String, String, String)> {
        if symbol.is_undefined() || symbol.section_index().is_none() {
            return None;
        }
        let raw = clean(symbol.name().unwrap_or(""));
        if raw.trim().is_empty() {
            return None;
        }
        Some((symbol.address(), raw, label(&symbol.kind()), from.to_owned()))
    }

    for (index, symbol) in file.symbols().enumerate() {
        symbols += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("symbol", index, &symbol));
        }
        // The index is not capped by MAX_LISTED: a name is worth finding precisely when the table is
        // too long to read as a list.
        named.extend(name_pair(&symbol));
        mangled.extend(mangled_name(&symbol));
        funcs.extend(function_pair(&file, &symbol));
        window.extend(name_entry(&symbol, "symtab"));
    }
    for (index, symbol) in file.dynamic_symbols().enumerate() {
        imported += 1;
        if index < MAX_LISTED {
            rows.push(symbol_row("dynsym", index, &symbol));
        }
        named.extend(name_pair(&symbol));
        mangled.extend(mangled_name(&symbol));
        funcs.extend(function_pair(&file, &symbol));
        window.extend(name_entry(&symbol, "dynsym"));
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
    let fixups = reloc_rows(bytes);
    RELOCS.with(|slot| *slot.borrow_mut() = fixups);
    let functions = function_rows(&funcs);
    FUNCTIONS.with(|slot| *slot.borrow_mut() = functions);
    for (address, name) in export_names.clone() {
        window.push((address, name, "-".to_owned(), "export".to_owned()));
    }
    window.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    window.dedup_by(|later, earlier| later.0 == earlier.0 && later.1 == earlier.1);
    let listed = named_rows(&window);
    NAMED.with(|slot| *slot.borrow_mut() = listed);
    let segments = segment_rows(bytes);
    SEGMENTS.with(|slot| *slot.borrow_mut() = segments);
    let resources = resource_rows(bytes);
    RESOURCES.with(|slot| *slot.borrow_mut() = resources);
    let version = version_rows(bytes);
    VERSION.with(|slot| *slot.borrow_mut() = version);
    let dynamic = dynamic_rows(bytes);
    DYNAMIC.with(|slot| *slot.borrow_mut() = dynamic);
    let debug = debug_rows(bytes);
    DEBUG.with(|slot| *slot.borrow_mut() = debug);
    let versions = symver_rows(bytes, &file);
    SYMVER.with(|slot| *slot.borrow_mut() = versions);
    let storage = tls_rows(bytes, &export_names);
    TLS.with(|slot| *slot.borrow_mut() = storage);
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
    /// The sections that hold memory and no file bytes at all - `.bss` is the standing case, and a PE's
    /// TLS index lives in one. `at` cannot name a position in them, which is a fact a row has to carry
    /// rather than round off to an offset of zero.
    empty: Vec<(u64, u64, String)>,
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
        let mut empty = Vec::new();
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
            let label = String::from_utf8_lossy(name).into_owned();
            if rawsize == 0 {
                empty.push((vaddr, vsize, label));
                continue;
            }
            // The span an RVA can fall in: a section's virtual size is what it claims to hold, and its
            // raw size is what the file gives it. Either can be the larger one, so the map takes the
            // wider - which is what lets a byte past the declared end still resolve to a section.
            sections.push((vaddr, vsize.max(rawsize), roff, label));
        }
        Some(Pe { image_base, dirs, wide, sections, empty })
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

    /// The section that owns an address the file keeps no bytes for - the other half of `at`, and the
    /// only answer for an address in a section the loader fills in rather than reads.
    fn in_empty(&self, rva: u64) -> Option<&str> {
        self.empty
            .iter()
            .find(|(base, span, _)| rva >= *base && rva < base.saturating_add(*span))
            .map(|(_, _, name)| name.as_str())
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
    // Every name the table carries, not just the ones the rows below are allowed to show: this list is a
    // lookup, and a file with more exports than a panel lists still has to answer for the address. The
    // linker's own order is what pairs a name with a body - `tls.dll`'s seventieth name is its eighth
    // callback, because the name table is sorted by the spelling and not by the address - so the pairs
    // are put back in ordinal order here, which is the order the rows are in and the one that decides
    // between two names on one address.
    let mut listed: Vec<(u32, u64, String)> = Vec::new();
    for (owner, name_at) in &entries {
        let step = match usize::try_from(u64::from(*owner).checked_mul(4).unwrap_or(u64::MAX)).ok() {
            Some(one) => one,
            None => continue,
        };
        let rva = match eat_at.checked_add(step).and_then(|where_| word_at(raw, where_, true)) {
            Some(value) => value,
            None => continue,
        };
        // A hole, a forwarder and an address in no section are the three kinds of slot that name no body
        // of this file's, so none of them contributes a name.
        if rva == 0
            || (dir_rva <= rva && rva < dir_rva.checked_add(dir_size).unwrap_or(u64::MAX))
            || pe.at(rva).is_none()
        {
            continue;
        }
        let text = match pe.at(*name_at) {
            Some((where_, _)) => clean(&cstr_at(raw, where_)),
            None => String::new(),
        };
        if !text.is_empty() {
            listed.push((*owner, pe.image_base + rva, text));
        }
    }
    listed.sort_by(|left, right| (left.0, &left.2).cmp(&(right.0, &right.2)));
    let found_names: Vec<(u64, String)> =
        listed.into_iter().map(|(_, where_, text)| (where_, text)).collect();
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

/// The type numbers a fixture put beside a name, and so the only ones this reader writes as names.
/// `llvm-readobj --coff-basereloc` prints `DIR64` where `pefile` prints `10`, and the pairing came out
/// of reading the same entries in the same order in three images: `ABSOLUTE` and `HIGHLOW` from the
/// PE32, `DIR64` from the PE32+. Anything else stays a number, because the loader knows what it means
/// and this reader was not shown.
fn reloc_type(kind: u16) -> Option<&'static str> {
    Some(match kind {
        0 => "ABSOLUTE",
        3 => "HIGHLOW",
        10 => "DIR64",
        _ => return None,
    })
}

/// Where an address of the file's own lies: the position and the section, or `-1` with the reason the
/// walk gives when no section covers it. Zero is the absent value the directory uses, so it is named
/// rather than looked for.
fn where_lies(pe: &Pe, rva: u64) -> (i64, String) {
    if rva == 0 {
        return (-1, "none".to_owned());
    }
    match pe.at(rva) {
        Some((where_, name)) => (i64::try_from(where_).unwrap_or(-1), clean(name)),
        None => (-1, "unmapped".to_owned()),
    }
}

thread_local! {
    /// The Segments window: the program headers an ELF hands its loader.
    static SEGMENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static RESOURCES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The version block a PE states about itself, from inside the resource tree.
    static VERSION: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The Dynamic window: the list an ELF hands its loader, entries and the names between them.
    static DYNAMIC: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Which version index each dynamic symbol carries, and what the tables around it name.
    static SYMVER: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The Information window: a PE's debug directory, and the CodeView block inside it that names a
    /// program database.
    static DEBUG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The thread-local storage window: a PE's directory 9, and the callbacks the loader runs from it.
    static TLS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The segment types two readers named in the files here, by number. Nine words, because nine appear
/// across `lab.elf`, `lab.so`, `lab32.so`, `labarm.so` and `interp.elf` - `readelf` and
/// `llvm-readobj --segments` agree on each one, LLVM's being readelf's with `PT_` in front, and a
/// disagreement about a word would stop the probe being written at all. Any other number prints as a
/// number: the OS-specific ranges and the unwinding kinds of other machines are in no file this lab can
/// build, so a name copied out of documentation would be a claim nothing here has checked.
fn segment_word(kind: u32) -> Option<&'static str> {
    Some(match kind {
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        6 => "PHDR",
        7 => "TLS",
        0x6474_E550 => "GNU_EH_FRAME",
        0x6474_E551 => "GNU_STACK",
        0x6474_E552 => "GNU_RELRO",
        _ => return None,
    })
}

/// The program headers, read out of the file.
///
/// `e_phentsize` is what the header says it is, not a constant, so a file with roomy records is walked at
/// its own stride. The fields are not consecutive words: in a 32-bit record `p_flags` sits between
/// `p_memsz` and `p_align`, where a 64-bit record puts it second, and reading the two the same way reports
/// a permission word as an alignment. The encoding comes from `e_ident`'s own byte, which has nothing to
/// do with the class - a 32-bit little-endian file is the ordinary case.
fn segment_rows(raw: &[u8]) -> Vec<String> {
    if raw.len() < 64 || raw.get(..4) != Some(b"\x7fELF") {
        return Vec::new();
    }
    let is64 = raw.get(4) == Some(&2);
    let little = raw.get(5) == Some(&1);
    let word = |at: usize, wide: bool| -> Option<u64> {
        if wide {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(raw.get(at..at.checked_add(8)?)?);
            Some(if little { u64::from_le_bytes(buf) } else { u64::from_be_bytes(buf) })
        } else {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(raw.get(at..at.checked_add(4)?)?);
            Some(u64::from(if little { u32::from_le_bytes(buf) } else { u32::from_be_bytes(buf) }))
        }
    };
    let half = |at: usize| -> Option<u64> {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(raw.get(at..at.checked_add(2)?)?);
        Some(u64::from(if little { u16::from_le_bytes(buf) } else { u16::from_be_bytes(buf) }))
    };
    let (Some(at_ph), Some(entry), Some(count)) = (
        word(if is64 { 0x20 } else { 0x1c }, is64),
        half(if is64 { 0x36 } else { 0x2a }),
        half(if is64 { 0x38 } else { 0x2c }),
    ) else {
        return Vec::new();
    };
    let smallest = if is64 { 56 } else { 32 };
    let Some(stride) = usize::try_from(entry).ok() else {
        return Vec::new();
    };
    if stride < smallest {
        return vec!["segments\ttotal\t0\tstopped\tentry size".to_owned()];
    }
    let places: [usize; 6] = if is64 {
        [8, 16, 24, 32, 40, 48]
    } else {
        [4, 8, 12, 16, 20, 28]
    };
    let flag_place = if is64 { 4 } else { 24 };
    let mut out: Vec<String> = Vec::new();
    let mut loads = 0usize;
    let mut writable = 0usize;
    let mut execed = 0usize;
    let mut mapped = 0u64;
    let mut listed = 0usize;
    let total = usize::try_from(count).unwrap_or(0);
    for index in 0..total {
        let Some(start) = at_ph.checked_add(u64::try_from(index).unwrap_or(0)
                                            * u64::try_from(stride).unwrap_or(0)) else {
            break;
        };
        let Some(at) = usize::try_from(start).ok() else { break };
        let Some(kind) = word(at, false) else { break };
        let Some(bits) = word(at + flag_place, false) else { break };
        let mut fields = Vec::with_capacity(6);
        let mut broke = false;
        for place in places {
            match word(at + place, is64) {
                Some(one) => fields.push(one),
                None => {
                    broke = true;
                    break;
                }
            }
        }
        if broke {
            break;
        }
        if kind == 1 {
            loads += 1;
        }
        if bits & 2 != 0 {
            writable += 1;
        }
        if bits & 1 != 0 {
            execed += 1;
        }
        mapped = mapped.saturating_add(fields[4]);
        if listed >= MAX_LISTED {
            continue;
        }
        listed += 1;
        let flags = format!("{}{}{}",
                            if bits & 4 != 0 { "r" } else { "-" },
                            if bits & 2 != 0 { "w" } else { "-" },
                            if bits & 1 != 0 { "x" } else { "-" });
        out.push(format!(
            "segment\t{index}\ttype\t{kind}\tname\t{}\toff\t{}\tvaddr\t0x{:x}\tpaddr\t0x{:x}\tfilesz\t{}\tmemsz\t{}\tflags\t{}\talign\t{}",
            segment_word(kind as u32).unwrap_or("-"),
            fields[0], fields[1], fields[2], fields[3], fields[4], flags, fields[5],
        ));
    }
    let mut head = format!(
        "segments\ttotal\t{total}\tload\t{loads}\twritable\t{writable}\texec\t{execed}\tmapped\t{mapped}\tbits\t{}",
        if is64 { 64 } else { 32 }
    );
    if total > listed {
        head.push_str("\tstopped\tshort");
    }
    let mut rows = vec![head];
    rows.append(&mut out);
    if total > MAX_LISTED {
        rows.push(format!("cut\tsegments\t{total}"));
    }
    rows
}

/// How many rows the Segments window has. A PE and a COFF object answer with no rows at all: the program
/// header table is an ELF's, and those formats say what to map in their own way - sections and a directory.
#[no_mangle]
pub extern "C" fn segment_count() -> i32 {
    SEGMENTS.with(|rows| rows.borrow().len() as i32)
}

/// One row: the record's index, its type number and - where two readers named that number in a file here
/// - the word, then the offsets, both addresses, both sizes, the permission letters and the alignment,
/// all as the header states them. Row zero is the totals.
#[no_mangle]
pub extern "C" fn segment_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    SEGMENTS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// Which data directory carries the resource tree (`2`, the one the optional header reserves for it),
/// and how many bodies one report will reach before it stops and says so.
const RESOURCE_DIRECTORY: usize = 2;
const RESOURCE_MAX_BODIES: usize = 512;
/// The resource type that carries a version block, and the word the fixed block opens with.
const VERSIONINFO_TYPE: u64 = 16;
const VERSIONINFO_SIGNATURE: u64 = 0xFEEF_04BD;

/// One type of the level-one directory, with the bodies counted under it.
struct TypeSlot {
    text: bool,
    id: u64,
    label: String,
    bodies: usize,
}

/// The identifiers two readers named in the files here. `llvm-readobj` prints the word beside the
/// number; Microsoft's own header spells the same number `RT_ICON`, so the *pair* is witnessed twice
/// while the *spelling* is witnessed once - which is why the row keeps the number and carries the word
/// beside it rather than replacing it. Anything not on this list prints with `word\t-`.
fn resource_word(id: u64) -> &'static str {
    match id {
        3 => "ICON",
        10 => "RCDATA",
        14 => "GROUP_ICON",
        16 => "VERSIONINFO",
        24 => "MANIFEST",
        _ => "-",
    }
}

/// One directory's entries: whether the child is another directory, the identifier's number, its text
/// when the identifier is a string, and where the child sits. An identifier with its high bit set is an
/// offset into the section's own string table, where a UTF-16 count is followed by that many characters
/// - and the text is kept exactly as the file spells it, quotes included, because rc puts the quote
/// characters *inside* a string type name and the loader hands them back.
fn resource_level(raw: &[u8], base: usize, node: usize) -> Vec<(bool, u64, String, usize)> {
    let header = |offset: usize| node.checked_add(offset).and_then(|at| half_at(raw, at, true));
    let Some(named) = header(12) else { return Vec::new() };
    let Some(ids) = header(14) else { return Vec::new() };
    let mut out = Vec::new();
    for slot in 0..named.checked_add(ids).unwrap_or(0).min(1024) {
        let step = match usize::try_from(slot.checked_mul(8).unwrap_or(u64::MAX)) {
            Ok(one) => one,
            Err(_) => break,
        };
        let Some(at) = node.checked_add(16).and_then(|start| start.checked_add(step)) else {
            break;
        };
        let key = match word_at(raw, at, true) {
            Some(one) => one,
            None => break,
        };
        let child = match at.checked_add(4).and_then(|place| word_at(raw, place, true)) {
            Some(one) => one,
            None => break,
        };
        let number = key & 0x7FFF_FFFF;
        let label = if key & 0x8000_0000 == 0 {
            String::new()
        } else {
            let place = match base.checked_add(usize::try_from(number).unwrap_or(usize::MAX)) {
                Some(one) => one,
                None => break,
            };
            let units = match half_at(raw, place, true) {
                Some(one) => one,
                None => break,
            };
            let count = match usize::try_from(units.checked_mul(2).unwrap_or(u64::MAX)) {
                Ok(one) => one,
                Err(_) => break,
            };
            let span = match place.checked_add(2).and_then(|start| start.checked_add(count).map(|stop| (start, stop))) {
                Some(one) => one,
                None => break,
            };
            let body = match raw.get(span.0..span.1) {
                Some(one) => one,
                None => break,
            };
            let wide: Vec<u16> = body.chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            String::from_utf16_lossy(&wide)
        };
        let where_ = match usize::try_from(child & 0x7FFF_FFFF)
            .ok()
            .and_then(|offset| base.checked_add(offset))
        {
            Some(one) => one,
            None => break,
        };
        out.push((child & 0x8000_0000 != 0, number, label, where_));
    }
    out
}

/// IDA's Resources window: every body a PE carries, with where the file says it is.
///
/// Three levels - type, name, language - each a directory of entries whose high bit says whether the
/// child is another directory or the data entry itself. The only interesting arithmetic left is the one
/// every PE reader has to do: an entry names an RVA, and the RVA has to be walked through the section
/// table before it names a byte, so `off` is `-1` when the file points somewhere no section covers
/// rather than being quietly turned into the RVA.
fn resource_rows(raw: &[u8]) -> Vec<String> {
    let Some(pe) = Pe::parse(raw) else { return Vec::new() };
    let Some(lfanew) = word_at(raw, 0x3c, true) else { return Vec::new() };
    let Some(lfanew) = usize::try_from(lfanew).ok() else { return Vec::new() };
    let Some(machine) = lfanew.checked_add(4).and_then(|at| half_at(raw, at, true)) else {
        return Vec::new();
    };
    let Some(at) = pe.dirs.checked_add(RESOURCE_DIRECTORY * 8) else { return Vec::new() };
    let Some(rva) = word_at(raw, at, true) else { return Vec::new() };
    let Some(size) = at.checked_add(4).and_then(|place| word_at(raw, place, true)) else {
        return Vec::new();
    };
    if size == 0 {
        return Vec::new();
    }
    let Some((base, _)) = pe.at(rva) else { return Vec::new() };
    // The type list is built in the order the file first names each type, and `bodies` on a type row is
    // counted from the bodies actually reached, so a directory that lists a type twice cannot make the
    // report list it twice.
    let mut order: Vec<TypeSlot> = Vec::new();
    let mut bodies = 0usize;
    let mut strings = 0usize;
    let mut rows: Vec<String> = Vec::new();
    for (type_dir, type_id, type_label, type_where) in resource_level(raw, base, base) {
        if !type_dir {
            continue;
        }
        let type_text = !type_label.is_empty();
        for (name_dir, name_id, name_label, name_where) in resource_level(raw, base, type_where) {
            if !name_dir {
                continue;
            }
            let name_text = !name_label.is_empty();
            let index = match order
                .iter()
                .position(|one| one.text == type_text && one.id == type_id)
            {
                Some(found) => found,
                None => {
                    order.push(TypeSlot { text: type_text, id: type_id, label: type_label.clone(), bodies: 0 });
                    order.len() - 1
                }
            };
            for (lang_dir, language, _lang_label, data_where) in resource_level(raw, base, name_where) {
                if lang_dir || bodies >= RESOURCE_MAX_BODIES {
                    continue;
                }
                let Some(data_rva) = word_at(raw, data_where, true) else { continue };
                let Some(at) = data_where.checked_add(4) else { continue };
                let Some(data_size) = word_at(raw, at, true) else { continue };
                let codepage = at.checked_add(4).and_then(|place| word_at(raw, place, true)).unwrap_or(0);
                let where_ = pe.at(data_rva).map(|(found, _name)| found);
                let number = order[index].bodies;
                rows.push(format!(
                    "entry\t{index}\t{number}\t{}\t{}\tlang\t{language}\tbytes\t{data_size}\trva\t0x{data_rva:x}\toff\t{}\tcodepage\t{codepage}",
                    if name_text { "text" } else { "id" },
                    if name_text { clean(&name_label) } else { name_id.to_string() },
                    where_.map_or(-1i64, |found| i64::try_from(found).unwrap_or(i64::MAX)),
                ));
                order[index].bodies += 1;
                strings += usize::from(type_text) + usize::from(name_text);
                bodies += 1;
            }
        }
    }
    // Two lists, two caps of their own: running out of type rows says nothing about the bodies, and a
    // report that stopped listing one must not claim it stopped listing the other.
    let listed = MAX_LISTED;
    let head = format!(
        "resources\ttypes\t{}\tentries\t{bodies}\tstrings\t{strings}\tdir\t{RESOURCE_DIRECTORY}\trva\t0x{rva:x}\tmachine\t{}\twide\t{}",
        order.len(),
        if machine == 0x14c { "x86".to_string() } else { format!("0x{machine:x}") },
        if pe.wide { "yes" } else { "no" },
    );
    let mut found = vec![head];
    for (index, slot) in order.iter().enumerate() {
        if index >= listed {
            break;
        }
        found.push(format!(
            "type\t{index}\t{}\t{}\tword\t{}\tbodies\t{}",
            if slot.text { "text" } else { "id" },
            if slot.text { clean(&slot.label) } else { slot.id.to_string() },
            // A string identifier's low bits are an offset into the string table, not a type number,
            // so there is nothing to name here - and matching the offset against the table of types
            // would print a word the file never used.
            if slot.text { "-" } else { resource_word(slot.id) },
            slot.bodies
        ));
    }
    for row in rows.into_iter().take(listed) {
        found.push(row);
    }
    if order.len() > listed {
        found.push(format!("cut\ttypes\t{}\tlisted\t{listed}", order.len()));
    }
    if bodies > listed {
        found.push(format!("cut\tentries\t{bodies}\tlisted\t{listed}"));
    }
    found
}

/// The Resources window's two calls, over the rows `resource_rows` built for the last file analysed.
#[no_mangle]
pub extern "C" fn resource_count() -> i32 {
    RESOURCES.with(|rows| rows.borrow().len() as i32)
}

/// One row: the totals, then one line per type and one per body, each with the address the entry names
/// and the file offset that address resolves to. Row zero is the totals.
#[no_mangle]
pub extern "C" fn resource_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    RESOURCES.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// The body of the version block, if the file has one: the bytes of the resource directory's type 16,
/// which is where a PE states what it says about itself. The tree walk is `resource_level`'s, shared
/// with the Resources window above, so the two panels cannot disagree about where the body is.
fn version_body(raw: &[u8], base: usize) -> Option<(usize, usize)> {
    for (type_dir, type_id, type_label, type_where) in resource_level(raw, base, base) {
        if !type_dir || !type_label.is_empty() || type_id != VERSIONINFO_TYPE {
            continue;
        }
        for (name_dir, _name_id, _name_label, name_where) in resource_level(raw, base, type_where) {
            if !name_dir {
                continue;
            }
            for (lang_dir, _language, _lang_label, data_where) in resource_level(raw, base, name_where) {
                if lang_dir {
                    continue;
                }
                let rva = word_at(raw, data_where, true)?;
                let size = word_at(raw, data_where.checked_add(4)?, true)?;
                let (place, _name) = Pe::parse(raw)?.at(rva)?;
                let stop = place.checked_add(usize::try_from(size).ok()?)?;
                if raw.get(place..stop).is_none() {
                    return None;
                }
                return Some((place, stop));
            }
        }
    }
    None
}

/// One node of a `VS_VERSIONINFO` tree: its key, where the value starts, how many bytes of value it
/// claims, where the children start, and where this node ends.
///
/// `wValueLength` is counted in characters when `wType` says text and in bytes otherwise, and every
/// node starts on a 4-byte boundary - apply either rule to the wrong node and the child lands in the
/// middle of the parent's text, which is how a four-byte blob (`Translation`) can otherwise appear to
/// hold two language pairs when the second one is really the next node's length.
fn version_node(body: &[u8], at: usize) -> Option<(String, usize, usize, usize, usize)> {
    let header = struct_at(body, at, 6)?;
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let value_length = u16::from_le_bytes([header[2], header[3]]) as usize;
    let kind = u16::from_le_bytes([header[4], header[5]]);
    if length == 0 {
        return None;
    }
    let stop = at.checked_add(length)?;
    if stop > body.len() {
        return None;
    }
    let mut end = at.checked_add(6)?;
    while end.checked_add(2)? <= stop {
        let pair = struct_at(body, end, 2)?;
        if pair == [0, 0] {
            break;
        }
        end = end.checked_add(2)?;
    }
    if end.checked_add(2)? > stop {
        return None;
    }
    let wide: Vec<u16> = body.get(at.checked_add(6)?..end)?
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let key = String::from_utf16_lossy(&wide);
    let value = align4(end.checked_add(2)?);
    let count = value_length.saturating_mul(if kind == 1 { 2 } else { 1 });
    Some((key, value, count, align4(value.checked_add(count)?), stop))
}

/// Read `count` bytes, or nothing at all when the range does not fit.
fn struct_at(body: &[u8], at: usize, count: usize) -> Option<&[u8]> {
    body.get(at..at.checked_add(count)?)
}

fn align4(at: usize) -> usize {
    at.saturating_add(3) & !3usize
}

/// IDA's version view: the fixed block's own words, the language and codepage pairs the file offers,
/// and every string key under them - including the keys no standard list carries, which is the point of
/// reading the file rather than asking an API for a fixed set of names.
///
/// The signature is the format's own constant (`0xFEEF04BD`); the numbers are the file's. No word is
/// printed for `os`, `type` or `subtype`, because the only spellings for them are a Microsoft header's
/// and no second reader in this lab names them for a file here.
fn version_rows(raw: &[u8]) -> Vec<String> {
    version_found(raw).unwrap_or_default()
}

fn version_found(raw: &[u8]) -> Option<Vec<String>> {
    let pe = Pe::parse(raw)?;
    let at = pe.dirs.checked_add(RESOURCE_DIRECTORY * 8)?;
    let rva = word_at(raw, at, true)?;
    if word_at(raw, at.checked_add(4)?, true)? == 0 {
        return None;
    }
    let (base, _name) = pe.at(rva)?;
    let (start, stop) = version_body(raw, base)?;
    let body = raw.get(start..stop)?;
    let (key, value_at, count, kids, end) = version_node(body, 0)?;
    if key != "VS_VERSION_INFO" || count < 52 {
        return None;
    }
    let fixed = struct_at(body, value_at, 52)?;
    let word = |slot: usize| -> u64 {
        u32::from_le_bytes([fixed[slot * 4], fixed[slot * 4 + 1], fixed[slot * 4 + 2], fixed[slot * 4 + 3]])
            as u64
    };
    if word(0) != VERSIONINFO_SIGNATURE {
        return None;
    }
    let mut tables: Vec<(u64, u64)> = Vec::new();
    let mut found: Vec<(String, String)> = Vec::new();
    let mut visit = Vec::new();
    visit.push((kids, end, String::new(), false));
    while let Some((at, stop, parent, strings)) = visit.pop() {
        let mut at = at;
        let mut steps = 0usize;
        while at < stop && steps < RESOURCE_MAX_BODIES {
            steps += 1;
            at = align4(at);
            let Some((key, value_at, count, kids, end)) = version_node(body, at) else {
                break;
            };
            let value = body.get(value_at..value_at.checked_add(count).unwrap_or(value_at)).unwrap_or(&[]);
            if key == "Translation" {
                for pair in value.chunks_exact(2).map(|one| one[0] as u64 | ((one[1] as u64) << 8))
                    .collect::<Vec<u64>>()
                    .chunks(2)
                {
                    tables.push((pair[0], *pair.get(1).unwrap_or(&0)));
                }
            } else if count > 0 && !value.is_empty() {
                let wide: Vec<u16> = value
                    .chunks(2)
                    .map(|pair| u16::from_le_bytes([*pair.first().unwrap_or(&0), *pair.get(1).unwrap_or(&0)]))
                    .collect();
                let text = String::from_utf16_lossy(&wide);
                let text = text.trim_end_matches('\0');
                if strings {
                    found.push((key.clone(), clean(text)));
                }
            }
            let next = format!("{}{}", if parent.is_empty() { String::new() } else { format!("{}\\", parent) }, key);
            visit.push((kids, end, next, key == "StringFileInfo" || strings));
            at = end;
        }
    }
    let mut rows = vec![format!(
        "version\tsignature\t0x{VERSIONINFO_SIGNATURE:08x}\tstruct\t{}\tfile\t{}\tproduct\t{}\tflags-mask\t0x{:x}\tflags\t0x{:x}\tos\t0x{:x}\ttype\t0x{:x}\tsubtype\t0x{:x}\tdate\t{}\ttables\t{}\tstrings\t{}",
        hi_lo(word(1)),
        hi_lo32(word(2), word(3)),
        hi_lo32(word(4), word(5)),
        word(6),
        word(7),
        word(8),
        word(9),
        word(10),
        (word(11) << 32) | word(12),
        tables.len(),
        found.len()
    )];
    for (index, (language, codepage)) in tables.iter().take(MAX_LISTED).enumerate() {
        rows.push(format!("translation\t{index}\tlang\t0x{language:04x}\tcodepage\t0x{codepage:04x}"));
    }
    for (key, value) in found.iter().take(MAX_LISTED) {
        rows.push(format!("string\t{key}\t{value}"));
    }
    if tables.len() > MAX_LISTED {
        rows.push(format!("cut\ttables\t{}\tlisted\t{MAX_LISTED}", tables.len()));
    }
    if found.len() > MAX_LISTED {
        rows.push(format!("cut\tstrings\t{}\tlisted\t{MAX_LISTED}", found.len()));
    }
    Some(rows)
}

/// `VS_FIXEDFILEINFO`'s two halves of one version: the high word then the low, which is how the block
/// stores a `1.2.3.4` - four numbers in two u32s, and a reader that prints one u32 prints `66051`.
fn hi_lo(value: u64) -> String {
    format!("{}.{}", value >> 16, value & 0xFFFF)
}

fn hi_lo32(high: u64, low: u64) -> String {
    format!("{}.{}.{}.{}", high >> 16, high & 0xFFFF, low >> 16, low & 0xFFFF)
}

#[no_mangle]
pub extern "C" fn version_count() -> i32 {
    VERSION.with(|rows| rows.borrow().len() as i32)
}

/// One row: the fixed block's words, then a line per language and codepage pair, then a line per
/// string. Row zero is the totals.
#[no_mangle]
pub extern "C" fn version_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    VERSION.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// The tag numbers two readers named in the files here. Twenty-seven, because those are the ones
/// `readelf -dW` and `llvm-readobj --dynamic-table` were both asked about, in ten files, and agreed on
/// word for word - and a `DT_*` table copied out of memory is the classic off-by-one (`0x1d` is
/// `RUNPATH`, `0xf` is `RPATH`, and `0x1c` is neither). A number outside this set prints as a number.
fn dynamic_name(tag: u64) -> Option<&'static str> {
    Some(match tag {
        0 => "NULL",
        1 => "NEEDED",
        2 => "PLTRELSZ",
        3 => "PLTGOT",
        4 => "HASH",
        5 => "STRTAB",
        6 => "SYMTAB",
        7 => "RELA",
        8 => "RELASZ",
        9 => "RELAENT",
        0xa => "STRSZ",
        0xb => "SYMENT",
        0xe => "SONAME",
        0x11 => "REL",
        0x12 => "RELSZ",
        0x13 => "RELENT",
        0x14 => "PLTREL",
        0x17 => "JMPREL",
        0x1d => "RUNPATH",
        0x6fff_fef5 => "GNU_HASH",
        0x6fff_fff0 => "VERSYM",
        0x6fff_fffc => "VERDEF",
        0x6fff_fffd => "VERDEFNUM",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERNEEDNUM",
        0x6fff_fff9 => "RELACOUNT",
        0x6fff_fffa => "RELCOUNT",
        _ => return None,
    })
}

/// What a value is, as both readers spell it: the size tags state their unit and `DT_PLTREL` holds a
/// relocation type rather than an address. Everything else in the section holds an address or a bare
/// count, and neither reader gives it a word, so neither does this one.
fn dynamic_word(tag: u64, value: u64) -> Option<&'static str> {
    Some(match tag {
        0x14 => match value {
            0x7 => "RELA",
            0x11 => "REL",
            _ => return None,
        },
        2 | 8 | 9 | 0xa | 0xb | 0x12 | 0x13 => "BYTES",
        _ => return None,
    })
}

/// The string an entry points at inside `DT_STRTAB`, bounded by that table's own length: an entry that
/// runs past the end of the table is left unresolved rather than answered with whatever bytes follow.
fn dynamic_text(raw: &[u8], home: Option<usize>, limit: usize, at: u64) -> Option<String> {
    let start = home?.checked_add(usize::try_from(at).ok()?)?;
    let window = raw.get(start..limit.min(raw.len()))?;
    let end = window.iter().position(|byte| *byte == 0)?;
    Some(clean(&String::from_utf8_lossy(&window[..end])))
}

/// The dynamic section - the list a loader reads to find out what to bring in before it runs anything.
///
/// Two things bound the walk: `PT_DYNAMIC`'s own `p_filesz`, and a `DT_NULL` entry, whichever comes
/// first. The records are as wide as the file's class (`Elf64_Dyn` is two 8-byte words, the 32-bit
/// shape two 4-byte ones) and read in the byte order `e_ident` states, so an 8-byte-record file and a
/// 64-bit one are not walked with the same stride.
///
/// Values are addresses in the file's own address space, so the three tags that hold an offset into the
/// string table are followed twice over: `DT_STRTAB`'s value is itself an address, and turning either
/// into a position in the file needs the `PT_LOAD` records. That is the same conversion the Resources
/// window does for an RVA, and a string whose address no segment covers comes back as no string.
fn dynamic_rows(raw: &[u8]) -> Vec<String> {
    if raw.len() < 64 || raw.get(..4) != Some(b"\x7fELF") {
        return Vec::new();
    }
    let wide = raw[4] == 2;
    let little = raw[5] == 1;
    let (Some(at_ph), Some(stride), Some(count)) = (
        addr_at(raw, if wide { 32 } else { 28 }, wide, little),
        usize::try_from(half_at(raw, if wide { 54 } else { 42 }, little).unwrap_or(0)).ok(),
        half_at(raw, if wide { 56 } else { 44 }, little),
    ) else {
        return Vec::new();
    };
    if stride < if wide { 56 } else { 32 } {
        return Vec::new();
    }
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut found: Option<(u64, u64, u64)> = None;
    for index in 0..count.min(64) {
        let Some(start) = at_ph.checked_add(index * u64::try_from(stride).unwrap_or(0)) else {
            break;
        };
        let Some(at) = usize::try_from(start).ok() else { break };
        // One record read or the walk stops, the same way the Segments window stops: a header table
        // that runs off the file's own end still leaves everything before it true.
        let (Some(kind), Some(offset), Some(vaddr), Some(filesz)) = (
            word_at(raw, at, little),
            addr_at(raw, at + if wide { 8 } else { 4 }, wide, little),
            addr_at(raw, at + if wide { 16 } else { 8 }, wide, little),
            addr_at(raw, at + if wide { 32 } else { 16 }, wide, little),
        ) else {
            break;
        };
        if kind == PT_LOAD {
            loads.push((offset, vaddr, filesz));
        }
        if kind == 2 && found.is_none() {
            found = Some((offset, vaddr, filesz));
        }
    }
    let Some((base, segment, span)) = found else {
        return Vec::new();
    };
    let width = if wide { 16u64 } else { 8 };
    let stop = base.saturating_add(span);
    let mut items: Vec<(u64, u64)> = Vec::new();
    let mut walk = base;
    while walk.saturating_add(width) <= stop {
        let Some(at) = usize::try_from(walk).ok() else { break };
        let (Some(tag), Some(value)) = (
            addr_at(raw, at, wide, little),
            addr_at(raw, at + width as usize / 2, wide, little),
        ) else {
            break;
        };
        items.push((tag, value));
        walk += width;
        if tag == 0 {
            break;
        }
    }
    let strtab = items.iter().find(|one| one.0 == 5).map(|one| one.1);
    let strsz = items.iter().find(|one| one.0 == 10).map_or(0, |one| one.1);
    let home = strtab
        .and_then(|address| {
            loads.iter().find_map(|&(offset, from, size)| {
                let over = from.checked_add(size)?;
                (from <= address && address < over).then_some(offset + (address - from))
            })
        })
        .and_then(|one| usize::try_from(one).ok());
    let limit = home.unwrap_or(0).saturating_add(usize::try_from(strsz).unwrap_or(0));
    let mut needed = 0usize;
    let mut with_text = 0usize;
    let mut body: Vec<String> = Vec::new();
    for (index, (tag, value)) in items.iter().enumerate() {
        if *tag == 1 {
            needed += 1;
        }
        let text = if matches!(*tag, 1 | 0xe | 0x1d) {
            dynamic_text(raw, home, limit, *value)
        } else {
            None
        };
        if text.is_some() {
            with_text += 1;
        }
        if index >= MAX_LISTED {
            continue;
        }
        let mut row = format!(
            "entry\t{index}\ttag\t0x{tag:x}\tname\t{}\tvalue\t0x{value:x}",
            dynamic_name(*tag).unwrap_or("-"),
        );
        if let Some(word) = dynamic_word(*tag, *value) {
            row.push_str(&format!("\tword\t{word}"));
        }
        if let Some(one) = text {
            row.push_str(&format!("\ttext\t{one}"));
        }
        body.push(row);
    }
    let total = items.len();
    let mut rows = vec![format!(
        "dynamic\tentries\t{total}\twidth\t{width}\tvaddr\t0x{segment:x}\toff\t{base}\tfilesz\t{span}\tstrtab\t0x{:x}\tstrlen\t{strsz}\tneeded\t{needed}\ttext\t{with_text}",
        strtab.unwrap_or(0),
    )];
    rows.append(&mut body);
    if total > MAX_LISTED {
        rows.push(format!("cut\tentries\t{total}\tlisted\t{MAX_LISTED}"));
    }
    rows
}

/// How many rows the dynamic section fills. A PE has no such list - it names its imports in a directory
/// of its own - and a static executable has no `PT_DYNAMIC` at all.
#[no_mangle]
pub extern "C" fn dynamic_count() -> i32 {
    DYNAMIC.with(|rows| rows.borrow().len() as i32)
}

/// One row: the totals, then a line per entry with the tag's number, the word two readers gave that
/// number in a file here, the value, and - where the value indexes the string table - the string. Row
/// zero is the totals.
#[no_mangle]
pub extern "C" fn dynamic_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    DYNAMIC.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// Which data directory holds the debug table, and how wide one of its records is.
const DEBUG_DIRECTORY: usize = 6;
const DEBUG_ENTRY_BYTES: usize = 28;
/// The body shape two readers parsed field for field in the files here.
const CODEVIEW_SIGNATURE: &[u8; 4] = b"RSDS";

/// The debug type numbers two readers named in the files here - one, because that is the only kind any
/// tool on this host writes. LLVM calls it `CodeView` and pefile `IMAGE_DEBUG_TYPE_CODEVIEW`, so the
/// kind is said twice and the spelling once, exactly as with the resource types: the number stays in the
/// row and the word only rides beside it.
fn debug_word(kind: u64) -> Option<&'static str> {
    Some(match kind {
        2 => "CodeView",
        _ => return None,
    })
}

/// The 16 GUID bytes as both readers spell them: three little-endian integers and then eight bytes, so
/// the digits are not the file's order. LLVM brackets them and pefile prints the same 32 digits plain,
/// and `make-debug-fixtures.py` refuses to write a probe unless both equal the bytes here.
fn debug_guid(body: &[u8]) -> String {
    let (one, two, three) = (
        u32::from_le_bytes(body[4..8].try_into().unwrap_or([0; 4])),
        u16::from_le_bytes(body[8..10].try_into().unwrap_or([0; 2])),
        u16::from_le_bytes(body[10..12].try_into().unwrap_or([0; 2])),
    );
    let tail: String = body[12..20].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{one:08x}{two:04x}{three:04x}{tail}")
}

/// The path a CodeView body ends with, bounded by the body's own length: a block whose name runs past
/// the bytes the entry claims is reported as none rather than read on into whatever follows.
fn debug_path(body: &[u8], from: usize) -> Option<String> {
    let window = body.get(from..)?;
    let end = window.iter().position(|byte| *byte == 0)?;
    Some(clean(&String::from_utf8_lossy(&window[..end])))
}

/// IDA's Information window: the debug directory, and the CodeView block that names the program
/// database an image was linked with.
///
/// Twenty-eight bytes per record, read in the order the format states them - the two version words sit
/// between the time stamp and the type, so a reader that takes four words and then two finds a type
/// where the age is. Each record points at a body by RVA, and as in the Resources window that address
/// is walked through the section table before it names a byte: `body` is `-1` where no section covers
/// it, and the entry's own `PointerToRawData` is printed beside it rather than trusted.
fn debug_rows(raw: &[u8]) -> Vec<String> {
    let Some(pe) = Pe::parse(raw) else { return Vec::new() };
    let Some(at) = pe.dirs.checked_add(DEBUG_DIRECTORY * 8) else { return Vec::new() };
    let (Some(rva), Some(size)) = (word_at(raw, at, true), word_at(raw, at + 4, true)) else {
        return Vec::new();
    };
    if size == 0 {
        return Vec::new();
    }
    let Some((base, _)) = pe.at(rva) else { return Vec::new() };
    // Bound the table by the file as well as by what the directory claims: a record that runs off the
    // end is not read, and the rows that came before it still stand.
    let whole = usize::try_from(size).unwrap_or(0) / DEBUG_ENTRY_BYTES;
    let room = (raw.len() - base.min(raw.len())) / DEBUG_ENTRY_BYTES;
    let items: Vec<[u64; 8]> = (0..whole.min(room))
        .filter_map(|each| {
            let at = base + each * DEBUG_ENTRY_BYTES;
            Some([
                word_at(raw, at, true)?,
                word_at(raw, at + 4, true)?,
                half_at(raw, at + 8, true)?,
                half_at(raw, at + 10, true)?,
                word_at(raw, at + 12, true)?,
                word_at(raw, at + 16, true)?,
                word_at(raw, at + 20, true)?,
                word_at(raw, at + 24, true)?,
            ])
        })
        .collect();
    if items.is_empty() {
        return Vec::new();
    }
    let mut rows: Vec<String> = Vec::new();
    let mut parsed = 0usize;
    for (index, one) in items.iter().enumerate() {
        let body = pe.at(one[6]).map(|(found, _name)| found);
        let block = match body {
            Some(at) => {
                let length = usize::try_from(one[5]).unwrap_or(0);
                raw.get(at..at.saturating_add(length)).filter(|_| length > 0)
            }
            None => None,
        };
        if block.is_some() {
            parsed += 1;
        }
        if index >= MAX_LISTED {
            continue;
        }
        rows.push(format!(
            "entry\t{index}\ttype\t{}\tname\t{}\ttime\t0x{:x}\tmajor\t{}\tminor\t{}\tbytes\t{}\trva\t0x{:x}\tbody\t{}\tptr\t{}",
            one[4],
            debug_word(one[4]).unwrap_or("-"),
            one[1],
            one[2],
            one[3],
            one[5],
            one[6],
            body.map_or_else(|| "-1".to_owned(), |found| found.to_string()),
            one[7],
        ));
        let Some(found) = block else { continue };
        let Some(head) = found.get(..4) else { continue };
        let spelled = if head.iter().all(|byte| (0x20..0x7f).contains(byte)) {
            String::from_utf8_lossy(head).into_owned()
        } else {
            format!("0x{}", u32::from_le_bytes(head.try_into().unwrap_or([0; 4])))
        };
        let mut one_row = format!("cv\t{index}\tsig\t{spelled}");
        if head == CODEVIEW_SIGNATURE && found.len() >= 24 {
            let age = u32::from_le_bytes(found[20..24].try_into().unwrap_or([0; 4]));
            one_row.push_str(&format!("\tguid\t{}", debug_guid(found)));
            one_row.push_str(&format!("\tage\t{age}"));
            one_row.push_str(&format!("\tpath\t{}", debug_path(found, 24).unwrap_or_else(|| "-".to_owned())));
        }
        rows.push(one_row);
    }
    let mut out = vec![format!(
        "debug\tentries\t{}\tsize\t{size}\tdir\t{DEBUG_DIRECTORY}\trva\t0x{rva:x}\toff\t{base}\tcv\t{parsed}",
        items.len(),
    )];
    out.append(&mut rows);
    if items.len() > MAX_LISTED {
        out.push(format!("cut\tentries\t{}\tlisted\t{MAX_LISTED}", items.len()));
    }
    out
}

/// How many rows the debug directory fills. A COFF object carries `.debug$S` *sections* and no
/// directory at all - only an image has data directories - and an image with an empty table answers
/// with nothing, the same as one with none.
#[no_mangle]
pub extern "C" fn debug_count() -> i32 {
    DEBUG.with(|rows| rows.borrow().len() as i32)
}

/// One row: the totals, then a line per entry with its type number and the word two readers gave it,
/// both locations and the size, and for a CodeView entry the signature, GUID, age and path. Row zero is
/// the totals.
#[no_mangle]
pub extern "C" fn debug_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    DEBUG.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// The three version tables' section names, and the string table they all index. `.gnu.version` is a
/// plain array of 16-bit indices, one per dynamic symbol; the other two are chains of records that end
/// where their own `v*_next` word says.
const VERSYM_SECTION: &str = ".gnu.version";
const VERDEF_SECTION: &str = ".gnu.version_d";
const VERNEED_SECTION: &str = ".gnu.version_r";
const DYNSTR_SECTION: &str = ".dynstr";

/// Where a named section's bytes lie in the file, as its own header states them.
fn section_place(file: &object::File<'_>, name: &str) -> Option<(usize, usize)> {
    let section = file.sections().find(|one| one.name().unwrap_or("") == name)?;
    let (at, size) = section.file_range()?;
    Some((usize::try_from(at).ok()?, usize::try_from(size).ok()?))
}

/// A name inside `.dynstr`, and nothing where the table does not reach: an offset past its end is left
/// unresolved rather than answered with the bytes that happen to follow.
fn version_name(raw: &[u8], strings: Option<(usize, usize)>, at: u64) -> Option<String> {
    let (base, size) = strings?;
    let offset = usize::try_from(at).ok()?;
    if offset >= size {
        return None;
    }
    let window = raw.get(base + offset..)?;
    let end = window.iter().position(|byte| *byte == 0)?;
    Some(clean(&String::from_utf8_lossy(&window[..end])))
}

/// IDA's view of symbol versioning: which version index each dynamic symbol carries, which versions this
/// file defines, and which versions it needs from elsewhere. None of it is readable from a plain symbol
/// name - `lab_second` in `libuse.so` and `lab_second` in `libver.so` are different symbols - so a
/// reader that skips these three tables cannot say which one a call reaches.
///
/// The record order is where a reader falls. `Verdef` is twenty bytes - four u16s (version, flags,
/// index, count), then the hash, then the offset of the name chain, then the stride to the next record -
/// and `Verneed` is sixteen: u16 version, u16 count, u32 file name, u32 to the aux chain, u32 next. The
/// version index a *need* carries is `vna_other`, a u16 six bytes into its record that has nothing to do
/// with the record's position, so reading one word late turns `2` into a name offset.
///
/// A symbol row claims nothing of its own: the index is looked up in this file's definitions, then in
/// what it needs, and prints as `-` where neither reaches - which is the honest answer for indices 0 and
/// 1, since binutils calls those `*local*` and `*global*` while LLVM gives them no version word at all.
fn symver_rows(raw: &[u8], file: &object::File<'_>) -> Vec<String> {
    if raw.len() < 64 || raw.get(..4) != Some(b"\x7fELF") {
        return Vec::new();
    }
    let little = raw.get(5) == Some(&1);
    let strings = section_place(file, DYNSTR_SECTION);
    let versym = section_place(file, VERSYM_SECTION);
    let verdef = section_place(file, VERDEF_SECTION);
    let verneed = section_place(file, VERNEED_SECTION);
    let mut symbols: Vec<u64> = Vec::new();
    if let Some((at, size)) = versym {
        for each in 0..size / 2 {
            match half_at(raw, at + each * 2, little) {
                Some(one) => symbols.push(one),
                None => break,
            }
        }
    }
    let mut defs: Vec<(u64, u64, u64, u64, u64, Option<String>)> = Vec::new();
    if let Some((at, size)) = verdef {
        let stop = at.checked_add(size).unwrap_or(0);
        let mut one = at;
        while one + 20 <= stop {
            let (Some(version), Some(flags), Some(index), Some(count)) = (
                half_at(raw, one, little),
                half_at(raw, one + 2, little),
                half_at(raw, one + 4, little),
                half_at(raw, one + 6, little),
            ) else {
                break;
            };
            let (Some(hash), Some(aux)) = (
                word_at(raw, one + 8, little),
                word_at(raw, one + 12, little),
            ) else {
                break;
            };
            let name = usize::try_from(aux)
                .ok()
                .and_then(|where_| word_at(raw, one + where_, little))
                .and_then(|at| version_name(raw, strings, at));
            defs.push((index, hash, flags, count, version, name));
            let next = word_at(raw, one + 16, little).unwrap_or(0);
            let Ok(step) = usize::try_from(next) else { break };
            if step == 0 {
                break;
            }
            one += step;
        }
    }
    let mut needs: Vec<(u64, u64, Option<String>, Option<String>, u64, bool)> = Vec::new();
    if let Some((at, size)) = verneed {
        let stop = at.checked_add(size).unwrap_or(0);
        let mut one = at;
        while one + 16 <= stop {
            let (Some(version), Some(count), Some(file_at), Some(aux)) = (
                half_at(raw, one, little),
                half_at(raw, one + 2, little),
                word_at(raw, one + 4, little),
                word_at(raw, one + 8, little),
            ) else {
                break;
            };
            let owner = version_name(raw, strings, file_at);
            if let Ok(start) = usize::try_from(aux) {
                let mut here = one + start;
                for _ in 0..count.max(1) {
                    let (Some(hash), Some(flags), Some(index), Some(name_at), Some(next)) = (
                        word_at(raw, here, little),
                        half_at(raw, here + 4, little),
                        half_at(raw, here + 6, little),
                        word_at(raw, here + 8, little),
                        word_at(raw, here + 12, little),
                    ) else {
                        break;
                    };
                    // A need's flag bit means something else again (`VER_FLG_NODEFLIB`) and the only
                    // value these files carry is zero, which both readers write as none, so anything
                    // else is left unnamed rather than answered with the definition table's word.
                    needs.push((index, hash, version_name(raw, strings, name_at), owner.clone(),
                                version, flags == 0));
                    let Ok(step) = usize::try_from(next) else { break };
                    if step == 0 {
                        break;
                    }
                    here += step;
                }
            }
            let next = word_at(raw, one + 12, little).unwrap_or(0);
            let Ok(step) = usize::try_from(next) else { break };
            if step == 0 {
                break;
            }
            one += step;
        }
    }
    if symbols.is_empty() && defs.is_empty() && needs.is_empty() {
        return Vec::new();
    }
    // What an index reaches in this file. Definitions win over needs, since a file that both defines and
    // needs the same index is saying which one its own symbols refer to.
    let mut reached: Vec<(u64, String)> = Vec::new();
    for (index, _hash, name, _file, _version, _flagged) in &needs {
        let reached_here = reached.iter().any(|one| one.0 == *index);
        if !reached_here {
            if let Some(one) = name {
                reached.push((*index, one.clone()));
            }
        }
    }
    for (index, _hash, _flags, _count, _version, name) in &defs {
        reached.retain(|one| one.0 != *index);
        if let Some(one) = name {
            reached.push((*index, one.clone()));
        }
    }
    let place = |one: Option<(usize, usize)>| one.map_or(-1isize, |(at, _)| at as isize);
    let mut rows = vec![format!(
        "symver\tsymbols\t{}\tdefs\t{}\tneeds\t{}\tversym\t{}\tverdef\t{}\tverneed\t{}\tbits\t{}",
        symbols.len(),
        defs.len(),
        needs.len(),
        place(versym),
        place(verdef),
        place(verneed),
        if raw.get(4) == Some(&2) { 64 } else { 32 },
    )];
    for (index, one) in symbols.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        let plain = one & 0x7FFF;
        let name = reached
            .iter()
            .find(|(at, _)| *at == plain)
            .map(|(_, name)| name.as_str())
            .unwrap_or("-");
        rows.push(format!(
            "symbol\t{index}\tvalue\t0x{one:x}\tindex\t{plain}\tname\t{name}\thidden\t{}",
            if one & 0x8000 != 0 { "yes" } else { "no" },
        ));
    }
    for (index, (at, hash, flags, count, version, name)) in defs.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        rows.push(format!(
            "def\t{index}\tindex\t{at}\thash\t{hash}\tflags\t{}\tname\t{}\tcnt\t{count}\tversion\t{version}",
            if *flags == 1 { "BASE" } else { "none" },
            name.clone().unwrap_or_else(|| "-".to_owned()),
        ));
    }
    for (index, (at, hash, name, file, version, flagged)) in needs.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        rows.push(format!(
            "need\t{index}\tfile\t{}\tname\t{}\thash\t{hash}\tindex\t{at}\tflags\t{}\tversion\t{version}",
            file.clone().unwrap_or_else(|| "-".to_owned()),
            name.clone().unwrap_or_else(|| "-".to_owned()),
            if *flagged { "none" } else { "-" },
        ));
    }
    for (label, length) in [("symbols", symbols.len()), ("defs", defs.len()), ("needs", needs.len())] {
        if length > MAX_LISTED {
            rows.push(format!("cut\t{label}\t{length}\tlisted\t{MAX_LISTED}"));
        }
    }
    rows
}

/// How many rows the version tables fill. A PIE linked without a version script has none of the three
/// sections, and a PE has no such convention at all, so both answer with nothing.
#[no_mangle]
pub extern "C" fn symver_count() -> i32 {
    SYMVER.with(|rows| rows.borrow().len() as i32)
}

/// One row: the totals, then the index each dynamic symbol carries, then the versions this file defines,
/// then the ones it needs from elsewhere. Row zero is the totals.
#[no_mangle]
pub extern "C" fn symver_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    SYMVER.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// Directory 9's record: four addresses at the file's own width, then the zero fill and the
/// characteristics - forty bytes of a 64-bit image, twenty-four of a 32-bit one.
const TLS_DIRECTORY: usize = 9;

/// Where the file says an address lies, in the three forms that have to be given together: the number
/// the bytes hold, that number with the image base taken off once, and the byte position it names. The
/// position is `-1` where no byte answers - for a TLS index, which lives in `.bss` and is allocated by
/// the loader rather than read from disk - and an address in no section at all says `-` for both.
fn tls_placed(pe: &Pe, raw: &[u8], value: u64, width: usize) -> Vec<String> {
    let rva = value.wrapping_sub(pe.image_base);
    let (offset, name) = match pe.at(rva) {
        // A section may claim more memory than the file gives it, so the position is only stated where a
        // read of this field would actually land inside the file.
        Some((at, name)) if at.saturating_add(width) <= raw.len() => (at.to_string(), name.to_string()),
        _ => (
            "-1".to_owned(),
            pe.in_empty(rva).map_or_else(|| "-".to_owned(), |name| name.to_owned()),
        ),
    };
    vec![
        format!("value\t0x{:x}", value),
        format!("rva\t0x{:x}", rva),
        format!("off\t{offset}"),
        format!("section\t{name}"),
    ]
}

/// IDA's thread-local storage window: what a PE's directory 9 states, and the callbacks the loader runs
/// before the entry point exists.
///
/// The four addresses are virtual rather than relative, which is why every row carries all three
/// spellings of them: a reader that subtracted the base twice, or not at all, shows up in one of the
/// columns. The array behind the fourth runs to its terminating zero, and each entry is looked up in the
/// export table, because a callback is a function and a function with a name is worth naming. Of
/// `tls.dll`'s seventy-three entries seventy are the file's own and three belong to the C runtime, which
/// exports nothing - those answer `-`, and they are the reason the list cannot be read off the symbols.
fn tls_rows(raw: &[u8], exported: &[(u64, String)]) -> Vec<String> {
    let pe = match Pe::parse(raw) {
        Some(found) => found,
        None => return Vec::new(),
    };
    let at = match pe.dirs.checked_add(TLS_DIRECTORY * 8) {
        Some(one) => one,
        None => return Vec::new(),
    };
    let (dir_rva, dir_size) = match (word_at(raw, at, true), word_at(raw, at + 4, true)) {
        (Some(one), Some(two)) => (one, two),
        _ => return Vec::new(),
    };
    // No directory, or one that declares no bytes, is a file that says nothing here - which is also what
    // an ELF says, since it keeps thread-local bookkeeping in program headers and a dynamic tag instead.
    if dir_rva == 0 || dir_size == 0 {
        return Vec::new();
    }
    let width = if pe.wide { 8 } else { 4 };
    let body = 4 * width + 8;
    let (where_, _) = match pe.at(dir_rva) {
        Some(found) => found,
        None => return Vec::new(),
    };
    if where_.saturating_add(body) > raw.len() {
        return Vec::new();
    }
    let mut fields = Vec::new();
    for each in 0..4 {
        match addr_at(raw, where_ + each * width, pe.wide, true) {
            Some(one) => fields.push(one),
            None => return Vec::new(),
        }
    }
    let (zero, character) = match (
        word_at(raw, where_ + 4 * width, true),
        word_at(raw, where_ + 4 * width + 4, true),
    ) {
        (Some(one), Some(two)) => (one, two),
        _ => return Vec::new(),
    };
    // The loader's own walk: entries until a zero, each one bounded by the bytes the file actually has.
    let mut callbacks: Vec<u64> = Vec::new();
    if let Some((start, _)) = pe.at(fields[3].wrapping_sub(pe.image_base)) {
        while callbacks.len() < 4096 {
            let one = match start.checked_add(callbacks.len() * width) {
                Some(at) => match addr_at(raw, at, pe.wide, true) {
                    Some(0) | None => break,
                    Some(value) => value.wrapping_sub(pe.image_base),
                },
                None => break,
            };
            callbacks.push(one);
        }
    }
    let mut rows = vec![format!(
        "tls\tdir\t{TLS_DIRECTORY}\trva\t0x{:x}\toff\t{where_}\tbytes\t{}\tbits\t{}\tbase\t0x{:x}\tcallbacks\t{}\tzero\t{}\tchar\t0x{:x}",
        dir_rva, dir_size, if pe.wide { 64 } else { 32 }, pe.image_base, callbacks.len(), zero, character
    )];
    for (label, value) in [("start", fields[0]), ("end", fields[1]), ("index", fields[2]), ("callbacks", fields[3])] {
        let mut row = vec!["field".to_owned(), label.to_owned()];
        row.extend(tls_placed(&pe, raw, value, width));
        rows.push(row.join("\t"));
    }
    for (index, rva) in callbacks.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        let value = rva.wrapping_add(pe.image_base);
        let name = exported
            .iter()
            .find(|(at, _)| *at == value)
            .map(|(_, name)| name.as_str())
            .unwrap_or("-");
        let mut row = vec!["callback".to_owned(), index.to_string()];
        row.extend(tls_placed(&pe, raw, value, width));
        row.push(format!("name\t{name}"));
        rows.push(row.join("\t"));
    }
    if callbacks.len() > MAX_LISTED {
        rows.push(format!("cut\tcallbacks\t{}\tlisted\t{MAX_LISTED}", callbacks.len()));
    }
    rows
}

/// How many rows the thread-local storage window fills. Nothing here has a directory 9 to read: an ELF
/// answers with program headers, a COFF object has no data directories, and a DLL built without any
/// thread-local object still answers, because its runtime supplies the table anyway.
#[no_mangle]
pub extern "C" fn tls_count() -> i32 {
    TLS.with(|rows| rows.borrow().len() as i32)
}

/// One row: the totals, then the four addresses the record holds, then the callbacks in the order the
/// loader walks them. Row zero is the totals.
#[no_mangle]
pub extern "C" fn tls_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    TLS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}

/// One relocation record's field, at the width the file's own class uses.
fn elf_word(body: &[u8], at: usize, wide: bool, little: bool) -> Option<u64> {
    if wide {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(body.get(at..at.checked_add(8)?)?);
        Some(if little { u64::from_le_bytes(buf) } else { u64::from_be_bytes(buf) })
    } else {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(body.get(at..at.checked_add(4)?)?);
        Some(u64::from(if little { u32::from_le_bytes(buf) } else { u32::from_be_bytes(buf) }))
    }
}

/// Which relocation table a section name states, if any: `Some(true)` for the RELA shape that carries
/// its own addend, `Some(false)` for REL, and `None` for anything that only looks like one.
fn relocation_shape(name: &str) -> Option<bool> {
    let (tail, addend) = name
        .strip_prefix(".rela")
        .map(|tail| (tail, true))
        .or_else(|| name.strip_prefix(".rel").map(|tail| (tail, false)))?;
    if tail.is_empty() || tail.starts_with('.') {
        Some(addend)
    } else {
        None
    }
}

/// The tightest named section whose address range holds the address, which is how a `.got` slot is told
/// apart from the `.relro_padding` that also covers it: the padding is a range, not a thing.
fn elf_owner(file: &object::File<'_>, where_: u64) -> String {
    let mut best: Option<(u64, String)> = None;
    for section in file.sections() {
        let size = section.size();
        if size == 0 || where_ < section.address() || where_ >= section.address() + size {
            continue;
        }
        let name = clean(section.name().unwrap_or("?"));
        if !name.starts_with('.') {
            continue;
        }
        if best.as_ref().is_none_or(|(wide, _)| size < *wide) {
            best = Some((size, name));
        }
    }
    best.map_or_else(|| "unmapped".to_owned(), |(_, name)| name)
}

/// The type names at least two readers wrote beside a number in the files on this host - `readelf -rW`,
/// `objdump -R` and `llvm-readobj --relocs`, per machine, because one number means a different word in
/// each instruction set: 6 is `R_X86_64_GLOB_DAT`, `R_386_GLOB_DAT` and `R_AARCH64_GLOB_DAT`, and the
/// x86 one is 1 against aarch64's 257. Which two readers agreed is recorded in the probe, not here:
/// binutils' `objdump` names none of the aarch64 types (it prints `UNKNOWN`), and readelf and
/// llvm-readobj cover for it. Anything else stays a number, so a RISC-V object prints types without names
/// rather than borrowing words from a table it was never in.
fn elf_type_name(machine: &str, kind: u64) -> Option<&'static str> {
    Some(match (machine, kind) {
        ("x86_64", 1) => "R_X86_64_64",
        ("x86_64", 6) => "R_X86_64_GLOB_DAT",
        ("x86_64", 7) => "R_X86_64_JUMP_SLOT",
        ("x86_64", 8) => "R_X86_64_RELATIVE",
        ("i386", 1) => "R_386_32",
        ("i386", 6) => "R_386_GLOB_DAT",
        ("i386", 7) => "R_386_JUMP_SLOT",
        ("i386", 8) => "R_386_RELATIVE",
        ("aarch64", 257) => "R_AARCH64_ABS64",
        ("aarch64", 1025) => "R_AARCH64_GLOB_DAT",
        ("aarch64", 1026) => "R_AARCH64_JUMP_SLOT",
        ("aarch64", 1027) => "R_AARCH64_RELATIVE",
        _ => return None,
    })
}

/// The dynamic relocation records of an ELF: the same question the PE directory answers - which addresses
/// get rewritten - asked of a format that keeps the answer in sections.
///
/// Two shapes, because the record carries its addend in one class and not the other, and the symbol
/// index is squeezed out of the info word at different widths: 64-bit splits it above the low 32 bits of
/// an eight-byte word, 32-bit above the low 8 of a four-byte one. A symbol index of zero is the
/// symbol-less case - the relative record that says "write the load address plus this addend" - and is
/// printed as no symbol rather than as the table's first entry. The addend is printed as the unsigned
/// word the file holds: folding it into a sign would be this reader's arithmetic, not the file's.
fn elf_reloc_rows(raw: &[u8]) -> Vec<String> {
    let Ok(file) = object::File::parse(raw) else {
        return Vec::new();
    };
    if label(&file.format()) != "elf" {
        return Vec::new();
    }
    let machine = label(&file.architecture());
    let wide = file.is_64();
    let little = file.is_little_endian();
    let step = if wide { 8 } else { 4 };
    let mut tables: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut entries = 0usize;
    let mut relative = 0usize;
    for section in file.sections() {
        // The crate calls both relocation tables `Metadata`, so the record's shape is read off the name
        // the ELF convention uses for it: `.rela…` carries its own addend word and `.rel…` does not.
        // `.relro_padding` shares the first four letters and is a range rather than a table, which is why
        // what follows has to be empty or a further dot.
        let name = clean(section.name().unwrap_or("?"));
        let Some(addend) = relocation_shape(&name) else {
            continue;
        };
        let Ok(body) = section.data() else { continue };
        let slot = step * if addend { 3 } else { 2 };
        let count = body.len() / slot;
        tables.push(format!(
            "table\t{name}\tentries\t{count}\tslot_bytes\t{slot}\taddend\t{}",
            if addend { "yes" } else { "no" }
        ));
        for each in 0..count {
            entries += 1;
            let at = each * slot;
            let (Some(where_), Some(info)) = (elf_word(body, at, wide, little), elf_word(body, at + step, wide, little))
            else {
                break;
            };
            let symbol = if wide { info >> 32 } else { info >> 8 };
            let number = info & if wide { 0xffff_ffff } else { 0xff };
            let spelled = if symbol == 0 {
                relative += 1;
                "-".to_owned()
            } else {
                file.dynamic_symbols()
                    .nth(symbol as usize)
                    .map_or_else(|| "?".to_owned(), |one| clean(one.name().unwrap_or("?")))
            };
            let stated = if addend {
                elf_word(body, at + 2 * step, wide, little).map(|one| one.to_string())
            } else {
                None
            };
            fixes.push(format!(
                "fixup\t0x{where_:x}\ttype\t{number}\tname\t{}\tsym\t{spelled}\taddend\t{}\tsection\t{}",
                elf_type_name(&machine, number).unwrap_or("-"),
                stated.unwrap_or_else(|| "-".to_owned()),
                elf_owner(&file, where_),
            ));
        }
    }
    let listed = fixes.len();
    let symbolic = entries - relative;
    let mut out = vec![format!(
        "relocs\tkind\tdyn\ttables\t{}\tentries\t{entries}\tsymbolic\t{symbolic}\trelative\t{relative}\tmachine\t{machine}\tbits\t{}",
        tables.len(),
        if wide { 64 } else { 32 }
    )];
    out.append(&mut tables);
    for (index, row) in fixes.into_iter().enumerate() {
        if index >= MAX_LISTED {
            break;
        }
        out.push(row);
    }
    if listed > MAX_LISTED {
        out.push(format!("cut\tfixups\t{listed}\tlisted\t{MAX_LISTED}"));
    }
    out
}

/// The base-relocation directory: the fixups a loader applies to the image when it does not land at the
/// address it was linked for, which is what an analyser needs in order to know that a word in `.data`
/// is a pointer rather than a number.
///
/// Directory five is a run of blocks, and a block is a page RVA, its own length, and that many
/// two-byte entries whose high nibble is the type and whose low twelve bits are the offset inside the
/// page. The length is what carries the walk from one block to the next, so a block that claims less
/// than its own header, or more than the directory has left, ends the list with the claim said out loud
/// rather than with an entry invented past it.
fn reloc_rows(raw: &[u8]) -> Vec<String> {
    let Some(pe) = Pe::parse(raw) else {
        return elf_reloc_rows(raw);
    };
    // Directory five: the base-relocation table, eight bytes of RVA and size at a fixed distance into
    // the directory array.
    let Some(at_rva) = pe.dirs.checked_add(40) else {
        return Vec::new();
    };
    let Some(at_size) = pe.dirs.checked_add(44) else {
        return Vec::new();
    };
    let Some(dir_rva) = word_at(raw, at_rva, true) else {
        return Vec::new();
    };
    let Some(dir_size) = word_at(raw, at_size, true) else {
        return Vec::new();
    };
    let (dir_off, dir_section) = where_lies(&pe, dir_rva);
    let mut rows: Vec<String> = Vec::new();
    let mut blocks = 0usize;
    let mut entries = 0usize;
    let mut listed = 0usize;
    let mut named = 0usize;
    let mut stopped = "";
    // An absent directory is an answer, not a failure: a PE linked `/FIXED` has nothing to apply, and
    // so does a freestanding image whose data needs no fixup. `exp.dll` is the second case, and its
    // rows are this line and nothing else.
    if dir_rva != 0 && dir_size != 0 {
        let Some((start, _)) = pe.at(dir_rva) else {
            return vec![format!(
                "relocs\tdir\t{:#x}\tbytes\t{}\toff\t{}\tsection\t{}\tblocks\t0\tentries\t0\tnamed\t0\tstopped\tunmapped",
                dir_rva, dir_size, dir_off, dir_section
            )];
        };
        // The bytes the walk may read: what the directory claims, cut to what the file has. A directory
        // that claims more than the image holds is said, not followed.
        let room = raw.len().saturating_sub(start);
        let want = usize::try_from(dir_size).unwrap_or(room);
        let mut left = want.min(room);
        let mut at = start;
        if want > room {
            stopped = "past the file";
        }
        while left >= 8 {
            let Some(page) = word_at(raw, at, true) else {
                break;
            };
            let Some(where_) = at.checked_add(4) else {
                break;
            };
            let Some(size) = word_at(raw, where_, true) else {
                break;
            };
            let Ok(body) = usize::try_from(size) else {
                stopped = "block size";
                break;
            };
            // Eight bytes is the block's own header, and the entries that follow are two bytes each, so
            // a length that is neither of those is a file that contradicts itself.
            if body < 8 || body % 4 != 0 || body > left {
                stopped = "block size";
                break;
            }
            let count = (body - 8) / 2;
            blocks += 1;
            entries += count;
            rows.push(format!("block\tpage\t{:#x}\tsize\t{}\tentries\t{}", page, size, count));
            for each in 0..count {
                let Some(first) = at.checked_add(8) else {
                    stopped = "entry past the file";
                    break;
                };
                let Some(step) = each.checked_mul(2) else {
                    stopped = "entry past the file";
                    break;
                };
                let Some(where_) = first.checked_add(step) else {
                    stopped = "entry past the file";
                    break;
                };
                let Some(word) = half_at(raw, where_, true) else {
                    stopped = "entry past the file";
                    break;
                };
                if listed >= MAX_LISTED {
                    continue;
                }
                listed += 1;
                // The high nibble is the type and the low twelve bits the offset inside the page, which
                // is why a block covers 4 KiB and no more.
                let kind = ((word >> 12) & 0xf) as u16;
                let rva = page.checked_add(word & 0x0fff).unwrap_or(page);
                let (off, section) = where_lies(&pe, rva);
                let head = match reloc_type(kind) {
                    Some(name) => {
                        named += 1;
                        format!("fixup\t{:#x}\ttype\t{kind}\tname\t{name}", rva)
                    }
                    None => format!("fixup\t{:#x}\ttype\t{kind}", rva),
                };
                rows.push(format!("{head}\toff\t{off}\tsection\t{section}"));
            }
            let Some(next) = at.checked_add(body) else {
                break;
            };
            let Some(rest) = left.checked_sub(body) else {
                break;
            };
            at = next;
            left = rest;
        }
        if left != 0 && stopped.is_empty() {
            stopped = "trailing";
        }
    }
    let mut head = format!(
        "relocs\tdir\t{:#x}\tbytes\t{}\toff\t{}\tsection\t{}\tblocks\t{}\tentries\t{}\tnamed\t{}",
        dir_rva, dir_size, dir_off, dir_section, blocks, entries, named
    );
    if !stopped.is_empty() {
        head.push_str("\tstopped\t");
        head.push_str(stopped);
    }
    let mut out = vec![head];
    out.append(&mut rows);
    if entries > listed {
        out.push(format!("cut\tfixups\t{entries}\tlisted\t{listed}"));
    }
    out
}

/// The map and the string list, from the same walk of the same bytes: every range the file names, in
/// order, with what falls between them called what it is - padding inside a segment the loader maps, or
/// bytes no table and no segment reaches at all.
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

thread_local! {
    /// The Functions window: the addresses the file's own symbol tables call functions.
    static FUNCTIONS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// The Names window: every name the file attaches to an address, from either symbol table or from
    /// the export directory, with the address kept beside it rather than folded away.
    static NAMED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// One row of the Names window. `from` says which table the name came from and `kind` says what the file
/// called it - a name the export table carries states no kind at all, so it answers `-` rather than
/// borrowing the one its address happens to fall inside.
fn named_rows(entries: &[(u64, String, String, String)]) -> Vec<String> {
    let spelled = entries
        .iter()
        .filter(|(_, raw, _, _)| demangle::demangle(raw).is_some())
        .count();
    let unique = entries.iter().map(|(at, _, _, _)| *at).collect::<std::collections::HashSet<_>>().len();
    let mut out = vec![format!(
        "names\ttotal\t{}\taddresses\t{unique}\tdemangled\t{spelled}",
        entries.len()
    )];
    for (listed, (address, raw, kind, from)) in entries.iter().enumerate() {
        if listed >= MAX_LISTED {
            break;
        }
        let read = match demangle::demangle(raw) {
            Some(text) => clean(&text),
            None => "-".to_owned(),
        };
        out.push(format!(
            "name\t0x{address:x}\tfrom\t{from}\tkind\t{kind}\tname\t{raw}\tread\t{read}"
        ));
    }
    if entries.len() > MAX_LISTED {
        out.push(format!("cut\tnames\t{}", entries.len()));
    }
    out
}

/// How many rows the Names window has.
#[no_mangle]
pub extern "C" fn named_count() -> i32 {
    NAMED.with(|rows| rows.borrow().len() as i32)
}

/// One row: the address, which table the name came from, what kind the file gave it, the name as the
/// table spells it, and the C++ reading where two demanglers agree on one. Row zero is the totals.
#[no_mangle]
pub extern "C" fn named_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    NAMED.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
}


/// One entry of the Functions window: address, the size the symbol carries (an object file's symbols do
/// have them, so this is not the disassembler's estimate), the section the name lies in, and the name in
/// both spellings - the table's raw bytes and, where two demanglers agree on one, the C++ reading.
///
/// The totals row separates what was counted from what was answered: `sized` and `demangled` are the
/// columns that could be filled, so a file whose symbols carry no sizes says so in the first row instead
/// of printing zeros that look like measurements.
fn function_rows(entries: &[(u64, u64, String, String)]) -> Vec<String> {
    let sized = entries.iter().filter(|(_, size, _, _)| *size != 0).count();
    let spelled = entries
        .iter()
        .filter(|(_, _, _, raw)| demangle::demangle(raw).is_some())
        .count();
    let mut out = vec![format!(
        "functions\ttotal\t{}\tsized\t{sized}\tdemangled\t{spelled}\tfrom\tsymtabs",
        entries.len()
    )];
    for (index, (address, size, section, raw)) in entries.iter().enumerate() {
        if index >= MAX_LISTED {
            continue;
        }
        let name = match demangle::demangle(raw) {
            Some(text) => clean(&text),
            None => "-".to_owned(),
        };
        let size = if *size == 0 { "-".to_owned() } else { size.to_string() };
        out.push(format!(
            "func\t0x{address:x}\tsize\t{size}\tsection\t{section}\tsym\t{raw}\tname\t{name}"
        ));
    }
    if entries.len() > MAX_LISTED {
        out.push(format!("cut\tfunctions\t{}", entries.len()));
    }
    out
}

/// How many rows the Functions window has. Zero is an answer, not a failure: a stripped binary and a
/// PE image with only an export table name no function in their symbol tables.
#[no_mangle]
pub extern "C" fn function_count() -> i32 {
    FUNCTIONS.with(|rows| rows.borrow().len() as i32)
}

/// One row: the address in hex, the size the symbol states (or `-`), the section, the raw name and the
/// demangled spelling where there is a two-witness one. Row zero is the totals.
#[no_mangle]
pub extern "C" fn function_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    FUNCTIONS.with(|rows| match rows.borrow().get(index as usize) {
        Some(row) => copy(row, out, cap),
        None => -1,
    })
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

/// How many base-relocation rows the last file produced, including its totals row. One row means the
/// image has a directory and nothing in it, or no directory at all - both of which are answers.
#[no_mangle]
pub extern "C" fn reloc_count() -> i32 {
    RELOCS.with(|rows| rows.borrow().len() as i32)
}

/// One row: `block` with the page and its own length, or `fixup` with the address, the type number and
/// - where a fixture paired one - the name, the position in the file and the section that owns it. Row
/// zero is the totals.
#[no_mangle]
pub extern "C" fn reloc_at(index: i32, out: *mut u8, cap: i32) -> i32 {
    if index < 0 {
        return -1;
    }
    RELOCS.with(|rows| match rows.borrow().get(index as usize) {
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
