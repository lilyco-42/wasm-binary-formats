//! PE inspection on the host target. The inputs are hand-assembled byte buffers, because a
//! real compiler-produced .exe would make the test depend on the toolchain.

use apk_lens::pe::{
    characteristics, cli_rva, entry_rva, image_base, machine, magic, parse, sections, subsystem,
};

const NT: usize = 64;

fn put_u16(bytes: &mut Vec<u8>, at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_str(bytes: &mut Vec<u8>, at: usize, text: &str) {
    bytes[at..at + text.len()].copy_from_slice(text.as_bytes());
}

/// A PE32 (32-bit) or PE32+ (64-bit) image with two sections, sized exactly like the spec says.
fn build(pe32plus: bool, characteristics_value: u16, cli: u32) -> Vec<u8> {
    build_with_optional(
        pe32plus,
        characteristics_value,
        cli,
        if pe32plus { 240 } else { 224 },
    )
}

/// The declared optional size is written both into the header field and as the real distance to
/// the section table, so passing 216 reproduces the smaller-but-legal PE32 headers in the wild.
fn build_with_optional(
    pe32plus: bool,
    characteristics_value: u16,
    cli: u32,
    optional_size: usize,
) -> Vec<u8> {
    let dirs_at = if pe32plus { 112 } else { 96 };
    let total = NT + 24 + optional_size + 2 * 40;
    let mut bytes = vec![0u8; total];

    put_str(&mut bytes, 0, "MZ");
    put_u32(&mut bytes, 0x3c, NT as u32);

    put_str(&mut bytes, NT, "PE");
    put_u16(&mut bytes, NT + 4, if pe32plus { 0x8664 } else { 0x014c });
    put_u16(&mut bytes, NT + 6, 2);
    put_u16(&mut bytes, NT + 20, optional_size as u16); // SizeOfOptionalHeader, per IMAGE_FILE_HEADER
    put_u16(&mut bytes, NT + 22, characteristics_value);

    let opt = NT + 24;
    put_u16(&mut bytes, opt, if pe32plus { 0x20b } else { 0x10b });
    put_u32(&mut bytes, opt + 16, 0x1000); // AddressOfEntryPoint
    put_u32(&mut bytes, opt + 56, 0x3000); // SizeOfImage
    if pe32plus {
        put_u64(&mut bytes, opt + 24, 0x1400_0000)
    } else {
        put_u32(&mut bytes, opt + 28, 0x40_0000)
    }
    put_u16(&mut bytes, opt + 68, 2); // Subsystem: GUI
    put_u32(&mut bytes, opt + dirs_at - 4, 15); // NumberOfRvaAndSizes
    put_u32(&mut bytes, opt + dirs_at + 14 * 8, cli); // COM descriptor directory

    let table = opt + optional_size;
    for (index, (name, rva)) in [(".text", 0x1000u32), (".rdata", 0x2000u32)]
        .iter()
        .enumerate()
    {
        let at = table + index * 40;
        put_str(&mut bytes, at, name);
        put_u32(&mut bytes, at + 8, 0x120);
        put_u32(&mut bytes, at + 12, *rva);
        put_u32(&mut bytes, at + 16, 0x200);
        put_u32(&mut bytes, at + 20, (0x400 + index * 0x200) as u32);
        put_u32(&mut bytes, at + 36, 0x6000_0020);
    }
    bytes
}

fn error_text() -> String {
    let mut buffer = vec![0u8; 256];
    let written = apk_lens::last_error(buffer.as_mut_ptr(), buffer.len() as i32);
    String::from_utf8_lossy(&buffer[..written.max(0) as usize]).into_owned()
}

#[test]
fn reads_a_pe32_header() {
    let file = build(false, 0x0102, 0);
    assert_eq!(parse(&file), 0, "{}", error_text());
    assert_eq!(machine(), 0x014c);
    assert_eq!(magic(), 0x10b);
    assert_eq!(entry_rva(), 0x1000);
    assert_eq!(image_base(), 0x40_0000);
    assert_eq!(subsystem(), 2);
    assert_eq!(cli_rva(), 0, "no COM descriptor means not a .NET image");
    assert_eq!(characteristics() & 0x2000, 0, "IMAGE_FILE_DLL not set");
}

#[test]
fn reads_a_pe32plus_header() {
    let file = build(true, 0x2000, 0x20d0);
    assert_eq!(parse(&file), 0, "{}", error_text());
    assert_eq!(machine(), 0x8664);
    assert_eq!(magic(), 0x20b);
    assert_eq!(image_base(), 0x1400_0000, "ImageBase is 64-bit in PE32+");
    assert_eq!(entry_rva(), 0x1000, "AddressOfEntryPoint keeps its offset");
    assert_eq!(subsystem(), 2);
    assert_eq!(characteristics() & 0x2000, 0x2000, "IMAGE_FILE_DLL set");
}

#[test]
fn detects_a_net_assembly() {
    let file = build(true, 0x0102, 0x20d0);
    assert_eq!(parse(&file), 0);
    assert_eq!(
        cli_rva(),
        0x20d0,
        "the COM descriptor directory is what marks .NET"
    );
}

#[test]
fn lists_sections_with_their_rvas() {
    let file = build(false, 0x0102, 0);
    assert_eq!(parse(&file), 0);
    let listing = sections();
    let rows: Vec<&str> = listing.lines().collect();
    assert_eq!(rows.len(), 2, "{listing:?}");
    assert!(
        rows[0].starts_with(".text\t4096\t288\t512\t1024\t"),
        "{}",
        rows[0]
    );
    assert!(rows[1].starts_with(".rdata\t8192\t"), "{}", rows[1]);
}

#[test]
fn refuses_things_that_are_not_pe() {
    let not_mz = vec![0u8; 512];
    assert_eq!(parse(&not_mz), -2, "no MZ signature");

    let mut no_pe = build(false, 0x0102, 0);
    put_str(&mut no_pe, NT, "XX");
    assert_eq!(parse(&no_pe), -3, "MZ but no PE signature");

    let mut far = build(false, 0x0102, 0);
    put_u32(&mut far, 0x3c, u32::MAX);
    assert_eq!(parse(&far), -5, "e_lfanew beyond the file");

    assert_eq!(parse(&[b'M', b'Z']), -1, "shorter than a DOS header");
    assert!(
        error_text().contains("PE") || error_text().contains("empty"),
        "{}",
        error_text()
    );
    assert_eq!(
        machine(),
        0,
        "getters must not return a stale header after a rejection"
    );
}

#[test]
fn survives_an_implausible_header_size() {
    // SizeOfOptionalHeader is attacker controlled. An absurd value must not send the reader past
    // the end of the file; it falls back to the canonical size instead of panicking.
    let mut file = build(false, 0x0102, 0);
    put_u16(&mut file, NT + 20, 0xffff);
    assert_eq!(parse(&file), 0);
    assert_eq!(
        sections().lines().count(),
        2,
        "an out-of-range declared size falls back to the canonical 224"
    );

    let mut many = build(false, 0x0102, 0);
    put_u16(&mut many, NT + 6, u16::MAX);
    assert_eq!(parse(&many), 0);
    assert_eq!(
        sections().lines().count(),
        2,
        "the table is clamped to what the file holds"
    );
}

#[test]
fn honours_a_smaller_but_legal_optional_header() {
    // 96 bytes of standard fields plus 15 directories is exactly 216, and real PE32 images use
    // it. Forcing 224 here would start the section table eight bytes late and report garbage.
    let file = build_with_optional(false, 0x0022, 0x2008, 216);
    assert_eq!(parse(&file), 0, "{}", error_text());
    let listing = sections();
    assert_eq!(listing.lines().count(), 2, "{listing:?}");
    assert!(
        listing.starts_with(".text\t4096\t288\t512\t1024\t"),
        "{listing}"
    );
    assert_eq!(cli_rva(), 0x2008, "15 directories still fit in 216 bytes");
    assert_eq!(characteristics() & 0x2000, 0, "0x0022 is an exe, not a dll");
}

#[test]
fn falls_back_when_the_field_is_not_a_size_at_all() {
    // Zero is not a header size. Reading it literally points the section table at the start of
    // the optional header, which is the failure this guard exists to stop.
    let mut file = build(false, 0x0102, 0x2008);
    put_u16(&mut file, NT + 20, 0);
    assert_eq!(parse(&file), 0, "{}", error_text());
    let listing = sections();
    assert_eq!(
        listing.lines().count(),
        2,
        "must fall back to 224: {listing:?}"
    );
    assert!(listing.starts_with(".text\t4096\t"), "{listing}");
    assert_eq!(cli_rva(), 0x2008, "the data directories stay reachable");
}
