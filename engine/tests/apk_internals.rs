//! APK-internal format tests: the two formats that live *inside* an APK once it is unpacked.

use apk_lens::axml;
use apk_lens::dex;

fn put_u16(bytes: &mut Vec<u8>, at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn dex_header(version: &[u8; 3]) -> Vec<u8> {
    const CHECKSUM: u32 = 0xdead_beef;
    let mut bytes = vec![0u8; 0x70];
    bytes[0..4].copy_from_slice(b"dex\n");
    bytes[4..7].copy_from_slice(version);
    put_u32(&mut bytes, 0x08, CHECKSUM);
    put_u32(&mut bytes, 0x20, 0x400); // file_size
    put_u32(&mut bytes, 0x24, 0x70); // header_size
    put_u32(&mut bytes, 0x28, 0x1234_5678); // endian_tag
    put_u32(&mut bytes, 0x34, 0x300); // map_off
    put_u32(&mut bytes, 0x38, 12); // string_ids_size
    put_u32(&mut bytes, 0x40, 3); // type_ids_size
    put_u32(&mut bytes, 0x58, 7); // method_ids_size
    put_u32(&mut bytes, 0x60, 2); // class_defs_size
    bytes
}

#[test]
fn reads_a_dex_header() {
    let bytes = dex_header(b"039");
    assert_eq!(dex::parse(&bytes), 0);
    assert_eq!(dex::version(), "039");
    assert_eq!(
        dex::checksum(),
        3_735_928_559,
        "the checksum round-trips unsigned"
    );
    assert_eq!(dex::header_size(), 0x70);
    assert_eq!(dex::file_size(), 0x400);
    assert_eq!(dex::map_off(), 0x300);
    assert_eq!(
        (
            dex::string_ids(),
            dex::type_ids(),
            dex::method_ids(),
            dex::class_defs()
        ),
        (12, 3, 7, 2)
    );
}

#[test]
fn rejects_things_that_are_not_dex() {
    assert_eq!(dex::parse(&vec![0u8; 0x6f]), -1, "shorter than a header");

    let mut not_magic = dex_header(b"035");
    not_magic[0] = b'D';
    assert_eq!(dex::parse(&not_magic), -2, "magic is case sensitive");

    let mut wrong_endian = dex_header(b"035");
    put_u32(&mut wrong_endian, 0x28, 0x7856_3412);
    assert_eq!(dex::parse(&wrong_endian), -3, "big-endian tag");

    let mut wrong_header = dex_header(b"035");
    put_u32(&mut wrong_header, 0x24, 0x6c);
    assert_eq!(dex::parse(&wrong_header), -4, "header size must be 0x70");
    assert_eq!(
        dex::version(),
        "",
        "a rejection must clear the previous result"
    );
}

/// A RES_XML_TYPE chunk wrapping a RES_STRING_POOL_TYPE chunk, the layout aapt emits for
/// AndroidManifest.xml. `utf8` selects the flag and the length encoding together.
fn axml_with(strings: &[&str], utf8: bool) -> Vec<u8> {
    let mut pool_strings = Vec::new();
    let mut offsets = Vec::new();
    for text in strings {
        offsets.push(pool_strings.len() as u32);
        if utf8 {
            let body = text.as_bytes();
            pool_strings.push(body.len() as u8);
            pool_strings.push(body.len() as u8);
            pool_strings.extend_from_slice(body);
            pool_strings.push(0);
        } else {
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut framed = vec![units.len() as u16];
            framed.extend_from_slice(&units);
            framed.push(0);
            for unit in framed {
                pool_strings.extend_from_slice(&unit.to_le_bytes());
            }
        }
    }
    if !utf8 && pool_strings.len() % 2 != 0 {
        pool_strings.push(0);
    }
    let header = 28usize;
    let strings_start = header + 4 * strings.len();
    let chunk_size = (strings_start + pool_strings.len()) as u32;
    let strings_start = strings_start as u32;

    let mut bytes = vec![0u8; 8 + chunk_size as usize];
    put_u16(&mut bytes, 0, 0x0003); // RES_XML_TYPE
    put_u16(&mut bytes, 2, 8); // its header size is where the pool starts
    let total = bytes.len() as u32;
    put_u32(&mut bytes, 4, total);

    put_u16(&mut bytes, 8, 0x0001); // RES_STRING_POOL_TYPE
    put_u16(&mut bytes, 10, header as u16);
    put_u32(&mut bytes, 12, chunk_size);
    put_u32(&mut bytes, 16, strings.len() as u32);
    put_u32(&mut bytes, 20, if utf8 { 0x100 } else { 0 });
    put_u32(&mut bytes, 24, strings_start);
    for (index, offset) in offsets.iter().enumerate() {
        put_u32(&mut bytes, (8 + header) as usize + index * 4, *offset);
    }
    let at = (8 + strings_start) as usize;
    bytes[at..at + pool_strings.len()].copy_from_slice(&pool_strings);
    bytes
}

#[test]
fn reads_a_utf16_string_pool() {
    let bytes = axml_with(
        &["package", "android.intent.action.MAIN", "Lcom/example/App;"],
        false,
    );
    assert_eq!(axml::parse(&bytes), 0);
    assert_eq!(axml::count(), 3);
    assert_eq!(axml::declared(), 3);
    assert_eq!(axml::at(0).as_deref(), Some("package"));
    assert_eq!(axml::at(1).as_deref(), Some("android.intent.action.MAIN"));
    assert_eq!(axml::at(2).as_deref(), Some("Lcom/example/App;"));
    assert!(axml::at(3).is_none(), "one past the pool must be refused");
}

#[test]
fn reads_a_utf8_string_pool() {
    let bytes = axml_with(&["package", "com.example.app"], true);
    assert_eq!(axml::parse(&bytes), 0);
    assert_eq!(
        axml::flags() & 0x100,
        0x100,
        "UTF8_FLAG is what selects the codec"
    );
    assert_eq!(axml::at(0).as_deref(), Some("package"));
    assert_eq!(axml::at(1).as_deref(), Some("com.example.app"));
}

#[test]
fn refuses_a_chunk_that_is_not_binary_xml() {
    assert_eq!(
        axml::parse(&vec![0u8; 8]),
        -1,
        "smaller than a chunk header plus pool"
    );

    let mut not_xml = axml_with(&["package"], false);
    put_u16(&mut not_xml, 0, 0x0002);
    assert_eq!(axml::parse(&not_xml), -2, "RES_XML_TYPE required");

    let mut no_pool = axml_with(&["package"], false);
    put_u16(&mut no_pool, 8, 0x0102);
    assert_eq!(
        axml::parse(&no_pool),
        -3,
        "the child chunk must be a string pool"
    );
    assert_eq!(axml::count(), 0, "a rejection must empty the previous pool");
}

#[test]
fn a_truncated_pool_yields_the_strings_that_fit() {
    let full = axml_with(
        &["package", "android.intent.action.MAIN", "Lcom/example/App;"],
        false,
    );
    let cut = full[..full.len() - 20].to_vec();
    assert_eq!(axml::parse(&cut), 0, "a short buffer is not a parse error");
    assert!(axml::count() <= 3, "{}", axml::count());
    assert_eq!(axml::at(0).as_deref(), Some("package"));
}
