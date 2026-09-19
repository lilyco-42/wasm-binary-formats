//! Round-trip test on the host target: build a zip in memory, then read it back
//! through the same C ABI the wasm build exposes.

use apk_lens::{count, entry, extract, last_error, open};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

fn sample_zip() -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (name, body) in [
        ("assets/index.html", "<h1>hi</h1>"),
        ("classes.dex", "dexbytes"),
    ] {
        writer.start_file(name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn read_entry(index: i32) -> String {
    let cap = 4096;
    let buffer = vec![0u8; cap];
    let written = unsafe { entry(index, buffer.as_ptr() as *mut u8, cap as i32) };
    assert!(written > 0, "entry {index} listing failed");
    String::from_utf8_lossy(&buffer[..written as usize]).into_owned()
}

#[test]
fn opens_lists_and_extracts() {
    let zip = sample_zip();
    let rc = unsafe { open(zip.as_ptr(), zip.len() as i32) };
    assert_eq!(rc, 0, "open should accept the archive we just wrote");
    assert_eq!(unsafe { count() }, 2);

    assert!(read_entry(0).starts_with("assets/index.html\t"));

    let cap = 64;
    let mut out = vec![0u8; cap];
    let n = unsafe { extract(0, out.as_mut_ptr(), cap as i32) };
    assert_eq!(n, 11, "index.html body length");
    assert_eq!(&out[..n as usize], b"<h1>hi</h1>");
}

#[test]
fn rejects_a_non_zip_and_reports_why() {
    let junk = b"not a zip file at all".to_vec();
    let rc = unsafe { open(junk.as_ptr(), junk.len() as i32) };
    assert!(rc < 0, "garbage input must be refused");

    let cap = 256;
    let mut buffer = vec![0u8; cap];
    let written = unsafe { last_error(buffer.as_mut_ptr(), cap as i32) };
    assert!(written > 0, "an error should be recorded");
    let message = String::from_utf8_lossy(&buffer[..written as usize]).into_owned();
    assert!(
        message.contains("zip"),
        "error text should explain the failure: {message}"
    );
}

#[test]
fn extract_refuses_to_overflow_the_callers_buffer() {
    let zip = sample_zip();
    assert_eq!(unsafe { open(zip.as_ptr(), zip.len() as i32) }, 0);
    let mut tiny = vec![0u8; 4];
    let rc = unsafe { extract(0, tiny.as_mut_ptr(), tiny.len() as i32) };
    assert_eq!(rc, -4, "a too-small buffer must be rejected, not overrun");
}

fn fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test/fixtures/lab-fixture.apk"
    );
    std::fs::read(path).unwrap_or_else(|error| {
        panic!("{path} is missing, run node scripts/make-fixture.mjs: {error}")
    })
}

/// The in-memory zip above is written by the same crate that reads it. This one is written by
/// hand, so it also checks the reader against an archive that only the spec was used for.
#[test]
fn reads_the_handwritten_apk_fixture() {
    let apk = fixture();
    assert_eq!(unsafe { open(apk.as_ptr(), apk.len() as i32) }, 0);
    assert_eq!(unsafe { count() }, 8);

    let names: Vec<String> = (0..8)
        .map(|index| read_entry(index).split('\t').next().unwrap().to_string())
        .collect();
    assert!(
        names.contains(&"assets/www/index.html".to_string()),
        "{names:?}"
    );
    assert!(names.contains(&"META-INF/CERT.SF".to_string()), "{names:?}");

    // index.html is deflated in the fixture, so this exercises the zlib reader.
    let index = names
        .iter()
        .position(|name| name == "assets/www/index.html")
        .unwrap() as i32;
    let mut out = vec![0u8; 4096];
    let n = unsafe { extract(index, out.as_mut_ptr(), out.len() as i32) };
    assert!(n > 20, "deflated entry should extract, got rc {n}");
    let head = &out[..(n as usize).min(40)];
    assert!(
        head.starts_with(b"<!doctype html>"),
        "unexpected body: {:?}",
        String::from_utf8_lossy(head)
    );

    // AndroidManifest.xml is stored and starts with the res AXML chunk type 0x0003.
    let manifest = names
        .iter()
        .position(|name| name == "AndroidManifest.xml")
        .unwrap() as i32;
    let m = unsafe { extract(manifest, out.as_mut_ptr(), out.len() as i32) };
    assert_eq!(m, 28);
    assert_eq!(&out[..2], &[0x03, 0x00], "binary AXML magic");
}
