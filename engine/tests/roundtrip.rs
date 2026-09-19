//! Round-trip test on the host target: build a zip in memory, then read it back
//! through the same C ABI the wasm build exposes.

use apk_lens::{count, entry, extract, last_error, open};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

fn sample_zip() -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (name, body) in [("assets/index.html", "<h1>hi</h1>"), ("classes.dex", "dexbytes")] {
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
    assert!(message.contains("zip"), "error text should explain the failure: {message}");
}

#[test]
fn extract_refuses_to_overflow_the_callers_buffer() {
    let zip = sample_zip();
    assert_eq!(unsafe { open(zip.as_ptr(), zip.len() as i32) }, 0);
    let mut tiny = vec![0u8; 4];
    let rc = unsafe { extract(0, tiny.as_mut_ptr(), tiny.len() as i32) };
    assert_eq!(rc, -4, "a too-small buffer must be rejected, not overrun");
}
