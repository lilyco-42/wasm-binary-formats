//! apk-lens: open an APK (or any zip) once, list its entries, extract one at a time.
//!
//! The ABI is plain integers and byte buffers so the JS side needs no bundler and no
//! wasm-bindgen glue:
//!
//!   open(ptr, len) -> i32          // 0 ok, negative = error
//!   count() -> i32
//!   entry(i, buf, cap) -> i32      // writes "name\tsize\tcompressed" into buf
//!   extract(i, buf, cap) -> i32    // bytes written, or negative if it does not fit
//!   last_error(buf, cap) -> i32
//!   alloc(len) / dealloc(ptr, len)
//!
//! Nothing is ever written to disk and no path is resolved by this crate: the caller
//! decides what to do with bytes, which is what keeps an untrusted APK inert here.

use std::cell::RefCell;
use std::io::Read;
use zip::ZipArchive;

thread_local! {
    static ARCHIVE: RefCell<Option<ZipArchive<std::io::Cursor<Vec<u8>>>>> = const { RefCell::new(None) };
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(message: &str) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = message.to_string());
}

fn copy_str(text: &str, buf: *mut u8, cap: i32) -> i32 {
    if buf.is_null() || cap <= 0 { return -1 }
    let bytes = text.as_bytes();
    let n = bytes.len().min(cap as usize);
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    bytes.len() as i32
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> *mut u8 {
    if len <= 0 { return std::ptr::null_mut() }
    let mut v: Vec<u8> = Vec::with_capacity(len as usize);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: i32) {
    if ptr.is_null() || len <= 0 { return }
    unsafe { drop(Vec::from_raw_parts(ptr, len as usize, len as usize)) }
}

#[no_mangle]
pub extern "C" fn last_error(buf: *mut u8, cap: i32) -> i32 {
    LAST_ERROR.with(|slot| copy_str(&slot.borrow(), buf, cap))
}

#[no_mangle]
pub extern "C" fn open(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    // Copy rather than take ownership: the caller's buffer belongs to the JS heap and
    // it frees it itself.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
    match ZipArchive::new(std::io::Cursor::new(bytes)) {
        Ok(archive) => {
            ARCHIVE.with(|slot| *slot.borrow_mut() = Some(archive));
            0
        }
        Err(error) => {
            set_error(&format!("not a zip container: {error}"));
            -2
        }
    }
}

#[no_mangle]
pub extern "C" fn count() -> i32 {
    ARCHIVE.with(|slot| slot.borrow().as_ref().map_or(0, ZipArchive::len) as i32)
}

#[no_mangle]
pub extern "C" fn entry(index: i32, buf: *mut u8, cap: i32) -> i32 {
    if index < 0 { return -1 }
    ARCHIVE.with(|slot| match slot.borrow_mut().as_mut() {
        None => -2,
        Some(archive) => match archive.by_index(index as usize) {
            Ok(file) => copy_str(&format!("{}\t{}\t{}", file.name(), file.size(), file.compressed_size()), buf, cap),
            Err(error) => { set_error(&error.to_string()); -3 }
        },
    })
}

#[no_mangle]
pub extern "C" fn extract(index: i32, buf: *mut u8, cap: i32) -> i32 {
    if index < 0 || buf.is_null() || cap <= 0 { return -1 }
    let out = unsafe { std::slice::from_raw_parts_mut(buf, cap as usize) };
    ARCHIVE.with(|slot| match slot.borrow_mut().as_mut() {
        None => -2,
        Some(archive) => match archive.by_index(index as usize) {
            Err(error) => { set_error(&error.to_string()); -3 }
            Ok(mut file) => {
                if file.size() > cap as u64 {
                    set_error("buffer too small for this entry");
                    return -4;
                }
                // read() may return short; loop until the declared size or EOF.
                let mut written = 0usize;
                let mut result = Ok(());
                while written < cap as usize {
                    match file.read(&mut out[written..]) {
                        Ok(0) => break,
                        Ok(n) => written += n,
                        Err(error) => { result = Err(error); break }
                    }
                }
                match result {
                    Ok(()) => written as i32,
                    Err(error) => { set_error(&format!("decompress failed: {error}")); -5 }
                }
            }
        },
    })
}
