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

pub mod audio;
pub mod axml;
pub mod containers;
pub mod dex;
pub mod documents;
pub mod pe;
pub mod scan;
pub mod streams;

thread_local! {
    static ARCHIVE: RefCell<Option<ZipArchive<std::io::Cursor<Vec<u8>>>>> = const { RefCell::new(None) };
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(message: &str) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = message.to_string());
}

fn copy_str(text: &str, buf: *mut u8, cap: i32) -> i32 {
    if buf.is_null() || cap <= 0 {
        return -1;
    }
    let bytes = text.as_bytes();
    let n = bytes.len().min(cap as usize);
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    bytes.len() as i32
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> *mut u8 {
    if len <= 0 {
        return std::ptr::null_mut();
    }
    let mut v: Vec<u8> = Vec::with_capacity(len as usize);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: i32) {
    if ptr.is_null() || len <= 0 {
        return;
    }
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
    if index < 0 {
        return -1;
    }
    ARCHIVE.with(|slot| match slot.borrow_mut().as_mut() {
        None => -2,
        Some(archive) => match archive.by_index(index as usize) {
            Ok(file) => copy_str(
                &format!(
                    "{}\t{}\t{}",
                    file.name(),
                    file.size(),
                    file.compressed_size()
                ),
                buf,
                cap,
            ),
            Err(error) => {
                set_error(&error.to_string());
                -3
            }
        },
    })
}

#[no_mangle]
pub extern "C" fn extract(index: i32, buf: *mut u8, cap: i32) -> i32 {
    if index < 0 || buf.is_null() || cap <= 0 {
        return -1;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(buf, cap as usize) };
    ARCHIVE.with(|slot| match slot.borrow_mut().as_mut() {
        None => -2,
        Some(archive) => match archive.by_index(index as usize) {
            Err(error) => {
                set_error(&error.to_string());
                -3
            }
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
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                    }
                }
                match result {
                    Ok(()) => written as i32,
                    Err(error) => {
                        set_error(&format!("decompress failed: {error}"));
                        -5
                    }
                }
            }
        },
    })
}

#[no_mangle]
pub extern "C" fn parse_pe(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    pe::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

#[no_mangle]
pub extern "C" fn pe_machine() -> i32 {
    pe::machine()
}

#[no_mangle]
pub extern "C" fn pe_magic() -> i32 {
    pe::magic()
}

#[no_mangle]
pub extern "C" fn pe_entry_rva() -> i64 {
    pe::entry_rva()
}

#[no_mangle]
pub extern "C" fn pe_image_base() -> i64 {
    pe::image_base()
}

#[no_mangle]
pub extern "C" fn pe_subsystem() -> i32 {
    pe::subsystem()
}

#[no_mangle]
pub extern "C" fn pe_characteristics() -> i32 {
    pe::characteristics()
}

/// Non-zero means the file carries a COM descriptor, i.e. it is a .NET assembly.
#[no_mangle]
pub extern "C" fn pe_cli_rva() -> i64 {
    pe::cli_rva()
}

#[no_mangle]
pub extern "C" fn pe_sections(buf: *mut u8, cap: i32) -> i32 {
    copy_str(&pe::sections(), buf, cap)
}
#[no_mangle]
pub extern "C" fn parse_stream(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    streams::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// 0 none, 5 xz, 6 bzip2, 7 lz4, 8 zstd, 9 gzip.
#[no_mangle]
pub extern "C" fn stream_kind() -> i32 {
    streams::kind()
}

/// Name of the recognised stream family, so a caller labels what it found instead of keeping a copy
/// of the code table on its side.
#[no_mangle]
pub extern "C" fn stream_name(buf: *mut u8, cap: i32) -> i32 {
    copy_str(streams::name(), buf, cap)
}

#[no_mangle]
pub extern "C" fn stream_field_count() -> i32 {
    streams::count()
}

#[no_mangle]
pub extern "C" fn stream_field(index: i32, buf: *mut u8, cap: i32) -> i32 {
    match streams::field(index) {
        Some(text) => copy_str(&text, buf, cap),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn parse_container(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    containers::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// Which container was recognised: 0 none, 1 tar, 2 ar, 3 RIFF, 4 TIFF, 10 ISO base media,
/// 11 EBML (Matroska/WebM), 16 PDF with a classic cross-reference table, 19 Netpbm, 20 ASF,
/// 21 FLV, 22 CAB (file table only), 23 Debian package, 25 MPEG transport stream, 26 WebAssembly,
/// 27 sfnt font, 28 WOFF, 30 Apple icon directory, 31 Apple binary property list.
#[no_mangle]
pub extern "C" fn container_kind() -> i32 {
    containers::kind()
}

/// The container family this reader settled on, for a caller that has to label it.
#[no_mangle]
pub extern "C" fn container_name(buf: *mut u8, cap: i32) -> i32 {
    copy_str(containers::name(), buf, cap)
}

#[no_mangle]
pub extern "C" fn container_count() -> i32 {
    containers::count()
}

/// One entry: tar "name	size	typeflag", ar "name	size	mode",
/// RIFF "form	FORM	declared" then "ID	size	offset", TIFF "ifdN	tag	type	count".
#[no_mangle]
pub extern "C" fn container_entry(index: i32, buf: *mut u8, cap: i32) -> i32 {
    match containers::at(index) {
        Some(text) => copy_str(&text, buf, cap),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn parse_dex(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    dex::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

#[no_mangle]
pub extern "C" fn dex_version(buf: *mut u8, cap: i32) -> i32 {
    copy_str(&dex::version(), buf, cap)
}

#[no_mangle]
pub extern "C" fn dex_checksum() -> i64 {
    dex::checksum()
}
#[no_mangle]
pub extern "C" fn dex_file_size() -> i64 {
    dex::file_size()
}
#[no_mangle]
pub extern "C" fn dex_header_size() -> i64 {
    dex::header_size()
}
#[no_mangle]
pub extern "C" fn dex_map_off() -> i64 {
    dex::map_off()
}
#[no_mangle]
pub extern "C" fn dex_string_ids() -> i64 {
    dex::string_ids()
}
#[no_mangle]
pub extern "C" fn dex_type_ids() -> i64 {
    dex::type_ids()
}
#[no_mangle]
pub extern "C" fn dex_method_ids() -> i64 {
    dex::method_ids()
}
#[no_mangle]
pub extern "C" fn dex_class_defs() -> i64 {
    dex::class_defs()
}

#[no_mangle]
pub extern "C" fn parse_axml(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    axml::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

#[no_mangle]
pub extern "C" fn axml_count() -> i32 {
    axml::count()
}

#[no_mangle]
pub extern "C" fn axml_declared() -> i32 {
    axml::declared()
}

#[no_mangle]
pub extern "C" fn axml_flags() -> i64 {
    axml::flags()
}

/// One string from the pool. Returns the byte length written, or -1 if the index is out of range,
/// so a caller that stops at the first negative value cannot read past the pool.
#[no_mangle]
pub extern "C" fn axml_string(index: i32, buf: *mut u8, cap: i32) -> i32 {
    match axml::at(index) {
        Some(text) => copy_str(&text, buf, cap),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn parse_audio(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    audio::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// Which audio header was recognised: 0 none, 12 FLAC, 13 MPEG audio (Layer III), 14 Ogg,
/// 15 WAVE, 24 MPEG audio (Layer II).
#[no_mangle]
pub extern "C" fn audio_kind() -> i32 {
    audio::kind()
}

/// The audio family this reader settled on, for a caller that has to label it.
#[no_mangle]
pub extern "C" fn audio_name(buf: *mut u8, cap: i32) -> i32 {
    copy_str(audio::name(), buf, cap)
}

#[no_mangle]
pub extern "C" fn audio_count() -> i32 {
    audio::count()
}

/// One `name<TAB>value` field, or a walk row (`block`, `bitrate`, `chunk`). -1 past the end.
#[no_mangle]
pub extern "C" fn audio_field(index: i32, buf: *mut u8, cap: i32) -> i32 {
    match audio::at(index) {
        Some(text) => copy_str(&text, buf, cap),
        None => -1,
    }
}

/// Office document packages (OOXML, OpenDocument, EPUB): 0 none, 1 docx, 2 xlsx, 3 pptx,
/// 4 odt, 5 ods, 6 odp, 7 epub; -1 not a zip, -2 a zip that is not one of these packages.
#[no_mangle]
pub extern "C" fn parse_document(ptr: *const u8, len: i32) -> i32 {
    if ptr.is_null() || len <= 0 {
        set_error("empty input");
        return -1;
    }
    documents::parse(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

#[no_mangle]
pub extern "C" fn document_kind() -> i32 {
    documents::kind()
}

/// The document package family this reader settled on, for a caller that has to label it.
#[no_mangle]
pub extern "C" fn document_name(buf: *mut u8, cap: i32) -> i32 {
    copy_str(documents::name(), buf, cap)
}

#[no_mangle]
pub extern "C" fn document_count() -> i32 {
    documents::count()
}

/// One `name<TAB>value` row: document, then main_part, mimetype or rootfile, plus entries,
/// archive_bytes and has_manifest.
#[no_mangle]
pub extern "C" fn document_field(index: i32, buf: *mut u8, cap: i32) -> i32 {
    match documents::at(index) {
        Some(text) => copy_str(&text, buf, cap),
        None => -1,
    }
}
