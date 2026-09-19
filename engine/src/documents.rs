//! Office document packages: OOXML (.docx/.xlsx/.pptx), OpenDocument (.odt/.ods/.odp) and EPUB.
//!
//! All three are zip archives with a mandated set of parts, so this is a *package* reader: it opens
//! the archive, reads the handful of entries that decide what the file is, and reports the shape.
//! It does not parse the XML inside, which is why the level recorded for these formats in
//! `tools/coverage.mjs` is `container` and never `fields` - identifying a document is not
//! understanding it, and the distinction is the whole reason the coverage matrix has levels.
//!
//! The classification is ordered, because two families use the same `mimetype` filename:
//!   1. `mimetype` present -> EPUB when it says `application/epub+zip`, ODF when it starts with
//!      `application/vnd.oasis.opendocument.` (the suffix is the kind). A mimetype saying anything
//!      else is refused: guessing from the other entries would be exactly the kind of over-claim
//!      the levels exist to prevent.
//!   2. `[Content_Types].xml` plus a `word/`, `xl/` or `ppt/` part -> the matching OOXML type. The
//!      part prefix decides, not the content types, because those lists are permissive.
//!   3. anything else -> not a document package, even though it is a zip.
//!
//! The zip reading itself is the one part that can fail for reasons that are not our bug, so a
//! malformed archive is reported as "not a document package" along with the reason.

use std::cell::RefCell;
use std::io::Read;
use zip::ZipArchive;

pub const DOC_DOCX: i32 = 1;
pub const DOC_XLSX: i32 = 2;
pub const DOC_PPTX: i32 = 3;
pub const DOC_ODT: i32 = 4;
pub const DOC_ODS: i32 = 5;
pub const DOC_ODP: i32 = 6;
pub const DOC_EPUB: i32 = 7;

thread_local! {
    static RESULT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static KIND: RefCell<i32> = const { RefCell::new(0) };
}

fn reject(message: &str, code: i32) -> i32 {
    crate::set_error(message);
    KIND.with(|slot| *slot.borrow_mut() = 0);
    RESULT.with(|slot| slot.borrow_mut().clear());
    code
}

pub fn kind() -> i32 {
    KIND.with(|slot| *slot.borrow())
}

pub fn count() -> i32 {
    RESULT.with(|slot| slot.borrow().len() as i32)
}

pub fn at(index: i32) -> Option<String> {
    RESULT.with(|slot| slot.borrow().get(index.max(0) as usize).cloned())
}

fn name_of(code: i32) -> &'static str {
    match code {
        DOC_DOCX => "docx",
        DOC_XLSX => "xlsx",
        DOC_PPTX => "pptx",
        DOC_ODT => "odt",
        DOC_ODS => "ods",
        DOC_ODP => "odp",
        DOC_EPUB => "epub",
        _ => "unknown",
    }
}

type Archive = ZipArchive<std::io::Cursor<Vec<u8>>>;

/// At most 64 KiB of one part. The parts read here are ASCII by specification.
fn slurp(archive: &mut Archive, name: &str) -> Option<String> {
    let mut file = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    if file.by_ref().take(65_536).read_to_end(&mut buf).is_err() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The value of the first `attribute="value"` for `attribute` in a document, without an XML parser:
/// EPUB's `rootfile` pointer is one attribute, and reading it by hand keeps this module honest about
/// how much it actually understands.
fn attribute(text: &str, key: &str) -> Option<String> {
    let head = text.find(&format!("{key}=\""))? + key.len() + 2;
    let tail = text[head..].find('"')?;
    Some(text[head..head + tail].to_string())
}

fn classify(archive: &mut Archive, names: &[String]) -> Option<(i32, String, Option<String>)> {
    if names.iter().any(|name| name == "mimetype") {
        let declared = slurp(archive, "mimetype")?
            .trim_end_matches(['\n', '\r', '\0'])
            .to_string();
        if declared == "application/epub+zip" {
            let container = slurp(archive, "META-INF/container.xml")?;
            let rootfile = attribute(&container, "full-path")?;
            if !names.iter().any(|name| name == &rootfile) {
                return None;
            }
            return Some((DOC_EPUB, format!("rootfile\t{rootfile}"), Some(rootfile)));
        }
        let suffix = declared.strip_prefix("application/vnd.oasis.opendocument.")?;
        let code = match suffix {
            "text" => DOC_ODT,
            "spreadsheet" => DOC_ODS,
            "presentation" => DOC_ODP,
            _ => return None,
        };
        let main = if names.iter().any(|name| name == "content.xml") {
            Some("content.xml".to_string())
        } else {
            None
        };
        return Some((code, format!("mimetype\t{declared}"), main));
    }
    if !names.iter().any(|name| name == "[Content_Types].xml") {
        return None;
    }
    let part = ["word/", "xl/", "ppt/"]
        .into_iter()
        .find_map(|prefix| names.iter().find(|name| name.starts_with(prefix)))
        .cloned()?;
    let code = if part.starts_with("word/") {
        DOC_DOCX
    } else if part.starts_with("xl/") {
        DOC_XLSX
    } else {
        DOC_PPTX
    };
    Some((code, format!("main_part\t{part}"), Some(part)))
}

/// -1 not a readable zip, -2 a zip that is none of these packages, otherwise the DOC_* code.
pub fn parse(bytes: &[u8]) -> i32 {
    let Ok(mut archive) = ZipArchive::new(std::io::Cursor::new(bytes.to_vec())) else {
        return reject("not a readable zip container", -1);
    };
    let names: Vec<String> = archive.file_names().map(|name| name.to_string()).collect();
    let entries = names.len();
    let Some((code, detail, main)) = classify(&mut archive, &names) else {
        return reject("a zip, but not an OOXML, OpenDocument or EPUB package", -2);
    };
    let main_size = main
        .as_deref()
        .and_then(|name| archive.by_name(name).ok())
        .map_or(0, |entry| entry.size().min(i64::MAX as u64) as i64);
    let has_manifest = i64::from(
        names.iter().any(|name| name == "[Content_Types].xml")
            || names.iter().any(|name| name == "META-INF/manifest.xml")
            || names.iter().any(|name| name == "META-INF/container.xml"),
    );
    let lines = vec![
        format!("document\t{}\t{main_size}", name_of(code)),
        detail,
        format!("entries\t{entries}"),
        format!("archive_bytes\t{}", bytes.len()),
        format!("has_manifest\t{has_manifest}"),
    ];
    KIND.with(|slot| *slot.borrow_mut() = code);
    RESULT.with(|slot| *slot.borrow_mut() = lines);
    code
}
