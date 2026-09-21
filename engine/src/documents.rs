//! Office document packages: OOXML (.docx/.dotx/.xlsx/.pptx), OpenDocument (.odt/.ods/.odp), EPUB,
//! and 3MF - a mesh package that borrows OOXML's zip-and-XML framing.
//!
//! All of them are zip archives with a mandated set of parts, so this is a *package* reader: it opens
//! the archive, reads the handful of entries that decide what the file is, and reports the shape. For
//! the document families it does not parse the XML inside, which is why the level recorded for those
//! formats in `tools/coverage.mjs` is `container` and never `fields` - identifying a document is not
//! understanding it, and the distinction is the whole reason the coverage matrix has levels.
//!
//! 3MF is the exception, and the exception is allowed because the mesh part *is* the format: a 3MF is
//! its `3D/3dmodel.model`, so the unit the file states and the objects and counts it carries are that
//! package's header fields rather than its payload. The walk is `containers::xml_document`, the same
//! one the GPS-log label uses, and `scripts/make-3mf-fixtures.py` predicts every row from
//! `xml.etree.ElementTree`'s own reading of the same bytes before the probe is written.
//!
//! The classification is ordered, because two families use the same `mimetype` filename:
//!   1. `mimetype` present -> EPUB when it says `application/epub+zip`, ODF when it starts with
//!      `application/vnd.oasis.opendocument.` (the suffix is the kind). A mimetype saying anything
//!      else is refused: guessing from the other entries would be exactly the kind of over-claim
//!      the levels exist to prevent.
//!   2. `[Content_Types].xml` plus a `_rels/.rels` relationship of type `…/3dmodel` -> 3MF, and the part
//!      that relationship names has to be in the archive. A pointer at a part that is not there refuses
//!      the package with that said out loud, rather than falling through to another family's answer.
//!   3. `[Content_Types].xml` plus a `word/`, `xl/` or `ppt/` part -> the matching OOXML type. The part
//!      prefix decides the family, because those content-type lists are permissive; within `word/` the
//!      manifest's own declaration for the main part splits a document from a template, the two
//!      packages being otherwise identical and neither storing its extension.
//!   4. anything else -> not a document package, even though it is a zip.
//!
//! The zip reading itself is the one part that can fail for reasons that are not our bug, so a
//! malformed archive is reported as "not a document package" along with the reason.

use std::cell::RefCell;
use std::io::Read;
use zip::ZipArchive;

use crate::containers::{xml_document, Node};

pub const DOC_DOCX: i32 = 1;
pub const DOC_XLSX: i32 = 2;
pub const DOC_PPTX: i32 = 3;
pub const DOC_ODT: i32 = 4;
pub const DOC_ODS: i32 = 5;
pub const DOC_ODP: i32 = 6;
pub const DOC_EPUB: i32 = 7;
/// A Word *template*: the same package as a .docx - same parts, same manifest - and one string away from
/// being one, which is why it is a separate code rather than an extension the reader cannot see.
pub const DOC_DOTX: i32 = 8;
/// A 3D model package: OPC framing like OOXML, and a mesh part whose own fields are the format.
pub const DOC_3MF: i32 = 9;

/// The relationship type that makes a package a model package. The part it points at is named by the
/// relationship, not by a prefix, so this is the one family found by following a pointer.
const MODEL_REL_TYPE: &str = "http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel";
const RELS_PART: &str = "_rels/.rels";
const TYPES_PART: &str = "[Content_Types].xml";
/// At most one object per row and eight rows: a package can carry thousands of them, and the model row
/// says how many there are, so the list is a sample and the cut row says so.
const MAX_OBJECTS_LISTED: usize = 8;
/// A part taken in full or not at all. The XML walk stops at 4 096 elements whatever the size, so this
/// only keeps a pathological member from being decompressed to report on nothing.
const MAX_PART_BYTES: u64 = 4 * 1024 * 1024;

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

/// The package name beside the code: docx, xlsx, pptx, dotx, odt, ods, odp, epub or 3mf.
pub fn name() -> &'static str {
    name_of(kind())
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
        DOC_DOTX => "dotx",
        DOC_3MF => "3mf",
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

/// A whole part, refused rather than truncated: XML cut in half is not the file's tree, and a walk over
/// the first 64 KiB of a manifest would print an answer the rest of the part contradicts.
fn slurp_whole(archive: &mut Archive, name: &str) -> Option<Vec<u8>> {
    let mut file = archive.by_name(name).ok()?;
    if file.size() > MAX_PART_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some(buf)
}

/// The value of the first `attribute="value"` for `attribute` in a document, without an XML parser:
/// EPUB's `rootfile` pointer is one attribute, and reading it by hand keeps this module honest about
/// how much it actually understands.
fn attribute(text: &str, key: &str) -> Option<String> {
    let head = text.find(&format!("{key}=\""))? + key.len() + 2;
    let tail = text[head..].find('"')?;
    Some(text[head..head + tail].to_string())
}

/// `-` where an attribute is absent. A 3MF model defaults its unit to millimetres and an object defaults
/// its type to `model`; this row set prints the file's own spelling and leaves the default to the
/// loader, because filling it in would print a value the file never carried.
fn spelled(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

/// The part a package's own relationship points at. A leading `/` in an OPC target is the package root,
/// so `/3D/3dmodel.model` and `3D/3dmodel.model` name one part - and both spellings are kept, because
/// the join made here is the kind of thing a reader should be able to be shown rather than trusted.
fn model_pointer(rels: &[u8]) -> Option<(String, String, String)> {
    let root = xml_document(rels)?;
    if root.name != "Relationships" {
        return None;
    }
    root.kids.iter().find_map(|one| {
        if one.name != "Relationship" || one.attr("Type") != Some(MODEL_REL_TYPE) {
            return None;
        }
        let target = one.attr("Target")?;
        Some((
            target.to_owned(),
            target.trim_start_matches('/').to_owned(),
            spelled(one.attr("Id")).to_owned(),
        ))
    })
}

/// Which entry of `[Content_Types].xml` covers the part, and by which of the two spellings OPC allows:
/// an `Override` names the part, a `Default` names its extension.
fn content_type(types: &Node, part: &str) -> (String, String, String, String) {
    for one in types.kids.iter().filter(|one| one.name == "Override") {
        if one.attr("PartName").unwrap_or("").trim_start_matches('/') == part {
            return (
                "Override".to_owned(),
                spelled(one.attr("PartName")).to_owned(),
                "-".to_owned(),
                spelled(one.attr("ContentType")).to_owned(),
            );
        }
    }
    let extension = part.rsplit('.').next().unwrap_or(part).to_ascii_lowercase();
    for one in types.kids.iter().filter(|one| one.name == "Default") {
        if one.attr("Extension").unwrap_or("").to_ascii_lowercase() == extension {
            return (
                "Default".to_owned(),
                "-".to_owned(),
                spelled(one.attr("Extension")).to_owned(),
                spelled(one.attr("ContentType")).to_owned(),
            );
        }
    }
    ("none".to_owned(), "-".to_owned(), "-".to_owned(), "-".to_owned())
}

/// The model part as the document it is: the unit the file states, how many objects it carries, and for
/// each of them the vertex and triangle counts of its own subtree. The counts are `under`, not `held`,
/// because a mesh keeps its points two levels down: `resources > object > mesh > vertices > vertex`.
fn model_rows(model: &Node) -> Vec<String> {
    let objects: Vec<&Node> = model
        .kids
        .iter()
        .filter(|one| one.name == "resources")
        .flat_map(|group| group.kids.iter().filter(|one| one.name == "object"))
        .collect();
    let build = model
        .kids
        .iter()
        .filter(|one| one.name == "build")
        .map(|group| group.held("item"))
        .sum::<usize>();
    let mut out = vec![format!(
        "model\tunit\t{}\tobjects\t{}\tvertices\t{}\ttriangles\t{}\tbuild\t{}\tmetadata\t{}",
        spelled(model.attr("unit")),
        objects.len(),
        model.under("vertex"),
        model.under("triangle"),
        build,
        model.held("metadata"),
    )];
    let listed = objects.len().min(MAX_OBJECTS_LISTED);
    for object in objects.iter().take(listed) {
        out.push(format!(
            "object\tid\t{}\tname\t{}\ttype\t{}\tvertices\t{}\ttriangles\t{}",
            spelled(object.attr("id")),
            spelled(object.attr("name")),
            spelled(object.attr("type")),
            object.under("vertex"),
            object.under("triangle"),
        ));
    }
    if objects.len() > listed {
        out.push(format!("cut\tobjects\t{}\tlisted\t{listed}", objects.len()));
    }
    out
}

/// The rows past the five every package prints, and the part whose size goes in the first of those.
/// `reason` is filled when the archive looked like a model package and was refused for a said reason.
fn classify(
    archive: &mut Archive,
    names: &[String],
    reason: &mut Option<String>,
) -> Option<(i32, Vec<String>, Option<String>)> {
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
            return Some((
                DOC_EPUB,
                vec![format!("rootfile\t{rootfile}")],
                Some(rootfile),
            ));
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
        return Some((code, vec![format!("mimetype\t{declared}")], main));
    }
    if !names.iter().any(|name| name == TYPES_PART) {
        return None;
    }
    if names.iter().any(|name| name == RELS_PART) {
        let pointer = slurp_whole(archive, RELS_PART).and_then(|rels| model_pointer(&rels));
        if let Some((spelled_target, part, id)) = pointer {
            if !names.iter().any(|name| name == &part) {
                *reason = Some(format!(
                    "the package's model relationship names {part} and the archive holds no such part"
                ));
                return None;
            }
            let types = xml_document(&slurp_whole(archive, TYPES_PART)?)?;
            let model = xml_document(&slurp_whole(archive, &part)?)?;
            if model.name != "model" {
                *reason = Some(format!("{part} is not a 3MF model: its root is <{}>", model.name));
                return None;
            }
            let manifest = content_type(&types, &part);
            let mut extra = vec![
                format!("main_part\t{part}"),
                format!("rels\tspelled\t{spelled_target}\tpart\t{part}\tid\t{id}"),
                format!(
                    "manifest\tkind\t{}\tpartname\t{}\textension\t{}\ttype\t{}",
                    manifest.0, manifest.1, manifest.2, manifest.3
                ),
            ];
            extra.extend(model_rows(&model));
            return Some((DOC_3MF, extra, Some(part)));
        }
    }
    let part = ["word/", "xl/", "ppt/"]
        .into_iter()
        .find_map(|prefix| names.iter().find(|name| name.starts_with(prefix)))
        .cloned()?;
    if part.starts_with("xl/") {
        return Some((DOC_XLSX, vec![format!("main_part\t{part}")], Some(part)));
    }
    if part.starts_with("ppt/") {
        return Some((DOC_PPTX, vec![format!("main_part\t{part}")], Some(part)));
    }
    // A .docx and a .dotx hold the same parts, so the package has to be asked a second question: what
    // content type does the manifest give the main document part? The template says
    // `wordprocessingml.template.main+xml` and the document says `document.main+xml`, and that string is
    // the whole difference the format itself states - the extension is not in the file. Substring rather
    // than XML parse because the manifest is ASCII by specification and the answer wanted is one word.
    // A manifest that cannot be read leaves the weaker, older answer rather than failing the package.
    let manifest = slurp(archive, TYPES_PART).unwrap_or_default();
    let template = manifest.contains("wordprocessingml.template.main+xml");
    let code = if template { DOC_DOTX } else { DOC_DOCX };
    let stated = if template {
        "\tcontent\twordprocessingml.template.main+xml"
    } else {
        ""
    };
    Some((
        code,
        vec![format!("main_part\t{part}{stated}")],
        Some(part),
    ))
}

/// -1 not a readable zip, -2 a zip that is none of these packages, otherwise the DOC_* code.
pub fn parse(bytes: &[u8]) -> i32 {
    let Ok(mut archive) = ZipArchive::new(std::io::Cursor::new(bytes.to_vec())) else {
        return reject("not a readable zip container", -1);
    };
    let names: Vec<String> = archive.file_names().map(|name| name.to_string()).collect();
    let entries = names.len();
    let mut reason = None;
    let Some((code, extra, main)) = classify(&mut archive, &names, &mut reason) else {
        let generic = "a zip, but not an OOXML, OpenDocument, EPUB or 3MF package";
        return reject(reason.as_deref().unwrap_or(generic), -2);
    };
    let main_size = main
        .as_deref()
        .and_then(|name| archive.by_name(name).ok())
        .map_or(0, |entry| entry.size().min(i64::MAX as u64) as i64);
    let has_manifest = i64::from(
        names.iter().any(|name| name == TYPES_PART)
            || names.iter().any(|name| name == "META-INF/manifest.xml")
            || names.iter().any(|name| name == "META-INF/container.xml"),
    );
    let mut lines = vec![
        format!("document\t{}\t{main_size}", name_of(code)),
        extra[0].clone(),
        format!("entries\t{entries}"),
        format!("archive_bytes\t{}", bytes.len()),
        format!("has_manifest\t{has_manifest}"),
    ];
    lines.extend(extra.into_iter().skip(1));
    KIND.with(|slot| *slot.borrow_mut() = code);
    RESULT.with(|slot| *slot.borrow_mut() = lines);
    code
}
