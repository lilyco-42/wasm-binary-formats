//! 3MF model packages: the mesh counts of a file `trimesh` wrote, and of two that only the questions
//! `trimesh` cannot answer are worth.
//!
//! `test/fixtures/lab.3mf` is `trimesh`'s own export of a box it built - 8 vertices, 12 faces - and the
//! same library re-reads it from disk to say so again; `scripts/make-3mf-fixtures.py` refuses to write
//! the probe unless its reload, `xml.etree.ElementTree`'s walk of the model part and the rows below all
//! give the same two numbers. The archive framing is `zipfile`'s.
//!
//! `hand.3mf` is authored here and packaged by `zipfile`, because trimesh always writes a unit, always
//! names its object, and always covers the part by `Default` extension rather than by `Override`
//! part-name. The three absences and that other spelling are what it is for. `loose.3mf` points its
//! model relationship at a part that is not in the archive, which is a refusal and is asserted as one.

use apk_lens::documents::{at, count, name, parse, DOC_3MF};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-3mf-fixtures.py: {error}")
    })
}

fn rows(file: &str) -> Vec<String> {
    let code = parse(&fixture(file));
    assert_eq!(code, DOC_3MF, "{file} is not read as a model package");
    assert_eq!(name(), "3mf", "the package name moved");
    (0..count()).filter_map(|index| at(index)).collect()
}

/// The rows `xml.etree.ElementTree` and `zipfile` produced in the probe, asserted whole: the counts in a
/// mesh are the two numbers a 3MF is about, and the leading slash in `rels` is the join this reader has
/// to make correctly to find the part at all.
#[test]
fn a_mesh_package_written_by_trimesh_reads_back_as_the_mesh_it_holds() {
    assert_eq!(
        rows("lab.3mf"),
        vec![
            "document\t3mf\t2004",
            "main_part\t3D/3dmodel.model",
            "entries\t3",
            "archive_bytes\t1283",
            "has_manifest\t1",
            "rels\tspelled\t/3D/3dmodel.model\tpart\t3D/3dmodel.model\tid\trel0",
            "manifest\tkind\tDefault\tpartname\t-\textension\tmodel\ttype\tapplication/vnd.ms-package.3dmanufacturing-3dmodel+xml",
            "model\tunit\tmillimeter\tobjects\t1\tvertices\t8\ttriangles\t12\tbuild\t1\tmetadata\t0",
            "object\tid\t1\tname\tgeometry_0\ttype\tmodel\tvertices\t8\ttriangles\t12",
        ],
        "one object, eight vertices, twelve triangles, as trimesh and ElementTree both counted them"
    );
}

/// Two objects, one of them a support, and neither carrying a name; a model with no `unit` attribute at
/// all; a manifest that covers the part by `Override`; a relationship target spelled without the leading
/// slash; and two build items listing the objects in the other order from the one they are declared in.
/// The per-object counts have to add up to the model's, which is the assertion that catches a walk that
/// counted one subtree twice or skipped a level.
#[test]
fn an_absent_attribute_is_printed_as_absent_rather_than_as_the_default_the_spec_would_fill_in() {
    let listed = rows("hand.3mf");
    assert_eq!(
        listed,
        vec![
            "document\t3mf\t756",
            "main_part\t3D/3dmodel.model",
            "entries\t3",
            "archive_bytes\t1699",
            "has_manifest\t1",
            "rels\tspelled\t3D/3dmodel.model\tpart\t3D/3dmodel.model\tid\trel0",
            "manifest\tkind\tOverride\tpartname\t/3D/3dmodel.model\textension\t-\ttype\tapplication/vnd.ms-package.3dmanufacturing-3dmodel+xml",
            "model\tunit\t-\tobjects\t2\tvertices\t5\ttriangles\t3\tbuild\t2\tmetadata\t1",
            "object\tid\t2\tname\t-\ttype\tsupport\tvertices\t2\ttriangles\t1",
            "object\tid\t3\tname\t-\ttype\t-\tvertices\t3\ttriangles\t2",
        ],
        "no unit, no names, one object with no type, and counts that add up"
    );
    let total = |column: &str| -> i64 {
        listed
            .iter()
            .filter(|row| row.starts_with("object\t"))
            .map(|row| {
                let cell = row.split('\t').collect::<Vec<_>>();
                cell[cell.iter().position(|one| *one == column).unwrap() + 1]
                    .parse::<i64>()
                    .unwrap()
            })
            .sum()
    };
    assert_eq!(total("vertices"), 5, "the per-object vertex counts drifted");
    assert_eq!(total("triangles"), 3, "the per-object triangle counts drifted");
}

/// A package whose own pointer names a part that is not there is refused, and the refusal says which
/// pointer it followed. The archive reads, the manifest is there and the model part is in the file under
/// a *different* name - so a reader that looked for `3D/3dmodel.model` by habit would accept this and
/// report a mesh the package never pointed at.
#[test]
fn a_model_relationship_pointing_at_nothing_refuses_the_package_and_says_which_pointer() {
    assert_eq!(parse(&fixture("loose.3mf")), -2, "a dangling pointer is not a mesh");
    assert_eq!(count(), 0, "nothing is listed once the package is refused");
    let mut buf = [0u8; 256];
    let written = apk_lens::last_error(buf.as_mut_ptr(), buf.len() as i32);
    assert!(written > 0, "a refusal leaves no reason behind");
    let why = String::from_utf8_lossy(&buf[..written as usize]).to_string();
    assert!(
        why.contains("3D/gone.model"),
        "the refusal should name the part the pointer asked for: {why}"
    );
}

/// The document codes are a contract with the page: 9 is a model package, and a zip that is none of
/// these families is still -2 rather than a new number.
#[test]
fn a_model_package_is_code_nine_and_a_plain_zip_is_still_not_a_package() {
    assert_eq!(DOC_3MF, 9, "the code the page asks about moved");
    assert_eq!(parse(&fixture("tiny.ttf")), -1, "a file that is not a zip at all");
    assert_eq!(name(), "unknown", "a refusal leaves no family name");
}
