//! `lab.xsd`, `hand.xsd`, `part.xsd`, `broken.xsd` and `many.xsd`: an XML Schema, read as the tree
//! of declarations it is.
//!
//! A schema has no magic. What makes one is a single binding - the root element is called `schema`
//! and it declares itself to be in `http://www.w3.org/2001/XMLSchema` - so that is the whole
//! acceptance rule, and `scripts/make-xsd-fixtures.py` writes a probe only after three readers that
//! nobody in this chain wrote have answered about the same bytes:
//!
//!   * `xml.etree.ElementTree` walks the tree and supplies every row below (the same walk, twice);
//!   * `xmlschema` (MIT) *compiles* the schema, and its component maps for global elements,
//!     attributes, types, groups and notations are compared name by name against the tree;
//!   * Xerces, through the JDK's `javax.xml.validation.SchemaFactory`, compiles it a second time and
//!     reports what its error handler collected.
//!
//! Four of the five files compile cleanly under both compilers. `broken.xsd` does not: it references
//! two types it never declares, Xerces says `src-resolve` twice and xmlschema says `missing base
//! type`, and this reader still lists its two components. That is the claim being made here -
//! identification is structural, and a schema whose derivation is wrong is still a schema.
//!
//! What is not claimed. The rows say what the file spells, not what it means: a `type` cell is the
//! QName as written (`tns:Item`), and resolving it needs the prefix bindings of the whole document
//! plus any file the `import` points at, which this reader does not load. XSD 1.0 and 1.1 share a
//! namespace URI, so nothing here says which version a file is.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_GPX, FORMAT_XSD};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-xsd-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_XSD, "the file has to be accepted first");
    assert_eq!(kind(), FORMAT_XSD, "kind() must agree with the return code");
    assert_eq!(name(), "xsd");
    report()
}

/// The schema every reader accepted: one of each of the seven global kinds, an import with no
/// location, a note whose sentence sits one level down in `documentation`, and two elements - one
/// pointing at a type by prefix, one carrying an anonymous complex type of its own.
#[test]
fn a_schema_lists_the_components_its_own_document_order_gives() {
    assert_eq!(
        read(&fixture("lab.xsd")),
        vec![
            "schema\tpieces\t10\telements\t2\tattributes\t1\tcomplexTypes\t1\tsimpleTypes\t1\tgroups\t1\tattributeGroups\t1\timports\t1\tincludes\t0\tnotations\t1\tannotations\t1\tunknown\t0\tnodes\t30\ttarget\thttp://lab.example.invalid/fixture\teform\tqualified\taform\tunqualified\tbytes\t1781",
            "import\t0\tnamespace\thttp://www.w3.org/XML/1998/namespace\tloc\t-",
            "doc\t1\tchars\t31\ttext\ta fixture schema & nothing else",
            "comp\t2\tkind\tsimpleType\tname\tCode\tbase\txs:token\tfacets\t1",
            "comp\t3\tkind\tcomplexType\tname\tItem\tmixed\t-\tderives\t-\tparticles\t1\tattributes\t1",
            "comp\t4\tkind\tgroup\tname\tParts\tparticles\t1",
            "comp\t5\tkind\tattributeGroup\tname\tCommon\tattributes\t1",
            "comp\t6\tkind\tattribute\tname\treviewed\ttype\txs:boolean\tuse\t-",
            "comp\t7\tkind\tnotation\tname\tJPEG\tpublic\timage/jpeg\tsystem\tviewer",
            "comp\t8\tkind\telement\tname\tline\tref\t-\ttype\ttns:Item\tnested\t-",
            "comp\t9\tkind\telement\tname\torder\tref\t-\ttype\t-\tnested\tcomplexType",
        ],
        "the rows are the three readers' answer about this file"
    );
}

/// `hand.xsd` is the other spelling of the same document: the schema namespace bound as the *default*,
/// so its children carry no prefix at all, and no target namespace, so `target` says `-` rather than
/// inventing the empty string. Its `include` is resolved by both compilers, which is why the file
/// beside it is in this directory: `part.xsd`'s two elements are globals of this schema too, and that
/// is what the probe records about the merged maps.
#[test]
fn the_default_namespace_is_a_namespace_too() {
    assert_eq!(
        read(&fixture("hand.xsd")),
        vec![
            "schema\tpieces\t8\telements\t1\tattributes\t1\tcomplexTypes\t1\tsimpleTypes\t3\tgroups\t0\tattributeGroups\t0\timports\t0\tincludes\t1\tnotations\t0\tannotations\t1\tunknown\t0\tnodes\t18\ttarget\t-\teform\t-\taform\t-\tbytes\t905",
            "doc\t0\tchars\t56\ttext\tno target namespace, and a default namespace on the root",
            "include\t1\tloc\tpart.xsd",
            "comp\t2\tkind\tsimpleType\tname\tAmount\tbase\txs:decimal\tfacets\t2",
            "comp\t3\tkind\tsimpleType\tname\tTags\tbase\txs:string\tfacets\t0",
            "comp\t4\tkind\tsimpleType\tname\tKind\tbase\t-\tfacets\t0",
            "comp\t5\tkind\tcomplexType\tname\tMoney\tmixed\ttrue\tderives\t-\tparticles\t1\tattributes\t1",
            "comp\t6\tkind\telement\tname\tamount\tref\t-\ttype\txs:decimal\tnested\t-",
            "comp\t7\tkind\tattribute\tname\tstamp\ttype\txs:dateTime\tuse\t-",
        ]
    );
    // The included file on its own: three elements, no annotation, nothing to inherit.
    assert_eq!(
        read(&fixture("part.xsd")),
        vec![
            "schema\tpieces\t2\telements\t2\tattributes\t0\tcomplexTypes\t0\tsimpleTypes\t0\tgroups\t0\tattributeGroups\t0\timports\t0\tincludes\t0\tnotations\t0\tannotations\t0\tunknown\t0\tnodes\t3\ttarget\t-\teform\t-\taform\t-\tbytes\t181",
            "comp\t0\tkind\telement\tname\twho\tref\t-\ttype\txs:string\tnested\t-",
            "comp\t1\tkind\telement\tname\twhere\tref\t-\ttype\txs:string\tnested\t-",
        ]
    );
    // A restriction counts its facets, a list takes its item type as the base and has none, a union
    // has neither - and `mixed` is the file's own word, present on Money and absent on Item.
}

/// Both compilers refuse this one, and the reader still answers: `thing` points at a type that is not
/// declared, and `Other` extends a base that is not declared either. The second row is also what
/// "direct children only" means in practice - the particles of a type whose content sits inside
/// `complexContent > extension > sequence` count zero here, because the row counts this element's own
/// children and not the subtree the derivation buries them in.
#[test]
fn a_schema_both_compilers_refuse_is_still_a_schema() {
    assert_eq!(
        read(&fixture("broken.xsd")),
        vec![
            "schema\tpieces\t2\telements\t1\tattributes\t0\tcomplexTypes\t1\tsimpleTypes\t0\tgroups\t0\tattributeGroups\t0\timports\t0\tincludes\t0\tnotations\t0\tannotations\t0\tunknown\t0\tnodes\t7\ttarget\thttp://lab.example.invalid/broken\teform\t-\taform\t-\tbytes\t512",
            "comp\t0\tkind\telement\tname\tthing\tref\t-\ttype\tt:Missing\tnested\t-",
            "comp\t1\tkind\tcomplexType\tname\tOther\tmixed\t-\tderives\tcomplexContent\tparticles\t0\tattributes\t0",
        ]
    );
}

/// Seventy globals, listed to the cap and then stopped at, with the file's own totals kept above.
#[test]
fn a_schema_with_more_components_than_the_panel_lists_says_so() {
    let rows = read(&fixture("many.xsd"));
    assert_eq!(rows.len(), 66, "64 components, the totals and the stop");
    assert_eq!(
        rows[0],
        "schema\tpieces\t70\telements\t70\tattributes\t0\tcomplexTypes\t0\tsimpleTypes\t0\tgroups\t0\tattributeGroups\t0\timports\t0\tincludes\t0\tnotations\t0\tannotations\t0\tunknown\t0\tnodes\t71\ttarget\t-\teform\t-\taform\t-\tbytes\t3171"
    );
    assert_eq!(
        rows[1],
        "comp\t0\tkind\telement\tname\tc00\tref\t-\ttype\txs:string\tnested\t-"
    );
    assert_eq!(
        rows[64],
        "comp\t63\tkind\telement\tname\tc63\tref\t-\ttype\txs:string\tnested\t-"
    );
    assert_eq!(rows[65], "cut\tcomponents\t70\tlisted\t64");
    assert_eq!(rows.iter().filter(|row| row.starts_with("comp\t")).count(), 64);
}

/// The rule is the binding, not the prefix: `q` is as good a name for the schema namespace as `xs`,
/// and a root that binds that URI under some *other* prefix while standing somewhere else is not a
/// schema at all. That second case is the one a rule of "any attribute whose value is the URI" would
/// have accepted, which is why the element's own prefix is what selects the declaration.
#[test]
fn the_binding_is_the_rule_and_the_prefix_is_not() {
    let aliased = br#"<?xml version="1.0"?>
<q:schema xmlns:q="http://www.w3.org/2001/XMLSchema">
  <q:element name="a" type="q:B"/>
</q:schema>"#;
    let rows = read(aliased);
    assert_eq!(rows.len(), 2);
    assert!(
        rows[1].starts_with("comp\t0\tkind\telement\tname\ta\tref\t-\ttype\tq:B"),
        "{rows}",
        rows = rows[1]
    );

    for not in [
        br#"<?xml version="1.0"?>
<schema xmlns="urn:elsewhere"><element name="a"/></schema>"#.as_slice(),
        br#"<?xml version="1.0"?>
<s:schema xmlns:s="urn:elsewhere" xmlns:x="http://www.w3.org/2001/XMLSchema">
  <x:element name="a"/>
</s:schema>"#.as_slice(),
        br#"<?xml version="1.0"?>
<xs:element xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#.as_slice(),
    ] {
        assert!(
            parse(not).is_negative(),
            "a document that is not a schema was read as one"
        );
    }
    // Neither XML nor a schema: the GPS log keeps its own label, and its own refusal stays a refusal.
    assert_eq!(parse(&fixture("lab.gpx")), FORMAT_GPX);
    assert!(parse(&fixture("broken.gpx")).is_negative(), "an unclosed document");
}

/// A child the schema namespace has no name for is counted and listed under its own local name rather
/// than dropped: an identity constraint, a foreign grammar, anything. Written here, because no
/// producer in this lab makes one, and labelled as such.
#[test]
fn a_child_nobody_named_goes_in_the_bucket_and_onto_a_row() {
    let rows = read(
        br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="a" type="xs:string"/>
  <xs:unique name="one"><xs:selector xpath="."/></xs:unique>
</xs:schema>"#,
    );
    assert!(rows[0].contains("\tpieces\t2\t"), "{}", rows[0]);
    assert!(rows[0].contains("\tunknown\t1\t"), "{}", rows[0]);
    assert_eq!(rows[1], "comp\t0\tkind\telement\tname\ta\tref\t-\ttype\txs:string\tnested\t-");
    assert_eq!(rows[2], "other\t1\tkind\tunique");
}

/// A literal newline inside an attribute value is a space as far as the information set goes, and the
/// two witnesses both hand back the space; a `&#10;` is the other half of the rule and stays a
/// newline, which the row then prints as `?` because a row is one line.
#[test]
fn an_attribute_that_spans_lines_says_so_as_a_space() {
    let rows = read(
        br#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:two
lines">
  <xs:element name="a" type="xs:string"/>
</xs:schema>"#,
    );
    assert!(
        rows[0].contains("target\turn:two lines\teform"),
        "the newline in the value should have become a space: {}",
        rows[0]
    );
    assert_eq!(rows.len(), 2);
}
