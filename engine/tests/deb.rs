//! Debian package tests, on a .deb assembled from Python's own tar and gzip writers.
//!
//! The archive is an ar container, so the claim worth testing is not that members can be listed -
//! `read_ar` does that - but that this one is recognised as a package by its mandated member set,
//! and that a plain archive still falls through to the ar reader. Sizes come from
//! `test/fixtures/lab-fixture.deb.json`, which `scripts/make-deb-fixture.py` wrote while it built
//! the file, so the expectations are observations rather than numbers typed into a test.

use apk_lens::containers::{at, count, kind, parse, FORMAT_AR, FORMAT_DEB};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{name}");
    fs::read(&path)
        .unwrap_or_else(|error| panic!("{path} missing, run scripts/make-deb-fixture.py: {error}"))
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(lines: &[String], prefix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|entry| entry.starts_with(prefix))
        .cloned()
        .collect()
}

#[test]
fn recognises_a_debian_package_by_its_mandated_members() {
    let deb = fixture("lab-fixture.deb");
    assert_eq!(parse(&deb), FORMAT_DEB);
    assert_eq!(kind(), FORMAT_DEB, "kind() must agree with the return code");
    let lines = report();
    assert_eq!(rows(&lines, "deb\t"), vec!["deb\t3"], "{lines:#?}");
    assert_eq!(rows(&lines, "control\t"), vec!["control\tcontrol.tar.gz"]);
    assert_eq!(rows(&lines, "data\t"), vec!["data\tdata.tar.gz"]);
    let members = rows(&lines, "member\t");
    assert_eq!(members.len(), 3, "{lines:#?}");
    // The version record is "2.0" plus a newline: four bytes, as the generator recorded.
    assert!(
        members[0].starts_with("member\tdebian-binary\t4\t"),
        "{:?}",
        members[0]
    );
    assert!(
        members[1].starts_with("member\tcontrol.tar.gz\t221\t"),
        "{:?}",
        members[1]
    );
    assert!(
        members[2].starts_with("member\tdata.tar.gz\t151\t"),
        "{:?}",
        members[2]
    );
    let record = String::from_utf8(fixture("lab-fixture.deb.json")).unwrap();
    for field in ["debian-binary", "control.tar.gz", "data.tar.gz"] {
        assert!(
            record.contains(field),
            "the generator did not record {field}"
        );
    }
}

#[test]
fn a_plain_ar_archive_is_still_just_ar() {
    // The deb branch runs first, so a plain archive has to fall through to the ar reader rather than
    // be called a package it is not.
    let plain = fixture("plain.ar");
    assert_eq!(parse(&plain), FORMAT_AR, "{:?}", report());
    assert_eq!(kind(), FORMAT_AR);
    assert_eq!(
        rows(&report(), "object.o"),
        vec!["object.o\t6\t644"],
        "one member, six bytes, the mode from its header"
    );
}
