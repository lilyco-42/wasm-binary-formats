//! PostScript: the format whose claim is a line, and whose page count is a statement to be checked.
//!
//! `test/fixtures/preview.eps` is written by LibreOffice (`draw_eps_Export`, from a 2x2 PNG) and
//! `test/fixtures/plain.ps` by ImageMagick's own PostScript writer, so neither is a transcription of
//! the other's habits; `scripts/make-ps-fixtures.py` walks both with a private mirror and writes
//! `ps.probe.json` with the rows printed here. A regeneration on another host moves ImageMagick's
//! `%%Title` and `%%CreationDate` - the *committed* bytes are what these assertions read.
//!
//! Two things are deliberately reported as claims rather than facts. LibreOffice states `%%Pages: 0`
//! for a file that carries a `%%Page: 1 1`, while ImageMagick states 1 for one page, so the reader
//! prints the number beside the count of `%%Page:` comments and picks no winner (as it does for a PDF's
//! `/Count` and an EMF's record count). And a preview header is believed only where its own two length
//! words add up to the `%!` they promise - which is also why the bytes between the magic and those
//! words come out as hex: one writer puts a length there, another spells `TK`.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_EMF, FORMAT_PS, FORMAT_STL};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-ps-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

/// Everything before the file's last terminator, which is the one edit that turns a finished program
/// into an unfinished one without touching any other byte.
fn without_terminator(bytes: &[u8]) -> Vec<u8> {
    let width = b"%%EOF".len();
    let last = (0..=(bytes.len() - width))
        .rev()
        .find(|at| bytes[*at..*at + width] == b"%%EOF"[..])
        .expect("the fixture ends with a terminator");
    bytes[..last].to_vec()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_PS, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_PS, "kind() must agree with the return code");
    assert_eq!(
        name(),
        "postscript",
        "the reader has to name what it walked"
    );
    report()
}

#[test]
fn reads_the_plain_imagemagick_program() {
    assert_eq!(
        rows(&fixture("plain.ps")),
        vec![
            "ps\t5720\tbroken\t0\tpreview\tnone\tstart\t0\tdsc\tPS-Adobe-3.0",
            "bounds\t0\t0\t2\t2\twh\t2x2",
            "pages\tclaimed\t1\tfound\t1",
            "comment\t0\tCreator\t(ImageMagick)",
            "comment\t1\tTitle\t(plain.ps)",
            "comment\t2\tCreationDate\t(2026-09-20T21:09:58+00:00)",
            "comment\t3\tBoundingBox\t-0 -0 2 2",
            "comment\t4\tHiResBoundingBox\t0 0 2 2",
            "comment\t5\tDocumentData\tClean7Bit",
            "comment\t6\tLanguageLevel\t1",
            "comment\t7\tOrientation\tPortrait",
            "comment\t8\tPageOrder\tAscend",
            "comment\t9\tPages\t1",
            "comment\t10\tPage\t1 1",
            "comment\t11\tPageBoundingBox\t0 0 2 2",
            "comments\tcounted\t12\tstructural\t7\tlines\t280\tcrlf\t0\teof\t5714",
            "walked\tend",
        ]
    );
}

#[test]
fn finds_the_header_a_preview_buried_and_says_where_it_put_it() {
    let lines = rows(&fixture("preview.eps"));
    assert_eq!(
        lines[0],
        "ps\t14149\tbroken\t0\tpreview\tyes\tstart\t11908\tdsc\tPS-Adobe-3.0 EPSF-3.0"
    );
    assert_eq!(
        lines[1],
        "preview\theader\t30\tdata\t11878\tto\t11908\tbytes\t842e0000c10800000000000000000000"
    );
    assert_eq!(lines[2], "bounds\t0\t0\t539\t785\twh\t539x785");
    assert_eq!(
        lines[lines.len() - 2],
        "comments\tcounted\t8\tstructural\t10\tlines\t135\tcrlf\t9\teof\t14143"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
    // The two words are the file's own, and the offset they name is checked against the bytes: read
    // them any other way and the row below is a guess.
    let bytes = fixture("preview.eps");
    let head = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let span = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    assert_eq!(head + span, 11908, "{head} + {span}");
    assert_eq!(&bytes[11908..11910], b"%!");
}

#[test]
fn a_pages_claim_that_does_not_match_the_page_comments_is_printed_both_ways() {
    // LibreOffice says 0 and carries one `%%Page:`; ImageMagick says 1 and carries one. Neither row is
    // corrected here, because "what the file states" and "what the file has" are different facts.
    let lo = rows(&fixture("preview.eps"));
    assert_eq!(lo[3], "pages\tclaimed\t0\tfound\t1");
    let im = rows(&fixture("plain.ps"));
    assert_eq!(im[2], "pages\tclaimed\t1\tfound\t1");
}

#[test]
fn a_preview_whose_lengths_do_not_add_up_is_not_believed() {
    let mut bytes = fixture("preview.eps");
    bytes[24..28].copy_from_slice(&11879u32.to_le_bytes());
    assert_ne!(
        parse(&bytes),
        FORMAT_PS,
        "the arithmetic is the whole claim, so a lying length means no file"
    );
}

#[test]
fn a_missing_terminator_and_an_unparsable_box_are_counted_separately() {
    let lines = rows(&without_terminator(&fixture("plain.ps")));
    assert_eq!(
        lines[0],
        "ps\t5714\tbroken\t1\tpreview\tnone\tstart\t0\tdsc\tPS-Adobe-3.0"
    );
    assert_eq!(
        lines[lines.len() - 2],
        "comments\tcounted\t12\tstructural\t7\tlines\t279\tcrlf\t0\teof\t-1"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tno\teof");

    // Both failures at once, on a file small enough to write out here.
    let lines = rows(b"%!PS-Adobe-3.0\n%%BoundingBox: none here\n");
    assert_eq!(
        lines[0],
        "ps\t40\tbroken\t2\tpreview\tnone\tstart\t0\tdsc\tPS-Adobe-3.0"
    );
    assert_eq!(lines[1], "pages\tclaimed\tabsent\tfound\t0");
    assert_eq!(lines[2], "comment\t0\tBoundingBox\tnone here");
    assert!(
        !lines.iter().any(|line| line.starts_with("bounds")),
        "a box that is not four numbers is not a box: {lines:?}"
    );
}

#[test]
fn crlf_is_only_reported_never_assumed() {
    // The DSC allows CR, LF or CRLF, so the line counts are a fact about the file rather than a
    // precondition on it: every line here ends CR LF, and the terminator is still found.
    let lines =
        rows(b"%!PS-Adobe-3.0 EPSF-3.0\r\n%%Pages: 2\r\n%%Page: 1 2\r\n%%Page: 2 2\r\n%%EOF\r\n");
    assert_eq!(
        lines[0],
        "ps\t70\tbroken\t0\tpreview\tnone\tstart\t0\tdsc\tPS-Adobe-3.0 EPSF-3.0"
    );
    assert_eq!(lines[1], "pages\tclaimed\t2\tfound\t2");
    assert_eq!(
        lines[lines.len() - 2],
        "comments\tcounted\t3\tstructural\t0\tlines\t5\tcrlf\t5\teof\t63"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn text_that_never_says_who_it_is_is_left_alone() {
    assert_eq!(parse(b"aaaaaaaabbbbbbbb"), -2, "sixteen bytes of letters");
    assert_eq!(parse(&[0u8; 400]), -2, "zeroes name no program");
    assert_ne!(
        parse(&fixture("srgb.icc")),
        FORMAT_PS,
        "a profile's first line is not a banner"
    );
    assert_ne!(parse(&fixture("gdi.emf")), FORMAT_PS, "nor is a metafile's");
    assert_ne!(parse(&fixture("tet.stl")), FORMAT_PS, "nor a mesh's");
    assert_eq!(
        parse(&fixture("gdi.emf")),
        FORMAT_EMF,
        "and the metafile still reaches its own reader"
    );
    assert_eq!(
        parse(&fixture("tet.stl")),
        FORMAT_STL,
        "and the mesh still reaches its own"
    );
}
