//! HEIF: the item metadata inside an ISO base-media container, and the two sizes that disagree.
//!
//! `test/fixtures/{photo,block,seq}.heic` and `container.heif` are written by pillow-heif (which
//! bundles libheif) by `scripts/make-heif-fixtures.py`. That script walks the boxes with its own
//! reader *and* asks pillow-heif what it thinks the file is, and refuses to write
//! `heif.probe.json` unless the clean aperture's numerators equal the writer's `size`, unless the
//! `pixi` depths' maximum equals the writer's `bit_depth`, and unless the `nclx` primaries, transfer
//! characteristics, matrix coefficients and full-range flag equal the writer's own colour profile.
//! So the rows below are the writer's numbers, not this repo's reading of ISO/IEC 23008-12.
//!
//! The interesting pair is `photo.heic` against `block.heic`. Both declare `ispe` 64x64 - that is the
//! coded size, and libheif rounds up to whole coding blocks - but only the first is cropped: 23x17
//! arrives in `clap` as rationals, so the file with the odd dimensions is the one whose `ispe` is a
//! lie about the picture.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_HEIF};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{path} missing, run temp/venv/Scripts/python.exe scripts/make-heif-fixtures.py: {error}"
        )
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(file: &str) -> Vec<String> {
    let bytes = fixture(file);
    assert_eq!(parse(&bytes), FORMAT_HEIF, "{file} has to be claimed");
    assert_eq!(
        kind(),
        FORMAT_HEIF,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "heif", "the reader has to name what it walked");
    report()
}

fn summary(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| !line.starts_with("box\t"))
        .cloned()
        .collect()
}

fn be32(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// A box with the payload already inside its declared size.
fn box_of(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut out = be32((8 + body.len()) as u32);
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(body);
    out
}

/// `ftyp heic` + a `meta` fullbox holding one `ipco` with an `ispe` of 8x6. With `junk` set, a box
/// that claims more bytes than its parent holds is appended inside `ipco`, which is the case the
/// walk has to survive after it already read the image size.
fn hand_built(brand: &str, junk: bool) -> Vec<u8> {
    let ispe = box_of("ispe", &[0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 6][..]);
    let mut ipco_body = ispe;
    if junk {
        let mut oversized = be32(9_000);
        oversized.extend_from_slice(b"junk");
        ipco_body.extend_from_slice(&oversized);
    }
    let ipco = box_of("ipco", &ipco_body);
    let iprp = box_of("iprp", &ipco);
    let mut meta = vec![0u8, 0, 0, 0];
    meta.extend_from_slice(&iprp);
    let meta = box_of("meta", &meta);
    let mut ftyp_body = brand.as_bytes().to_vec();
    ftyp_body.extend_from_slice(&[0u8; 4]);
    ftyp_body.extend_from_slice(b"mif1");
    let mut out = box_of("ftyp", &ftyp_body);
    out.extend_from_slice(&meta);
    out
}

#[test]
fn reads_the_item_metadata_pillow_heif_wrote() {
    assert_eq!(
        rows("photo.heic"),
        vec![
            "heif\t453\tboxes\t16\tbroken\t0\tbrand\theic",
            "compat\tmif1,heic",
            "handler\tpict",
            "items\t1\tprimary\t1\tdescs\t1",
            "coded\t64x64",
            "visible\t23/1x17/1",
            "depths\t8,8,8\tchannels\t3",
            "colour\t1\ttransfer\t13\tmatrix\t6\trange\t1",
            "data\t41",
            "box\t0\tftyp\tat\t0\tsize\t24\tdepth\t0",
            "box\t1\tmeta\tat\t24\tsize\t380\tdepth\t0",
            "box\t2\thdlr\tat\t36\tsize\t33\tdepth\t1",
            "box\t3\tiloc\tat\t69\tsize\t34\tdepth\t1",
            "box\t4\tiinf\tat\t103\tsize\t35\tdepth\t1",
            "box\t5\tinfe\tat\t117\tsize\t21\tdepth\t2",
            "box\t6\tpitm\tat\t138\tsize\t14\tdepth\t1",
            "box\t7\tiprp\tat\t152\tsize\t252\tdepth\t1",
            "box\t8\tipco\tat\t160\tsize\t220\tdepth\t2",
            "box\t9\thvcC\tat\t168\tsize\t117\tdepth\t3",
            "box\t10\tcolr\tat\t285\tsize\t19\tdepth\t3",
            "box\t11\tispe\tat\t304\tsize\t20\tdepth\t3",
            "box\t12\tclap\tat\t324\tsize\t40\tdepth\t3",
            "box\t13\tpixi\tat\t364\tsize\t16\tdepth\t3",
            "box\t14\tipma\tat\t380\tsize\t24\tdepth\t2",
            "box\t15\tmdat\tat\t404\tsize\t49\tdepth\t0",
            "walked\tend",
        ]
    );
}

#[test]
fn the_coded_size_is_not_the_picture_and_only_clap_says_which_is_which() {
    let cropped = rows("photo.heic");
    let exact = rows("block.heic");
    assert_eq!(
        summary(&cropped)[4],
        "coded\t64x64",
        "ispe is what the codec stored"
    );
    assert_eq!(summary(&cropped)[5], "visible\t23/1x17/1");
    assert_eq!(
        summary(&exact),
        vec![
            "heif\t403\tboxes\t15\tbroken\t0\tbrand\theic",
            "compat\tmif1,heic,miaf",
            "handler\tpict",
            "items\t1\tprimary\t1\tdescs\t1",
            "coded\t64x64",
            "depths\t8,8,8\tchannels\t3",
            "colour\t1\ttransfer\t13\tmatrix\t6\trange\t1",
            "data\t25",
            "walked\tend",
        ],
        "a picture that fills its blocks needs no clean aperture, and gets none"
    );
}

#[test]
fn a_multi_image_file_lists_every_item_description() {
    let lines = rows("seq.heic");
    let head = summary(&lines);
    assert_eq!(head[0], "heif\t636\tboxes\t18\tbroken\t0\tbrand\theic");
    assert_eq!(head[1], "compat\tmif1,heic,miaf");
    assert_eq!(head[3], "items\t3\tprimary\t1\tdescs\t3");
    assert_eq!(head[4], "coded\t64x64");
    assert_eq!(head[5], "visible\t32/1x24/1");
    assert_eq!(head[8], "data\t126", "two mdat-style payloads summed");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("box\t") && line.contains("\tinfe\t"))
            .count(),
        3
    );
}

#[test]
fn the_extension_does_not_decide_the_brand() {
    let lines = rows("container.heif");
    assert_eq!(
        summary(&lines)[0],
        "heif\t457\tboxes\t16\tbroken\t0\tbrand\theic",
        "the file says heic in its ftyp whatever it is called"
    );
    assert_eq!(summary(&lines)[5], "visible\t18/1x12/1");
}

#[test]
fn a_hand_built_box_list_is_read_by_the_same_rules() {
    let bytes = hand_built("heic", false);
    assert_eq!(parse(&bytes), FORMAT_HEIF, "{} bytes", bytes.len());
    assert_eq!(
        summary(&report()),
        vec![
            format!(
                "heif\t{size}\tboxes\t5\tbroken\t0\tbrand\theic",
                size = bytes.len()
            ),
            "compat\tmif1".to_owned(),
            "handler\t?".to_owned(),
            "items\t0\tprimary\t0\tdescs\t0".to_owned(),
            "coded\t8x6".to_owned(),
            "data\t0".to_owned(),
            "walked\tend".to_owned(),
        ]
    );
}

#[test]
fn another_brand_or_a_broken_box_is_not_claimed_as_heif() {
    // Which other reader answers is not the point; that the HEIF reader does not is.
    for brand in ["isom", "av01", "qt  "] {
        assert_ne!(
            parse(&hand_built(brand, false)),
            FORMAT_HEIF,
            "{brand} is not a HEIF brand this reader knows"
        );
    }

    // A box inside the property container that claims more than its parent holds: the image size was
    // already read, so the file is HEIF, and the walk has to say it stopped rather than pretend.
    let broken = hand_built("heic", true);
    assert_eq!(parse(&broken), FORMAT_HEIF);
    let lines = report();
    assert_eq!(
        summary(&lines)[0],
        format!(
            "heif\t{size}\tboxes\t5\tbroken\t1\tbrand\theic",
            size = broken.len()
        ),
        "the box that claims past its parent is never listed, so the count stays at five"
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t1", "{lines:?}");
    assert!(
        summary(&lines)
            .iter()
            .any(|line| line.as_str() == "coded\t8x6"),
        "{lines:?}"
    );

    // The very first box reaching past the end leaves nothing to read.
    let mut oversized = hand_built("heic", false);
    let size = be32(9_000);
    oversized.splice(0..4, size);
    assert_ne!(
        parse(&oversized),
        FORMAT_HEIF,
        "a first box bigger than the file"
    );
}

#[test]
fn short_buffers_are_refused_before_any_reader_runs() {
    assert_eq!(parse(b"\0\0\0\x18f"), -1);
    assert_eq!(parse(&[0u8; 7]), -1);
}
