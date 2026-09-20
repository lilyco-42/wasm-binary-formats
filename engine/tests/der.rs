//! ASN.1 DER, read as the certificate it is: a tree somebody else has already listed.
//!
//! `test/fixtures/rsa.crt` and `test/fixtures/ec.crt` are written by OpenSSL 3.5.7 - `genpkey`, then
//! `req -new -x509` with the serial and both validity dates fixed - by `scripts/make-der-fixtures.py`.
//! That script then reads the same bytes back with two OpenSSL commands and refuses to write its probe
//! unless both agree with its own walk: `asn1parse -i`, whose list of offset, depth, header length,
//! content length and type name has to be *the same list in the same order*, and `x509 -text`, which
//! states the version, serial, both algorithm names, the two times, the issuer and subject strings and
//! the RSA key size. So the numbers below are observations from a second implementation, and the OID
//! names in parentheses are the strings `asn1parse` printed beside those same value bytes.
//!
//! What the reader does not do is stated too. It prints an EC key's size as `-`, because "256 bit" is a
//! property of the named curve and the only way to have that number would be to carry a table of curves
//! claimed from memory; and it prints the validity strings exactly as DER holds them, because parsing a
//! `UTCTime` would require a two-digit-year rule nobody has vouched for here.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_DER, FORMAT_ICC};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-der-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_DER, "{} bytes", bytes.len());
    assert_eq!(kind(), FORMAT_DER, "kind() must agree with the return code");
    assert_eq!(name(), "der", "the reader has to name what it walked");
    report()
}

#[test]
fn reads_the_certificate_openssl_signed_and_listed() {
    let lines = rows(&fixture("rsa.crt"));
    assert_eq!(lines[0], "der\t856\tbroken\t0\ttlvs\t58\tdepth\t5\tend\tyes");
    assert_eq!(
        lines[1],
        "cert\tversion\t3\tserial\t2a\tsig\tsha256WithRSAEncryption(1.2.840.113549.1.1.11)\tpub\trsaEncryption(1.2.840.113549.1.1.1)"
    );
    assert_eq!(
        lines[2],
        "valid\tkind\t17(UTCTIME)\tnot_before\t260101000000Z\tnot_after\t360101000000Z"
    );
    assert_eq!(
        lines[3],
        "name\tissuer\t3\t2.5.4.6=CN,2.5.4.10=apk-lens lab,2.5.4.3=test.example.invalid"
    );
    assert_eq!(
        lines[4],
        "name\tsubject\t3\t2.5.4.6=CN,2.5.4.10=apk-lens lab,2.5.4.3=test.example.invalid",
        "self-signed, so the two names hold the same strings - compared as two rows, not as one"
    );
    assert_eq!(
        lines[5],
        "key\talgorithm\trsaEncryption(1.2.840.113549.1.1.1)\tbits\t2048\tpoint\t270"
    );
    assert_eq!(lines[lines.len() - 2], "cut\ttlvs\t58");
    assert_eq!(lines[lines.len() - 1], "walked\tend");
    assert_eq!(lines.len(), 48, "6 field rows, 40 tree rows, cut, walked");
}

#[test]
fn the_tree_is_the_same_offsets_and_names_asn1parse_printed() {
    // Offsets, header lengths and content lengths come from the bytes; the names after the pipe are
    // `asn1parse`'s own spellings, uppercase included, and `cont [ 0 ]` is how it renders the context
    // tag that wraps the version.
    let lines = rows(&fixture("rsa.crt"));
    assert_eq!(lines[6], "tlv\t0\td0\t0\thl\t4\tl\t852\t30(cons|SEQUENCE)");
    assert_eq!(lines[7], "tlv\t1\td1\t4\thl\t4\tl\t572\t30(cons|SEQUENCE)");
    assert_eq!(lines[8], "tlv\t2\td2\t8\thl\t2\tl\t3\ta0(cons|cont [ 0 ])");
    assert_eq!(lines[9], "tlv\t3\td3\t10\thl\t2\tl\t1\t02(prim|INTEGER)");
    assert_eq!(lines[12], "tlv\t6\td3\t18\thl\t2\tl\t9\t06(prim|OBJECT)");
    assert_eq!(lines[13], "tlv\t7\td3\t29\thl\t2\tl\t0\t05(prim|NULL)");
    assert_eq!(lines[28], "tlv\t22\td3\t102\thl\t2\tl\t13\t17(prim|UTCTIME)");
    // The listing cap is a fact about the report, not about the file: 58 objects, 40 rows, and the cut
    // row names the total.
    let tlv_rows = lines
        .iter()
        .filter(|line| line.starts_with("tlv\t"))
        .count();
    assert_eq!(tlv_rows, 40);
}

#[test]
fn an_ec_certificate_reads_with_the_same_tree_and_no_borrowed_curve_size() {
    let lines = rows(&fixture("ec.crt"));
    assert_eq!(
        lines[0],
        "der\t459\tbroken\t0\ttlvs\t56\tdepth\t5\tend\tyes"
    );
    assert_eq!(
        lines[1],
        "cert\tversion\t3\tserial\t2a\tsig\tecdsa-with-SHA256(1.2.840.10045.4.3.2)\tpub\tid-ecPublicKey(1.2.840.10045.2.1)"
    );
    assert_eq!(
        lines[5],
        "key\talgorithm\tid-ecPublicKey(1.2.840.10045.2.1)\tbits\t-\tpoint\t65",
        "x509 -text calls this a 256-bit key because it knows the curve; the bytes only name it"
    );
    assert_eq!(lines[lines.len() - 2], "cut\ttlvs\t56");
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn an_oid_beyond_the_table_is_printed_as_the_number_the_bytes_hold() {
    let mut bytes = fixture("rsa.crt");
    // The signature algorithm's OBJECT at 18, last value byte 28: 0x0b is sha256WithRSAEncryption,
    // 0x09 is an OID nobody here has named. Length is untouched, so the tree is the same tree.
    bytes[28] = 0x09;
    let lines = rows(&bytes);
    assert_eq!(
        lines[1],
        "cert\tversion\t3\tserial\t2a\tsig\t1.2.840.113549.1.1.9(1.2.840.113549.1.1.9)\tpub\trsaEncryption(1.2.840.113549.1.1.1)"
    );
    assert_eq!(
        lines[0],
        "der\t856\tbroken\t0\ttlvs\t58\tdepth\t5\tend\tyes",
        "an unnamed OID is not a failed claim"
    );
    assert_eq!(lines[lines.len() - 1], "walked\tend");
}

#[test]
fn the_framing_claim_is_printed_rather_than_demanded_and_a_broken_one_is_not_read() {
    // One byte spare: the top SEQUENCE still parses, so the file is still a certificate - it just says
    // its own length does not account for the file, and the stray byte counts as a failed check too.
    let mut padded = fixture("rsa.crt");
    padded.push(0);
    let lines = rows(&padded);
    assert_eq!(
        lines[0],
        "der\t857\tbroken\t2\ttlvs\t58\tdepth\t5\tend\tno",
        "{}",
        lines.join(" | ")
    );
    assert_eq!(lines[lines.len() - 1], "stopped\tbroken\t2");

    // One byte short: the stated length runs past the end, so there is no tree to walk at all and the
    // file is not claimed.
    let cut = fixture("rsa.crt")[..855].to_vec();
    assert_ne!(
        parse(&cut),
        FORMAT_DER,
        "a certificate that cannot hold its own length is not read as one"
    );

    let mut not_sequence = fixture("rsa.crt");
    not_sequence[0] = 0x31;
    assert_ne!(parse(&not_sequence), FORMAT_DER, "the top object has to be a SEQUENCE");

    assert_eq!(parse(&[0x30u8; 8]), -2, "eight bytes that claim 48 are nothing");
    assert_ne!(parse(&fixture("srgb.icc")), FORMAT_DER, "a profile is not a certificate");
    assert_eq!(
        parse(&fixture("srgb.icc")),
        FORMAT_ICC,
        "and the profile still reaches its own reader"
    );
    assert_ne!(
        parse(b"-----BEGIN CERTIFICATE-----\nMIIB\n"),
        FORMAT_DER,
        "PEM is base64 text, and saying so is the pem reader's business"
    );
}
