//! `.pgp` / `.gpg`: OpenPGP, read as the packet lengths the file states for itself.
//!
//! `scripts/make-pgp-fixtures.py` writes six fixtures with GnuPG and asks `gpg --list-packets` to read
//! them back. That listing is the witness, and it is an unusually direct one: for each packet gpg prints
//! `# off=N ctb=XX tag=T hlen=H plen=P`, so the offsets, tags and sizes the rows below claim are compared
//! against the same numbers another implementation derived from the same bytes - and the script refuses to
//! write the probe unless the two agree, packet for packet, including the *names* (`public key`,
//! `onepass_sig`, `literal data`) rather than a table recalled from an RFC.
//!
//! Six fixtures because the framing has branches that a single file cannot show: an ed25519 key export
//! keeps every old-format length inside one octet, an rsa2048 export needs the two-octet form (269 and 334
//! bytes), a default-signed message is one compressed packet of *indeterminate* length, and an encrypted
//! one mixes both header formats in two packets. The `old` / `new` in each packet row is which of the two
//! the file actually used.
//!
//! Two things are deliberately not claimed. Nothing is decompressed or decrypted: past a compressed or
//! encrypted packet the report says `descend no deflate` / `descend no encrypted` and stops, because the
//! bytes beyond it are not packet framing. And a one-pass signature's algorithm octets - which sit in the
//! opposite order to a full signature's - are not printed at all, because the witness prints neither, so
//! there would be nothing to check the reading against.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_PGP};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-pgp-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn row(lines: &[String], named: &str) -> String {
    lines
        .iter()
        .find(|entry| entry.starts_with(named))
        .cloned()
        .unwrap_or_else(|| panic!("no row starting {named:?} in {lines:#?}"))
}

fn read(bytes: &[u8]) -> Vec<String> {
    assert_eq!(parse(bytes), FORMAT_PGP, "the file has to be accepted first");
    assert_eq!(kind(), FORMAT_PGP, "kind() must agree with the return code");
    assert_eq!(name(), "pgp");
    report()
}

/// A keyring export: five packets, each one's length read from the two low bits of its own tag octet.
#[test]
fn a_key_export_is_a_run_of_packets_that_ends_on_the_last_byte() {
    let lines = read(&fixture("lab-key.pgp"));
    assert_eq!(
        lines,
        vec![
            "openpgp\tpackets\t5\tbytes\t421\tends\tyes\tbroken\t0",
            "kind\tkey",
            "packet\t0\told\ttag\t6\tpublic key\thlen\t2\tplen\t51",
            "packet\t53\told\ttag\t13\tuser ID\thlen\t2\tplen\t40",
            "packet\t95\told\ttag\t2\tsignature\thlen\t2\tplen\t144",
            "packet\t241\told\ttag\t14\tpublic sub key\thlen\t2\tplen\t56",
            "packet\t299\told\ttag\t2\tsignature\thlen\t2\tplen\t120",
            "key\tv4\talgo\t22\tcreated\t1789967999",
            "userid\tAPK Lens ed Fixture <ed@example.invalid>",
            "sig\tv4\tfull\tsigclass\t0x13\tpubkey\t22\thash\t10",
            "key\tv4\talgo\t18\tcreated\t1789967999",
            "sig\tv4\tfull\tsigclass\t0x18\tpubkey\t22\thash\t10",
        ]
    );
    // The subkey's own binding signature is class 0x18 and its algorithm is ECDH (18), while the user ID
    // certification above it is 0x13 with EdDSA (22). Both numbers come from gpg's sentence about the same
    // packet, so a reader that took the two signature packets to be alike would fail the probe.
    assert_eq!(row(&lines, "userid"), "userid\tAPK Lens ed Fixture <ed@example.invalid>");
    let record = String::from_utf8(fixture("pgp.probe.json")).unwrap();
    for field in [
        "\"packets\": 5",
        "\"bytes\": 421",
        "APK Lens ed Fixture",
        "sigclass 0x18",
        "digest algo 10",
        "\"opaque\": false",
    ] {
        assert!(record.contains(field), "the probe does not record {field}");
    }
}

/// The branch the ed25519 file never reaches: an rsa2048 key whose packets do not fit in one length octet.
#[test]
fn an_old_format_header_that_needs_two_length_octets_is_still_one_walk() {
    let lines = read(&fixture("lab-rsa.pgp"));
    assert_eq!(
        lines,
        vec![
            "openpgp\tpackets\t3\tbytes\t653\tends\tyes\tbroken\t0",
            "kind\tkey",
            "packet\t0\told\ttag\t6\tpublic key\thlen\t3\tplen\t269",
            "packet\t272\told\ttag\t13\tuser ID\thlen\t2\tplen\t42",
            "packet\t316\told\ttag\t2\tsignature\thlen\t3\tplen\t334",
            "key\tv4\talgo\t1\tcreated\t1789968000",
            "userid\tAPK Lens rsa Fixture <rsa@example.invalid>",
            "sig\tv4\tfull\tsigclass\t0x13\tpubkey\t1\thash\t10",
        ]
    );
    // Two packets use the two-octet length and the user ID still uses the one-octet one, so the octet count
    // is a property of each header rather than of the file.
    assert!(row(&lines, "packet\t0").ends_with("\thlen\t3\tplen\t269"));
    assert!(row(&lines, "packet\t272").ends_with("\thlen\t2\tplen\t42"));
}

/// A signed message with the compression switched off: three packets, and a literal whose body the
/// witness counts the same way.
#[test]
fn a_literal_packet_reports_its_own_name_and_the_body_left_after_its_fields() {
    let lines = read(&fixture("lab-signed.pgp"));
    assert_eq!(
        lines,
        vec![
            "openpgp\tpackets\t3\tbytes\t180\tends\tyes\tbroken\t0",
            "kind\tmessage",
            "packet\t0\told\ttag\t4\tonepass_sig\thlen\t2\tplen\t13",
            "packet\t15\told\ttag\t11\tliteral data\thlen\t2\tplen\t44",
            "packet\t61\told\ttag\t2\tsignature\thlen\t2\tplen\t117",
            "sig\tv3\tonepass",
            "literal\tnote.txt\tbody\t30\tfields\t14",
            "sig\tv4\tfull\tsigclass\t0x00\tpubkey\t22\thash\t10",
        ]
    );
    // 44 bytes of payload, 14 of them mode, name length, the eight-character name and a timestamp.
    let record = String::from_utf8(fixture("pgp.probe.json")).unwrap();
    assert!(record.contains("raw data: 30 bytes"), "gpg never counted the body");
    assert!(record.contains("name=\\\"note.txt\\\""));
}

/// The honest shape of a signed file: everything after the compressed packet is inside a stream this
/// reader will not open, so the walk is one packet long and says why it stopped.
#[test]
fn a_compressed_packet_runs_to_the_end_of_the_file_and_is_not_descended_into() {
    let lines = read(&fixture("lab-signedz.pgp"));
    assert_eq!(
        lines,
        vec![
            "openpgp\tpackets\t1\tbytes\t176\tends\tyes\tbroken\t0",
            "kind\tmessage",
            "packet\t0\told\ttag\t8\tcompressed\thlen\t1\tplen\t-\tindeterminate",
            "descend\tno\tdeflate",
        ]
    );
    // The listing holds nested packets at offsets that are positions in the decompressed stream; the walk
    // stops before them, and gpg's own first line is the compressed packet at offset zero.
    let record = String::from_utf8(fixture("pgp.probe.json")).unwrap();
    assert!(record.contains("indeterminate"));
    assert!(record.contains("\"opaque\": true"));
}

/// The two encrypted shapes: an opaque SEIPD packet whose header uses the *new* format while the packet in
/// front of it uses the old one.
#[test]
fn an_encrypted_body_is_named_as_far_as_its_header_goes_and_no_further() {
    let keyed = read(&fixture("lab-encr.pgp"));
    assert_eq!(
        keyed,
        vec![
            "openpgp\tpackets\t2\tbytes\t185\tends\tyes\tbroken\t0",
            "kind\tmessage",
            "packet\t0\told\ttag\t1\tpubkey enc\thlen\t2\tplen\t94",
            "packet\t96\tnew\ttag\t18\tencrypted data\thlen\t2\tplen\t87",
            "pkesf\tv3\talgo\t18\tkeyid\tffc5990a3b25afc3",
            "descend\tno\tencrypted",
        ]
    );
    // The key ID sits between the version and the algorithm, which is not the order gpg lists them in:
    // reading the algorithm at body[1] returns 0xff, the key ID's first octet, and the probe refuses that.
    assert_eq!(row(&keyed, "pkesf"), "pkesf\tv3\talgo\t18\tkeyid\tffc5990a3b25afc3");
    let phrase = read(&fixture("lab-sym.pgp"));
    assert_eq!(
        phrase,
        vec![
            "openpgp\tpackets\t2\tbytes\t104\tends\tyes\tbroken\t0",
            "kind\tmessage",
            "packet\t0\told\ttag\t3\tsymkey enc\thlen\t2\tplen\t13",
            "packet\t15\tnew\ttag\t18\tencrypted data\thlen\t2\tplen\t87",
            "skesf\tv4\tcipher\t9\ts2k\t3\thash\t10",
            "descend\tno\tencrypted",
        ]
    );
}

/// Hand-built cases: what a tile that fails is refused for, and the two rows a well-formed but unusual
/// file can produce that no fixture here contains.
#[test]
fn a_walk_that_does_not_tile_is_refused_rather_than_half_reported() {
    // One packet, its stated length running off the end.
    let over = b"\x88\x10\x04\x13\x16\x0a\x00\x00\x00\x00";
    assert_eq!(parse(over), -2, "a packet longer than the file: {:?}", report());
    // A packet that stops short: the walk ends at byte 4 of 8, so the tiling claim is false.
    let extra = [0x90, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(parse(&extra), -2, "a file with bytes left over: {:?}", report());
    assert_eq!(count(), 0, "a refusal left rows behind");
    // A new-format partial-length chain: legal, but its next packet cannot be located without reading the
    // chunks, so the whole file is refused here rather than reported up to the point of doubt.
    let partial = [0xC2, 0xE0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00];
    assert_eq!(parse(&partial), -2, "a partial length was sized anyway: {:?}", report());
    // Something with no packet header at all.
    assert_eq!(parse(b"not a packet stream at all"), -2);
    assert_eq!(count(), 0, "and rows behind it");

    // A hand-built subkey packet, long enough to clear the eight-byte floor the whole module shares: the
    // tag is named because gpg names it, and the body's version, algorithm and creation time are read out
    // of the octet order the packet spells.
    let built = read(&[0xb8, 0x06, 0x04, 0x13, 0x16, 0x0a, 0x00, 0x00]);
    assert_eq!(
        built,
        vec![
            "openpgp\tpackets\t1\tbytes\t8\tends\tyes\tbroken\t0",
            "kind\tkey",
            "packet\t0\told\ttag\t14\tpublic sub key\thlen\t2\tplen\t6",
            "key\tv4\talgo\t0\tcreated\t320211456",
        ]
    );
    // The same shape with a tag no file here carries: named by number, since there is no witness to copy a
    // name from, and `kind` follows the first packet rather than the file's extension.
    let odd = read(&[0xbc, 0x06, 0x04, 0x13, 0x16, 0x0a, 0x00, 0x00]);
    assert_eq!(
        row(&odd, "packet"),
        "packet\t0\told\ttag\t15\ttag 15\thlen\t2\tplen\t6"
    );
    assert_eq!(row(&odd, "kind"), "kind\tmessage");
}

/// Sanitising and unreadable-field rows: a user ID with control octets, and a literal whose declared name
/// length does not fit its payload.
#[test]
fn text_that_would_break_the_abi_is_spared_the_row_rather_than_the_reader() {
    // tag 13 (user ID), one length octet, body holds a NUL and a newline.
    let mut card = vec![0xb4, 0x06];
    card.extend_from_slice(b"ab\x00c\nz");
    let lines = read(&card);
    assert_eq!(
        row(&lines, "userid"),
        "userid\tab?c?z",
        "control octets must not reach a C string"
    );

    // tag 11 (literal), payload 6 bytes but the name length claims 40.
    let named = read(b"\xac\x06\x62\x28\x6e\x6f\x74\x65");
    assert_eq!(row(&named, "literal"), "literal\tunreadable");
    assert_eq!(row(&named, "packet"), "packet\t0\told\ttag\t11\tliteral data\thlen\t2\tplen\t6");
}
