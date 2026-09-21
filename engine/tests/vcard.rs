//! vCard: the line grammar behind `.vcf`, read as the lines state it.
//!
//! Both fixtures come from `vobject` (`scripts/make-vcard-fixtures.py`), which is also the witness: the
//! probe records what that library reads back out of the bytes it wrote, so a property this reader
//! counted wrongly disagrees with another implementation rather than with a comment. `lab.vcard` is a
//! vCard 4.0 whose NOTE is long enough that the writer folded it across five physical lines, and whose N
//! value carries an escaped comma; `lab3.vcard` is 3.0 with two EMAIL properties and the same fold.
//! The two together separate "count the lines" from "count the properties after unfolding".
//!
//! What is deliberately not claimed: no value is decoded - `\,` stays in the value and the report counts
//! backslashes and unescaped semicolons instead of resolving them into text - and no field's *meaning*
//! is asserted, only that the file states it. That is why `vcard` is a `fields` label over the line
//! structure and not over the address book.

use apk_lens::containers::{at, count, kind, name, parse, FORMAT_VCARD};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/");

fn fixture(file: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}{file}");
    fs::read(&path).unwrap_or_else(|error| {
        panic!("{path} missing, run temp/venv/Scripts/python.exe scripts/make-vcard-fixtures.py: {error}")
    })
}

fn report() -> Vec<String> {
    (0..count()).filter_map(at).collect()
}

fn rows(bytes: &[u8]) -> Vec<String> {
    assert_eq!(
        parse(bytes),
        FORMAT_VCARD,
        "the card has to be accepted first"
    );
    assert_eq!(
        kind(),
        FORMAT_VCARD,
        "kind() must agree with the return code"
    );
    assert_eq!(name(), "vcard");
    report()
}

#[test]
fn counts_the_properties_that_the_writer_folded_into_lines() {
    let lines = rows(&fixture("lab.vcard"));
    assert_eq!(
        lines,
        vec![
            "vcard\t4.0\tprops\t8\tnames\t8\tlines\t14\tfolded\t4\tcomponents\t1",
            "endings\tcrlf\t14\tlf\t0\tlogical\t10\tlast_newline\tyes",
            "version\t4.0\tsecond\tyes",
            "end\tyes\tbroken\t0\tescapes\t1",
            "prop\tADR\tcount\t1\tparts\t7\tparams\t-",
            "prop\tEMAIL\tcount\t1\tparts\t1\tparams\tTYPE",
            "prop\tFN\tcount\t1\tparts\t1\tparams\t-",
            "prop\tN\tcount\t1\tparts\t5\tparams\t-",
            "prop\tNOTE\tcount\t1\tparts\t1\tparams\t-",
            "prop\tTEL\tcount\t1\tparts\t1\tparams\tTYPE",
            "prop\tVERSION\tcount\t1\tparts\t1\tparams\t-",
            "prop\tX-LAB-TAG\tcount\t1\tparts\t1\tparams\t-",
        ]
    );
    // Fourteen physical lines, ten logical ones: the fold is what separates the two, and it is the
    // number the witness library reports for the same file.
    let record = String::from_utf8(fixture("vcard.probe.json")).unwrap();
    for field in [
        "\"properties\": 8",
        "\"children\": 8",
        "\"folded\": 4",
        "\"physical_lines\": 14",
        "\"logical_lines\": 10",
    ] {
        assert!(record.contains(field), "the probe does not record {field}");
    }

    // The same walk on a card with a second EMAIL: one name, two occurrences, and the parameter keys of
    // both gathered into that row.
    let second = rows(&fixture("lab3.vcard"));
    assert_eq!(
        second[0],
        "vcard\t3.0\tprops\t9\tnames\t8\tlines\t15\tfolded\t4\tcomponents\t1"
    );
    assert!(
        second
            .iter()
            .any(|line| line == "prop\tEMAIL\tcount\t2\tparts\t1\tparams\tTYPE"),
        "{second:#?}"
    );
    assert!(
        record.contains("\"emails\": 2"),
        "the probe does not record vobject's own count of the two EMAIL properties"
    );
}

#[test]
fn a_semicolon_that_is_escaped_is_not_a_separator_and_a_quoted_parameter_is_not_a_value() {
    // Hand-built on purpose: these are the shapes the fixtures do not carry, and each is the smallest
    // file that isolates one rule.
    let escaped = rows(b"BEGIN:VCARD\r\nVERSION:4.0\r\nNOTE:a\\;b\r\nbroken line\r\nEND:VCARD\r\n");
    assert!(
        escaped
            .iter()
            .any(|line| line == "prop\tNOTE\tcount\t1\tparts\t1\tparams\t-"),
        "an escaped semicolon must not split the value: {escaped:#?}"
    );
    assert_eq!(
        escaped[3], "end\tyes\tbroken\t1\tescapes\t1",
        "the line with no colon is counted, not skipped: {escaped:#?}"
    );

    let quoted = rows(b"BEGIN:VCARD\r\nVERSION:4.0\r\nX;P=\"a:b;c\":one\r\nEND:VCARD\r\n");
    assert!(
        quoted
            .iter()
            .any(|line| line == "prop\tX\tcount\t1\tparts\t1\tparams\tP"),
        "the colon inside a quoted parameter value does not end the name part: {quoted:#?}"
    );

    let after = rows(b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:a\r\nEND:VCARD\r\nFN:after\r\n");
    assert_eq!(
        after[3],
        "end\tno\tbroken\t1\tescapes\t0",
        "a property outside a closed component is a defect, and the card no longer ends where it should: {after:#?}"
    );

    let unclosed = rows(b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:a\r\n");
    assert_eq!(
        unclosed[3], "end\tno\tbroken\t0\tescapes\t0",
        "a card that never says END is reported, not refused: {unclosed:#?}"
    );

    let unterminated = rows(b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:a\r\nEND:VCARD");
    assert_eq!(
        unterminated[1],
        "endings\tcrlf\t3\tlf\t0\tlogical\t4\tlast_newline\tno",
        "the file's own last line has no break, and that is the one thing the row can prove: {unterminated:#?}"
    );
    assert_eq!(unterminated[3], "end\tyes\tbroken\t0\tescapes\t0");

    // Case: `begin:vcard` is as legal as `BEGIN:VCARD`, and the names come back upper-cased either way.
    let lower = rows(b"begin:vcard\r\nversion:2.1\r\nFN:x\r\nEND:VCARD\r\n");
    assert_eq!(
        lower[0],
        "vcard\t2.1\tprops\t2\tnames\t2\tlines\t4\tfolded\t0\tcomponents\t1"
    );
}

#[test]
fn a_vcalendar_is_not_claimed_as_a_vcard() {
    // The line grammar is shared and the reader would walk it happily, but `ics` is outside the label
    // set this repo scores against and nothing here produces a .vcs whose definition is written down
    // anywhere, so the only card accepted is the one that says so.
    let calendar = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//lab//\r\nEND:VCALENDAR\r\n";
    assert_eq!(
        parse(calendar),
        -2,
        "a calendar is not a card: {:?}",
        report()
    );
    assert_eq!(count(), 0, "a refusal leaves no rows behind");

    // `BEGIN:VCARDX` opens something else entirely: the token has to end where the card's name does.
    assert_eq!(
        parse(b"BEGIN:VCARDX\r\nVERSION:4.0\r\nFN:a\r\nEND:VCARD\r\n"),
        -2,
        "a longer token is not this format: {:?}",
        report()
    );
}
