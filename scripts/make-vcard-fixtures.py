#!/usr/bin/env python3
"""Write the vCard fixtures with vobject, and record what vobject reads back from them.

`vcard` is one of magika's 219 binary labels (`text/vcard`, and `is_text: false`, so it is in the
denominator rather than the text half of the taxonomy) and it shares its line grammar with every other
iCalendar-derived format - `BEGIN:`/`END:`, `NAME;PARAM=value:value`, and long values folded with a
leading space. `ics` is not available as a target: magika marks iCalendar `is_text: true`, so it is
outside the 219. `vcs` is in the denominator but its knowledge-base entry is empty - no mime type, no
description, no extensions - so there is nothing citable to key a claim on and it is left as a gap.

Two implementations, as always. `vobject` writes the files and *is* the witness for the counts the reader
will print: the probe records what vobject sees when it reads its own output back (version, the property
list, how many EMAIL children exist, the folded NOTE's length), so a property miscounted by this repo's
reader shows up as a disagreement rather than as a test that agrees with itself.

Two fixtures, because the format has two shapes worth separating: a vCard 4.0 whose long NOTE is folded
across five physical lines and whose N value carries an escaped comma, and a vCard 3.0 with two EMAIL
properties and no folding at all. The first exercises unfold-before-count; the second says that counting
does not depend on there being a folded line to unfold.

Usage: temp/venv/Scripts/python.exe scripts/make-vcard-fixtures.py
"""
import json
import os
import sys

import vobject

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "vcard-work"))
FAMILY, GIVEN = "Fixture, Jr.", "Lab"
NOTE_LENGTH = 300
EMAILS = ("lab@example.invalid", "lab-alternate@example.invalid")


def card(version, second_email):
    card = vobject.vCard()
    card.add("fn").value = "Lab Fixture"
    card.add("n").value = vobject.vcard.Name(family=FAMILY, given=GIVEN)
    first = card.add("email")
    first.value = EMAILS[0]
    first.params = {"TYPE": ["INTERNET"]}
    tel = card.add("tel")
    tel.value = "+15550001111"
    tel.params = {"TYPE": ["CELL"]}
    adr = card.add("adr")
    adr.value = vobject.vcard.Address(street="1 Main St", city="Springfield", region="IL", code="00000", country="US")
    if second_email:
        extra = card.add("email")
        extra.value = EMAILS[1]
    card.add("note").value = "x" * NOTE_LENGTH
    card.add("x-lab-tag").value = "kept"
    card.add("version").value = version
    return card


def physical(text):
    """Physical lines, counting the empty string after the file's final CRLF as nothing."""
    lines = text.split("\r\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def unfold(lines):
    joined, folded = [], 0
    for line in lines:
        if line[:1] in (" ", "\t") and joined:
            joined[-1] += line[1:]
            folded += 1
        else:
            joined.append(line)
    return joined, folded


def witness(text):
    """What the other implementation says about the same bytes."""
    back = vobject.readOne(text)
    kids = list(back.getChildren())
    names = sorted({child.name for child in kids})
    return {
        "version": back.version.value,
        "children": len(kids),
        "names": names,
        "emails": len(back.email_list),
        "fn": back.fn.value,
        "n": [back.n.value.given, back.n.value.family],
        "note_length": len(back.note.value),
        "adr_parts": len(back.adr.value.lines[0].split(";")) if hasattr(back, "adr") else 0,
        "params": {child.name: sorted(child.params) for child in kids if child.params},
    }


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    report = {}
    for label, version, second in (("lab.vcard", "4.0", False), ("lab3.vcard", "3.0", True)):
        text = card(version, second).serialize()
        lines = physical(text)
        logical, folded = unfold(lines)
        if text.count("\n") != text.count("\r\n"):
            raise SystemExit("{} is not CRLF throughout, so the reader's line discipline is moot".format(label))
        if not text.endswith("\r\n"):
            raise SystemExit("{} has no final CRLF; END would look like a truncated file".format(label))
        if logical[0] != "BEGIN:VCARD" or logical[-1] != "END:VCARD":
            raise SystemExit("{} is not a balanced component: {!r} .. {!r}".format(label, logical[0], logical[-1]))
        if not logical[1].startswith("VERSION:"):
            raise SystemExit("vobject did not put VERSION second, so `first yes` cannot be asserted")
        back = witness(text)
        if back["version"] != version or back["note_length"] != NOTE_LENGTH:
            raise SystemExit("vobject read back {} / {} for what was written".format(
                back["version"], back["note_length"]))
        if back["children"] != len(logical) - 2:
            raise SystemExit(
                "vobject counted {} properties against {} content lines".format(
                    back["children"], len(logical) - 2))
        # The `note_length` check above is also the proof that unfolding works: a fold left in place
        # would put CRLF plus the leading space back into the value and change its length.
        report[label] = {
            "bytes": len(text.encode("utf8")),
            "physical_lines": len(lines),
            "logical_lines": len(logical),
            "folded": folded,
            "properties": len(logical) - 2,
            "n_line": next((line for line in logical if line.startswith("N:")), ""),
            "backslashes": sum(line.count("\\") for line in logical),
            "witness": back,
        }
        with open(os.path.join(OUT, label), "wb") as handle:
            handle.write(text.encode("utf8"))
        print("== {} {} bytes, {} physical, {} logical, {} folded".format(
            label, len(text.encode("utf8")), len(lines), len(logical), folded))
        for line in lines:
            print("   ", repr(line[:78]))
    # The escaped comma is the one thing in the fixture a reader has to leave alone but still count, so
    # it is checked here rather than assumed from the writer's documentation.
    for label, record in sorted(report.items()):
        if "\\" not in record["n_line"]:
            raise SystemExit("{} has no escape to count: {!r}".format(label, record["n_line"]))
        print("   {}: N: {} with {} backslash(es)".format(
            label, record["n_line"], record["backslashes"]))
    # newline="\n" on purpose: the probe is a committed artefact, and a generator that let the platform
    # choose its line endings would rewrite the whole file on a second run.
    with open(os.path.join(OUT, "vcard.probe.json"), "w", encoding="utf8", newline="\n") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print("wrote lab.vcard, lab3.vcard and vcard.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
