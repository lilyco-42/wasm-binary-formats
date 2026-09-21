#!/usr/bin/env python3
"""Write the Word-template fixture, and say what in the file makes it a template rather than a document.

`dotx` is one of magika's 219 binary labels and the only Office template name among them (`xltx` and
`potx` are not labels at all), so this is one label rather than three.

Two writers, because that is what makes the claim checkable. `python-docx` writes the source .docx - a
real OOXML package, which LibreOffice will not build from the minimal hand-assembled fixtures in
`test/fixtures` - and LibreOffice's own `Office Open XML Text Template` filter writes the .dotx from it.
The witness is then the manifest, read with `zipfile` from both packages: a .docx declares its main part
as `wordprocessingml.document.main+xml` and a .dotx declares the **same part name** as
`wordprocessingml.template.main+xml`. That string is the only difference either file carries - the
extension is not stored inside - so it is what the reader is allowed to key on, and it is reported in the
row beside the part name rather than left as an inference.

Usage: temp/venv/Scripts/python.exe scripts/make-dotx-fixture.py
"""
import json
import os
import re
import subprocess
import sys
import zipfile

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "dotx-work"))
TEMPLATE_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
DOCUMENT_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
# LibreOffice installs under Program Files, not under Windows' own directory; both spellings are tried
# because the earlier Office rounds had to find it the same way.
CANDIDATES = [
    os.path.join(os.environ.get("PROGRAMFILES", "C:/Program Files"), "LibreOffice", "program", "soffice.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"),
                 "LibreOffice", "program", "soffice.exe"),
]
SOFFICE = next((each for each in CANDIDATES if os.path.exists(each)), CANDIDATES[0])


def convert(source, target):
    if not os.path.exists(SOFFICE):
        raise SystemExit("no LibreOffice at {}; the template cannot be produced here".format(SOFFICE))
    os.makedirs(SCRATCH, exist_ok=True)
    made = subprocess.run(
        [SOFFICE, "--headless", "--norestore", "--invisible",
         "-env:UserInstallation=file:///" + SCRATCH.replace("\\", "/") + "/profile",
         "--convert-to", "dotx", "--outdir", SCRATCH, source],
        capture_output=True, shell=False)
    if made.returncode != 0:
        raise SystemExit("LibreOffice refused: {}".format(made.stderr[:200]))
    if not os.path.exists(target):
        raise SystemExit("LibreOffice reported success but wrote no {}".format(target))
    return target


def read_package(path):
    """The parts, and the content type the manifest states for the main document part."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "word/document.xml" not in names:
            raise SystemExit("{} has no word/document.xml".format(path))
        # The reader reports the first `word/` entry in central-directory order, which is not a rule
        # the format states, so the probe carries the name the walk actually lands on rather than the
        # one the specification mandates.
        first = next(name for name in names if name.startswith("word/"))
        manifest = archive.read("[Content_Types].xml").decode("utf8", "replace")
        size = archive.getinfo("word/document.xml").file_size
    overrides = dict(re.findall(
        r'PartName="(/[^"]+)"\s+ContentType="([^"]+)"', manifest))
    stated = overrides.get("/word/document.xml")
    if stated is None:
        # The OOXML manifest may also declare the type by extension rather than per part; a package
        # laid out that way cannot be told apart from this reader's seat, so say so instead of guessing.
        raise SystemExit("{} states no per-part content type for /word/document.xml".format(path))
    return {"parts": len(names), "main_size": size, "content_type": stated,
            "first_word_part": first,
            "has_manifest": "[Content_Types].xml" in names}


def main():
    import docx  # the real .docx writer, installed here and used by the package fixtures already

    os.makedirs(SCRATCH, exist_ok=True)
    source = os.path.join(SCRATCH, "in.docx")
    document = docx.Document()
    document.add_heading("apk-lens lab", 0)
    document.add_paragraph("a template is a package that says so in its manifest")
    document.save(source)
    target = os.path.join(SCRATCH, "in.dotx")
    if not os.path.exists(target):
        convert(source, target)

    plain = read_package(source)
    template = read_package(target)
    if plain["content_type"] != DOCUMENT_TYPE:
        raise SystemExit("the source is not a document.main+xml package: {}".format(plain["content_type"]))
    if template["content_type"] != TEMPLATE_TYPE:
        raise SystemExit("the converted file is not a template: {}".format(template["content_type"]))

    raw = open(target, "rb").read()
    # The reader prints the content type minus the vendor prefix, because what is left is the part that
    # differs - and the guard below insists on that being exactly one word.
    prefix = "application/vnd.openxmlformats-officedocument."
    tail = TEMPLATE_TYPE[len(prefix):]
    document_tail = DOCUMENT_TYPE[len(prefix):]
    if not tail.startswith("wordprocessingml.") or not document_tail.startswith("wordprocessingml."):
        raise SystemExit("unexpected content-type shape: {} / {}".format(tail, document_tail))
    if tail.replace("wordprocessingml.", "") != document_tail.replace("wordprocessingml.", "").replace(
            "document.main+xml", "template.main+xml"):
        raise SystemExit("the two differ in more than the one word: {} vs {}".format(tail, document_tail))
    rows = [
        "document\t{}\t{}".format(len(raw), template["main_size"]),
        "main_part\t{}\tcontent\t{}".format(template["first_word_part"], tail),
        "entries\t{}".format(template["parts"]),
        "archive_bytes\t{}".format(len(raw)),
        "has_manifest\t1",
    ]
    if template["first_word_part"] != "word/document.xml":
        raise SystemExit("the walk lands on {}, not the part the manifest describes".format(
            template["first_word_part"]))
    print("== in.dotx {} bytes, {} parts".format(len(raw), template["parts"]))
    for row in rows:
        print("   ", row.replace("\t", " | "))
    fixture = os.path.join(OUT, "lab-fixture.dotx")
    with open(fixture, "wb") as handle:
        handle.write(raw)
    with open(os.path.join(OUT, "dotx.probe.json"), "w", encoding="utf8") as handle:
        json.dump({"bytes": len(raw), "docx": plain, "dotx": template, "rows": rows},
                  handle, indent=1, sort_keys=True)
    print("wrote lab-fixture.dotx and dotx.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
