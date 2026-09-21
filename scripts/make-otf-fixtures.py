#!/usr/bin/env python3
"""Write the CFF-flavoured OpenType fixture, and record what a second implementation sees in it.

`otf` is one of magika's 219 binary labels and the only one in the `font` group left unclaimed, and it
was recorded as needing "a CFF charstring writer that nothing here has" - which was only true of the
interpreter on PATH. `temp/venv` has fontTools, whose `FontBuilder(isTTF=False)` writes a real CFF
outline font, so the writer side was installed all along.

Two implementations, because one of them has to be somebody else's. fontTools writes the file *and* is
the library that knows its own tables, so reading it back with fontTools proves nothing on its own; the
witness here is FreeType through Pillow, which shares no code with the writer:
`ImageFont.truetype(path, size)` answers the family and style, the advance width of `A` and the
ascent/descent, and every one of those numbers has to come out of the bytes this reader will report -
the advance comes from the CFF Private dict's `DefaultWidthX`/`NominalWidthX` (or the per-glyph Widths),
and the ascent and descent from `hhea`, scaled by `head.unitsPerEm`. The script refuses to commit
unless FreeType agrees, so a wrong offset in the writer or a wrong field in the reader shows up here
rather than in a test that only re-reads its own assumption.

What the reader is *not* given: the charstrings are left as an encoded program, no glyph is rasterised,
and no CFF index is walked, so the label this earns is the sfnt directory plus the outline-table check -
see the `outlines` row in `engine/src/containers.rs`.

Usage: temp/venv/Scripts/python.exe scripts/make-otf-fixtures.py
"""
import json
import os
import struct
import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.ttLib import TTFont

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "otf-work"))
UNITS = 1000
ASCENT, DESCENT = 800, 200
DEFAULT_WIDTH, NOMINAL_WIDTH = 600, 0
SIZE = 40  # pixels per em for the FreeType witness


def box(pen, x0, y0, x1, y1):
    pen.moveTo((x0, y0))
    pen.lineTo((x0, y1))
    pen.lineTo((x1, y1))
    pen.lineTo((x1, y0))
    pen.closePath()


def charstring(box_width):
    """A closed square, built with the T2 pen: setupCFF wants T2CharString objects, not source text."""
    pen = T2CharStringPen(DEFAULT_WIDTH, None)
    box(pen, 100, 0, 100 + box_width, 700)
    return pen.getCharString()


def build(path, glyphs):
    names = [".notdef"] + [name for name, _ in glyphs]
    builder = FontBuilder(UNITS, isTTF=False)
    builder.setupGlyphOrder(names)
    builder.setupCharacterMap({code: name for code, (name, _) in enumerate(glyphs, start=65)})
    charstrings = {".notdef": charstring(400)}
    charstrings.update({name: charstring(width) for name, width in glyphs})
    builder.setupCFF(
        "LabTestOTF",
        {"FullName": "Lab Test OTF", "FamilyName": "Lab", "Weight": "Regular"},
        charstrings,
        {"NominalWidthX": NOMINAL_WIDTH, "DefaultWidthX": DEFAULT_WIDTH},
    )
    builder.setupHorizontalMetrics({name: (DEFAULT_WIDTH, 100) for name in names})
    builder.setupHorizontalHeader(ascent=ASCENT, descent=-DESCENT)
    builder.setupNameTable({"familyName": "Lab", "styleName": "Regular"})
    builder.setupOS2(sTypoAscender=ASCENT, usWinAscent=ASCENT, usWinDescent=DESCENT)
    builder.setupPost()
    builder.font.save(path)
    return path


def directory(raw):
    """The sfnt table directory, read with struct so the probe is a second walk, not fontTools'."""
    tag, number = raw[:4], struct.unpack_from(">H", raw, 4)[0]
    tables = {}
    for index in range(number):
        record = 12 + 16 * index
        name = raw[record:record + 4].decode("latin-1")
        offset, length = struct.unpack_from(">II", raw, record + 8)
        tables[name] = (offset, length)
    return tag.decode("latin-1"), number, tables


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    made = build(os.path.join(SCRATCH, "lab.otf"), [("A", 400), ("B", 450)])
    raw = open(made, "rb").read()
    flavour, number, tables = directory(raw)
    if flavour != "OTTO":
        raise SystemExit("an isTTF=False font should carry the OTTO flavour tag, got {!r}".format(flavour))
    if "CFF " not in tables or "glyf" in tables:
        raise SystemExit("not a CFF-flavoured font: {}".format(sorted(tables)))
    head = tables["head"][0]
    units = struct.unpack_from(">H", raw, head + 18)[0]
    hhea = tables["hhea"][0]
    ascent, descent = struct.unpack_from(">hh", raw, hhea + 4)
    glyphs = TTFont(made)["maxp"].numGlyphs
    if units != UNITS or (ascent, descent) != (ASCENT, -DESCENT):
        raise SystemExit("head/hhea disagree with what was asked for: {} {}/{}".format(units, ascent, descent))

    from PIL import ImageFont

    face = ImageFont.truetype(made, SIZE)
    name = face.getname()
    advance = face.getlength("A")
    metrics = face.getmetrics()
    # The numbers FreeType reads back are the same ones the bytes state, scaled: an advance of 600 units
    # in a 1000-em font at 40 px is 24 px, and 800/-200 give (32, 8). If the writer had put the width in
    # the wrong place, or FreeType read another table, these would not hold and nothing is committed.
    expect_advance = DEFAULT_WIDTH / units * SIZE
    expect_metrics = (ASCENT / units * SIZE, DESCENT / units * SIZE)
    if name[0] != "Lab" or list(metrics) != list(map(int, expect_metrics)) or abs(advance - expect_advance) > 0.51:
        raise SystemExit(
            "FreeType saw {} advance {} metrics {} for expected {} / {}".format(
                name, advance, metrics, expect_advance, expect_metrics))

    fields = {
        "flavour_tag": flavour,
        "tables_in_directory": sorted(tables),
        "outline_tables": [tag for tag in ("CFF ", "CFF2", "glyf") if tag in tables],
        "num_glyphs": glyphs,
        "units_per_em": units,
        "ascender": ascent,
        "descender": descent,
        "name_records": struct.unpack_from(">H", raw, tables["name"][0] + 2)[0],
        "tables_end_highest": max(at + size for at, size in tables.values()),
        "file_bytes": len(raw),
    }
    fixture = os.path.join(OUT, "lab.otf")
    with open(fixture, "wb") as handle:
        handle.write(raw)
    with open(os.path.join(OUT, "otf.probe.json"), "w", encoding="utf8") as handle:
        json.dump(
            {
                "bytes": len(raw),
                "flavour": flavour,
                "tables": {tag: {"offset": at, "length": size} for tag, (at, size) in sorted(tables.items())},
                "freetype": {"name": list(name), "advance_A": advance, "metrics": list(metrics), "size": SIZE},
                "fields": fields,
            },
            handle,
            indent=1,
            sort_keys=True,
        )
    print("== lab.otf {} bytes, flavour {}, {} tables, {} glyphs".format(len(raw), flavour, number, glyphs))
    for key, value in sorted(fields.items()):
        print("   ", key, "=", value)
    print("   FreeType:", name, "advance", advance, "metrics", metrics)
    print("wrote lab.otf and otf.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
