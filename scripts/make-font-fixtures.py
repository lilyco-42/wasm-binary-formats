#!/usr/bin/env python3
"""Write the font fixtures the table-directory tests read.

fontTools compiles a two-glyph font from nothing - no third-party outline is copied here - so the
bytes come from an implementation this repo does not control while the fixture stays small and free
to commit. The probe JSON is the same library's reading of the finished file, which is what the Rust
assertions were written against.

    python scripts/make-font-fixtures.py [out_dir]

`woff2` is not produced: converting to it needs `brotli`, which this Python refuses to install
(externally managed environment), so that label stays an honest gap.
"""

import json
import os
import struct
import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)

fb = FontBuilder(1000, isTTF=True)
fb.setupGlyphOrder([".notdef", "A"])
fb.setupCharacterMap({65: "A"})
pen = TTGlyphPen(None)
pen.moveTo((100, 0))
pen.lineTo((100, 700))
pen.lineTo((500, 700))
pen.lineTo((500, 0))
pen.closePath()
fb.setupGlyf({".notdef": TTGlyphPen(None).glyph(), "A": pen.glyph()})
fb.setupHorizontalMetrics({".notdef": (500, 0), "A": (600, 0)})
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupNameTable({"familyName": "Lab Fixture", "styleName": "Regular"})
fb.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
fb.setupPost()
ttf = os.path.join(out, "tiny.ttf")
fb.save(ttf)

woff = os.path.join(out, "tiny.woff")
carried = TTFont(ttf)
carried.flavor = "woff"
carried.save(woff)


def sfnt_rows(path):
    data = open(path, "rb").read()
    version = data[:4]
    number = struct.unpack_from(">H", data, 4)[0]
    tables = {}
    for index in range(number):
        record = 12 + 16 * index
        tag = data[record : record + 4].decode("latin-1")
        offset, length = struct.unpack_from(">II", data, record + 8)
        tables[tag] = (offset, length)
    head = tables["head"][0]
    hhea = tables["hhea"][0]
    maxp = tables["maxp"][0]
    name = tables["name"][0]
    return {
        "bytes": len(data),
        "sfntVersion": version.hex(),
        "numTables": number,
        "tables": {tag: list(tables[tag]) for tag in sorted(tables)},
        "unitsPerEm": struct.unpack_from(">H", data, head + 18)[0],
        "ascender": struct.unpack_from(">h", data, hhea + 4)[0],
        "descender": struct.unpack_from(">h", data, hhea + 6)[0],
        "numGlyphs": struct.unpack_from(">H", data, maxp + 4)[0],
        "nameRecords": struct.unpack_from(">H", data, name + 2)[0],
        "tablesEnd": max(off + ln for off, ln in tables.values()),
    }


def woff_rows(path):
    data = open(path, "rb").read()
    sig, flavor, length, number, _reserved, total = struct.unpack_from(">4s4sIHHI", data, 0)
    entries = {}
    for index in range(number):
        record = 44 + 20 * index
        tag = data[record : record + 4].decode("latin-1")
        offset, comp, orig = struct.unpack_from(">III", data, record + 4)
        entries[tag] = [offset, comp, orig]
    return {
        "bytes": len(data),
        "signature": sig.decode("latin-1"),
        "flavor": flavor.hex(),
        "declaredLength": length,
        "numTables": number,
        "totalSfntSize": total,
        "tables": entries,
        "compressedSum": sum(v[1] for v in entries.values()),
        "originalSum": sum(v[0 + 2] for v in entries.values()),
        "tablesEnd": max(off + comp for off, comp, _orig in entries.values()),
    }


for path, reader in ((ttf, sfnt_rows), (woff, woff_rows)):
    report = reader(path)
    report["fixture"] = os.path.basename(path)
    report["written_by"] = "fontTools %s" % __import__("fontTools").version
    report["detail"] = "two-glyph font compiled from scratch by scripts/make-font-fixtures.py"
    # Underscored like the media probes: `tiny.probe.json` already belongs to tiny.pdf.
    probe = path.replace(".ttf", "_ttf").replace(".woff", "_woff") + ".probe.json"
    with open(probe, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("wrote", os.path.basename(path), json.dumps(report, sort_keys=True)[:150])
