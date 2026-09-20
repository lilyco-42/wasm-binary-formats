#!/usr/bin/env python3
"""Write the ICNS fixture and its probe.

Pillow's ICNS writer builds the icon from a plain in-memory image, so the bytes come from an
implementation this repo does not control while nothing third-party is copied in.

The probe matters more than usual here. Apple's icon types are usually described as a tag-to-size
table, but Pillow writes `ic13`/`ic14` at 256 and 514 pixels of *image*, not at the point sizes the
type names imply, so a reader that printed dimensions from a remembered table would be wrong about
this very file. The probe therefore decodes each embedded image with Pillow and records the pixels
the payload actually carries, which is also what the reader derives - from the PNG header, not from
a lookup.

    python scripts/make-icon-fixtures.py [out_dir]
"""

import io
import json
import os
import struct
import sys

from PIL import Image

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)

# Flat colour on purpose: the encoded sizes stay a few tens of kilobytes instead of hundreds, and
# nothing in the directory walk depends on the picture content.
source = Image.new("RGBA", (64, 64), (20, 90, 200, 255))
path = os.path.join(out, "tiny.icns")
source.save(path, "ICNS")

data = open(path, "rb").read()
magic = data[:4]
declared = struct.unpack_from(">I", data, 4)[0]
entries = []
at = 8
while at + 8 <= len(data):
    tag = data[at : at + 4].decode("latin-1")
    size = struct.unpack_from(">I", data, at + 4)[0]
    body = data[at + 8 : at + size]
    info = {"tag": tag, "size": size, "body": len(body), "first4": body[:4].hex()}
    if body[:8] == b"\x89PNG\r\n\x1a\n":
        info["format"] = "png"
        info["width"], info["height"] = struct.unpack_from(">II", body, 16)
    elif body[4:12] == b"jP  \r\n":
        info["format"] = "jp2"
    else:
        info["format"] = "metadata"
    try:
        decoded = Image.open(io.BytesIO(body))
        info["pillow"] = [decoded.width, decoded.height, decoded.format]
    except Exception as error:  # not every entry is an image
        info["pillow"] = None
    entries.append(info)
    if size < 8:
        break
    at += size

report = {
    "fixture": os.path.basename(path),
    "written_by": "Pillow %s ICNS plugin" % __import__("PIL").__version__,
    "detail": "64x64 RGBA icon; Pillow writes the full icon set, upscaled from the source",
    "bytes": len(data),
    "magic": magic.decode("latin-1"),
    "declaredLength": declared,
    "entriesEnd": at,
    "tiled": at == len(data),
    "entries": entries,
}
with open(os.path.join(out, "tiny_icns.probe.json"), "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")

print("wrote", report["bytes"], "bytes,", len(entries), "entries, tiled", report["tiled"])
for entry in entries:
    print("  ", entry["tag"], entry["size"], entry["format"], entry.get("width"), entry.get("height"))
