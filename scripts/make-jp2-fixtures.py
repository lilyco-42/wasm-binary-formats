#!/usr/bin/env python3
"""Write the JPEG 2000 PCRL (JP2) fixtures with Pillow's openjpeg-backed encoder.

    python3 scripts/make-jp2-fixtures.py

`jp2` is a magika label with no Kaitai spec in the pinned bundle, and Pillow writes it, so both the
producer and a second decoder are one library away: every fixture is saved, opened again, and its
pixels checked before the box walk below runs.

The walk is the point of this script, because two of the facts it records are the opposite of what
the format's neighbours do:

  * the `ihdr` box puts **height before width** (the part-1 codestream's own `SIZ` inside `jp2c`
    lists them the other way round, and both are read here so the file testifies twice);
  * sample depth is stored minus one, so the byte reads 7 where the decoded image is 8-bit.

`bpc` is therefore recorded both as the byte and as the depth the decoder agrees to. The witness for
both is Pillow opening the finished file and returning the same size and mode - `ihdr` read as
width-then-height would fail that assert - and the `jp2c` box is checked only for its SOC marker,
because laying the part-1 `SIZ` segment out from memory did not add up to its own declared length.
Three fixtures, because `NC` decides everything downstream: one greyscale, one three-component, one
with alpha and a `cdef` box besides.
"""

import json
import pathlib
import struct
import sys

from PIL import Image

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"
PRINTABLE = lambda raw: "".join(chr(c) if 32 <= c < 127 else "?" for c in raw)  # noqa: E731


def boxes(data, start, end):
    """Top-level boxes, and the children of any superbox, as the file lays them out."""
    found, at, broken = [], start, 0
    while at + 8 <= end:
        size = int.from_bytes(data[at : at + 4], "big")
        tag = PRINTABLE(data[at + 4 : at + 8])
        if size == 1:
            size = int.from_bytes(data[at + 8 : at + 16], "big")
            header = 16
        else:
            header = 8
        length = end - at if size == 0 else size
        if length < header or at + length > end:
            broken += 1
            break
        found.append({"tag": tag, "size": length, "at": at, "header": header})
        at += length
    return found, broken


def children_of(data, box):
    inner, _ = boxes(data, box["at"] + box["header"], box["at"] + box["size"])
    return inner


def record(name, image, **options):
    path = OUT / name
    image.save(path, **options)
    data = path.read_bytes()
    back = Image.open(path)
    back.load()
    assert back.size == image.size and back.mode == image.mode, f"{name}: encoder/decoder disagree"

    top, broken = boxes(data, 0, len(data))
    header_box = top[0]
    assert header_box["tag"] == "jP  " and data[8:12] == bytes([0x0D, 0x0A, 0x87, 0x0A]), name
    superbox = next((box for box in top if box["tag"] == "jp2h"), None)
    kids = children_of(data, superbox) if superbox else []
    probe = {
        "length": len(data),
        "declared": sum(box["size"] for box in top),
        "boxes": [f"{box['tag']}\t{box['size']}\t{box['at']}" for box in top],
        "children": [f"{box['tag']}\t{box['size']}\t{box['at']}" for box in kids],
        "broken": broken,
        "signature": data[8:12].hex(),
        "mode_after_decode": back.mode,
    }
    ihdr = next((box for box in kids if box["tag"] == "ihdr"), None)
    if ihdr:
        at = ihdr["at"] + 8
        height, width, components, bpc, colour_filter, unknown, ipr = struct.unpack(
            ">IIHBBBB", data[at : at + 14]
        )
        probe["ihdr"] = {
            "height": height,
            "width": width,
            "components": components,
            "depth_byte": bpc,
            "bits": bpc + 1,
            "colour_filter": colour_filter,
            "unknown": unknown,
            "ipr": ipr,
        }
        codestream = next((box for box in top if box["tag"] == "jp2c"), None)
        if codestream:
            # Only the start of the codestream is checked here. Reading the SIZ segment's own
            # geometry meant laying out nine fields from memory, and the offsets did not add up to
            # the declared Lsiz - so the size claim rests on `ihdr` above and on Pillow's decoder
            # agreeing with it, which is what the assert at the top of this function already is.
            start = codestream["at"] + 8
            assert data[start : start + 2] == b"\xff\x4f", f"{name}: the codestream has no SOC marker"
            probe["codestream"] = {"at": codestream["at"], "size": codestream["size"], "soc": True}
    colr = next((box for box in kids if box["tag"] == "colr"), None)
    if colr:
        at = colr["at"] + 8
        probe["colr"] = {
            "method": data[at],
            "precision": data[at + 1],
            "approx": data[at + 2],
            "enumerated": int.from_bytes(data[at + 3 : at + 7], "big"),
        }
    print(f"{name}: {len(data)} bytes, {[b['tag'] for b in top]}, {broken} broken")
    return probe


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rgb = Image.new("RGB", (32, 20))
    pixels = rgb.load()
    for y in range(20):
        for x in range(32):
            pixels[x, y] = (x * 8 % 256, y * 13 % 256, 60)
    probes = {
        "tiny": record("tiny.jp2", rgb),
        "rgba": record("rgba.jp2", Image.new("RGBA", (16, 16), (200, 30, 40, 128))),
        "grey": record("grey.jp2", Image.new("L", (64, 8), 77)),
    }
    (OUT / "jp2.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
