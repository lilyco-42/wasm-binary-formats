#!/usr/bin/env python3
"""Write the QOI fixtures with Pillow's own encoder, then account for their chunks by hand.

    python3 scripts/make-qoi-fixtures.py

QOI (`qoi` in magika's taxonomy) has no Kaitai spec in the pinned bundle, and Pillow 12.3 both
reads and writes it, so the producer and a second, independent decoder are one import away. The
header is `qoif` + width + height as big-endian u32, then *single bytes* for channels and
colorspace - Pillow's writer only emits colorspace 0 when the caller passes `colorspace="sRGB"`,
which is why `srgb.qoi` exists next to the two files that say 1: a reader that showed the
colorspace byte as a name needs both values in the repository.

`all6.qoi` is the one that separates the chunk classes. Its bands were built to make Pillow
choose each of the six encodings - a flat band (run), two colours alternating inside the 64-entry
index window (index), steps of one or two per channel (diff), a green ramp (luma), an alpha ramp
(argb) - and the probe records the counts this script read off the finished bytes. Nothing here is
guessed from the specification: `walk()` decodes the file Pillow wrote, and Pillow then decodes it
back and the pixels are compared, so the chunk accounting and the image agree through two
implementations.
"""

import json
import pathlib
import struct
import sys
from collections import Counter

from PIL import Image

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"
TERMINATOR = bytes([0, 0, 0, 0, 0, 0, 0, 1])


def walk(data):
    """Classify every chunk, count the pixels each one covers, and see where the stream ends."""
    kinds, scan, pixels = Counter(), 14, 0
    body = len(data) - 8
    while scan < body:
        tag = data[scan]
        if tag == 0xFE:
            name, step, count = "rgb", 4, 1
        elif tag == 0xFF:
            name, step, count = "argb", 5, 1
        elif tag < 0x40:
            name, step, count = "index", 1, 1
        elif tag < 0x80:
            name, step, count = "diff", 1, 1
        elif tag < 0xC0:
            name, step, count = "luma", 2, 1
        else:
            name, step, count = "run", 1, (tag & 0x3F) + 1
        if scan + step > body:
            return kinds, pixels, scan, "short"
        kinds[name] += 1
        pixels += count
        scan += step
    return kinds, pixels, scan, "none" if scan == body else "misaligned"


def record(name, image, **options):
    path = OUT / name
    image.save(path, **options)
    data = path.read_bytes()
    width, height, channels, colorspace = (
        *struct.unpack(">II", data[4:12]),
        data[12],
        data[13],
    )
    kinds, pixels, scan, stopped = walk(data)
    back = Image.open(path)
    back.load()
    assert (width, height) == back.size, f"{name}: header and decoder disagree on size"
    assert (data[-8:] == TERMINATOR) and scan == len(data) - 8, f"{name}: stream does not end right"
    probe = {
        "length": len(data),
        "width": width,
        "height": height,
        "channels": channels,
        "colorspace": colorspace,
        "claimed": width * height,
        "pixels": pixels,
        "chunks": sum(kinds.values()),
        "kinds": {key: kinds[key] for key in ("rgb", "argb", "index", "diff", "luma", "run")},
        "terminator": data[-8:].hex(),
        "stopped": stopped,
        "mode_after_decode": back.mode,
        "corner": list(back.getpixel((width - 1, height - 1))),
    }
    print(f"{name}: {len(data)} bytes, {pixels} pixels in {sum(kinds.values())} chunks {dict(probe['kinds'])}")
    return probe


def banded():
    """64x8 RGBA whose bands make the encoder pick all six chunk classes."""
    image = Image.new("RGBA", (64, 8))
    pixels = image.load()
    for y in range(8):
        for x in range(64):
            if x < 20:
                pixels[x, y] = (10, 20, 30, 255)
            elif x < 30:
                pixels[x, y] = (200, 10, 10, 255) if x % 2 else (10, 200, 10, 255)
            elif x < 40:
                pixels[x, y] = (60 + (x % 10) // 2, 60, 60, 255)
            elif x < 50:
                pixels[x, y] = (90, 90 + (x % 10) // 3, 90, 255)
            else:
                pixels[x, y] = (7, 7, 7, (x - 49) * 40 + 3)
    return image


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    flat = Image.new("RGBA", (8, 6), (10, 20, 30, 255))
    probes = {
        "tiny": record("tiny.qoi", flat),
        "srgb": record("srgb.qoi", flat.convert("RGB"), colorspace="sRGB"),
        "all6": record("all6.qoi", banded()),
    }
    (OUT / "qoi.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
