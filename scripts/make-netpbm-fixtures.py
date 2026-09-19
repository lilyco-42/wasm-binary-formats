"""Netpbm fixtures for the container reader's tests.

Pillow writes the binary variants (`P6` pixmap, `P5` greymap, `P4` bitmap); it has no ASCII writer,
so `tiny.ppm-ascii` is written here straight from the published layout, with a comment line in the
header because accepting comments between the magic and the geometry is the part of this parser that
is easy to get wrong.

    python scripts/make-netpbm-fixtures.py [out_dir]     (default: test/fixtures)
"""

import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)

from PIL import Image  # noqa: E402  (after the path setup so the import stays simple)

PIXELS = [[(x * 40, y * 80, 200) for x in range(5)] for y in range(3)]
image = Image.new("RGB", (5, 3))
for y in range(3):
    for x in range(5):
        image.putpixel((x, y), PIXELS[y][x])

image.save(os.path.join(out, "tiny.ppm"))
image.convert("L").save(os.path.join(out, "tiny.pgm"))
image.convert("1").save(os.path.join(out, "tiny.pbm"))

rows = "\n".join(" ".join(f"{r} {g} {b}" for r, g, b in row) for row in PIXELS)
ascii_ppm = f"P3\n# written by scripts/make-netpbm-fixtures.py\n5 3\n255\n{rows}\n"
with open(os.path.join(out, "tiny.ppm-ascii"), "w", newline="\n", encoding="ascii") as handle:
    handle.write(ascii_ppm)

for name in ("tiny.ppm", "tiny.pgm", "tiny.pbm", "tiny.ppm-ascii"):
    path = os.path.join(out, name)
    print("made", name, os.path.getsize(path), "B", open(path, "rb").read(8))
