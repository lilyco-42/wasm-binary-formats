#!/usr/bin/env python3
"""Write the two PostScript fixtures and print the rows a reader has to reproduce.

PostScript claims nothing in its first bytes - it claims a line: `%!PS-Adobe-3.0`, and then a run of
`%%Key: value` document comments whose only job is to describe the file to whoever prints it without
running it. Two properties make it worth reading structurally rather than as text: the header can be
buried behind a preview, and the page count is a *claim* that a producer can get wrong.

Both cases are here, from two writers:

  * `preview.eps` - LibreOffice, given a 2x2 PNG through `draw_eps_Export`. The file opens with a
    binary preview header: four magic bytes, then two little-endian words at 20 and 24 that are the
    header's own size (30) and the preview's length - and their sum is exactly where
    `%!PS-Adobe-3.0` starts. That arithmetic is the only claim available here: the sixteen bytes
    between the magic and those two words are not the same in the samples looked at (one spells `TK`,
    the other a length), so they go out as hex and are named nothing.
  * `plain.ps` - ImageMagick's own PostScript writer, so `%!` is at byte 0 and no preview exists. Its
    `%%Title` and `%%CreationDate` carry the host path and the moment of writing, which is why the
    committed bytes - not a regeneration - are what the tests read.

And the disagreement both are kept: LibreOffice states `%%Pages: 0` for a file that carries one
`%%Page: 1 1`, while ImageMagick states `%%Pages: 1` for one page. So the reader prints the claim next
to the count of `%%Page:` comments and calls neither wrong - the same shape as the PDF `/Count` row and
the EMF record count.

Usage: temp/venv/Scripts/python.exe scripts/make-ps-fixtures.py
"""
import json
import os
import struct
import subprocess
import sys

from PIL import Image

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "ps-work"))
SOFFICE = r"C:\Program Files\LibreOffice\program\soffice.exe"
MAGICK = r"C:\Program Files\ImageMagick-7.1.2-Q16-HDRI\magick.exe"
LISTED = 32
TK = bytes.fromhex("c5d0d3c6")


def preview_span(data):
    """(header size, preview length, offset of the PostScript, the bytes between) or None.

    The magic is four bytes at 0 and two little-endian words at 20 and 24 - a header length and a
    preview length - and what makes them nameable is that their sum is exactly where `%!` begins. The
    bytes between the magic and those words differ between writers (LibreOffice spells `TK` in one
    sample and a length in another), so they are carried out as hex and given no field name.
    """
    if len(data) < 28 or data[:4] != TK:
        return None
    header, length = struct.unpack_from("<II", data, 20)
    start = header + length
    if not data.startswith(b"%!", start):
        return None
    return header, length, start, data[4:20]


def comments(data, start):
    """The `%%Key: value` pairs and the bare structural markers, in file order."""
    keyed = []
    structural = 0
    for line in data[start:].split(b"\n"):
        line = line.rstrip(b"\r")
        if not line.startswith(b"%%"):
            continue
        text = line[2:].decode("latin1").rstrip()
        if text.startswith("EOF"):
            continue
        head, sep, tail = text.partition(":")
        if sep and " " not in head.strip():
            keyed.append((head.strip(), tail.strip()))
        else:
            structural += 1
    return keyed, structural


def rows_for(data):
    start = 0
    pre = preview_span(data)
    if pre:
        start = pre[2]
    line_end = data.find(b"\n", start)
    banner = data[start : len(data) if line_end < 0 else line_end]
    banner = banner.decode("latin1").rstrip()
    if not banner.startswith("%!"):
        return None
    keyed, structural = comments(data, start)
    tail = data.rstrip()
    has_eof = tail.endswith(b"%%EOF")

    def number(text, index):
        try:
            return int(text.split()[index], 10)
        except (ValueError, IndexError):
            return None

    box = [value for key, value in keyed if key == "BoundingBox"]
    bounds = number(box[0], 0) if box else None
    pages = [int(value) for key, value in keyed if key == "Pages" and value.lstrip("-").isdigit()]
    found = sum(1 for key, _ in keyed if key == "Page")
    broken = (0 if has_eof else 1) + (1 if box and bounds is None else 0)

    rows = [
        "ps\t{}\tbroken\t{}\tpreview\t{}\tstart\t{}\tdsc\t{}".format(
            len(data), broken, "yes" if pre else "none", start, banner[2:]
        )
    ]
    if pre:
        rows.append(
            "preview\theader\t{}\tdata\t{}\tto\t{}\tbytes\t{}".format(
                pre[0], pre[1], pre[2], pre[3].hex()
            )
        )
    if box and bounds is not None:
        parts = box[0].split()
        left, bottom, right, top = (int(p) for p in parts[:4])
        rows.append(
            "bounds\t{}\t{}\t{}\t{}\twh\t{}x{}".format(
                left, bottom, right, top, right - left, top - bottom
            )
        )
    rows.append("pages\tclaimed\t{}\tfound\t{}".format(pages[0] if pages else "absent", found))
    for index, (key, value) in enumerate(keyed[:LISTED]):
        rows.append("comment\t{}\t{}\t{}".format(index, key, value if value else "-"))
    if len(keyed) > LISTED:
        rows.append("cut\tcomments\t{}".format(len(keyed)))
    rows.append(
        "comments\tcounted\t{}\tstructural\t{}\tlines\t{}\tcrlf\t{}\teof\t{}".format(
            len(keyed),
            structural,
            data.count(b"\n"),
            data.count(b"\r\n"),
            data.rfind(b"%%EOF"),
        )
    )
    rows.append("walked\tend" if has_eof else "stopped\tno\teof")
    return rows


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    png = os.path.join(SCRATCH, "tiny.png")
    Image.new("RGB", (2, 2), (10, 200, 30)).save(png)

    built = {}
    made = subprocess.run(
        [SOFFICE, "--headless", "--convert-to", "eps:draw_eps_Export", "--outdir", SCRATCH, png],
        capture_output=True,
        text=True,
    )
    eps = os.path.join(SCRATCH, "tiny.eps")
    if not os.path.exists(eps):
        raise SystemExit(f"LibreOffice wrote no EPS: {made.stdout} {made.stderr}")
    # Run from the scratch directory with a bare file name: ImageMagick writes the path it was given
    # into %%Title, and an absolute path here would only end up committed as a fixture's comment.
    subprocess.run(
        [MAGICK, "tiny.png", "plain.ps"], check=True, capture_output=True, cwd=SCRATCH
    )

    for label, source in (("preview.eps", eps), ("plain.ps", os.path.join(SCRATCH, "plain.ps"))):
        data = open(source, "rb").read()
        rows = rows_for(data)
        if rows is None:
            raise SystemExit(f"{label}: no %! banner where the file says it should be")
        with open(os.path.join(OUT, label), "wb") as handle:
            handle.write(data)
        print("==", label, len(data), "bytes")
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {"bytes": len(data), "rows": rows}

    with open(os.path.join(OUT, "ps.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote preview.eps, plain.ps and ps.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
