#!/usr/bin/env python3
"""Write the two EMF fixtures and print the rows a reader has to reproduce.

An EMF is a header record followed by a flat list of `u32 type, u32 size` records, and the format's
whole self-description is arithmetic: the header states the byte count and the record count, and the
same rectangle is written three times - in device units, in hundredths of a millimetre, and as a
pixels/mm pair whose ratio is the resolution that turns one into the other.

Two producers, deliberately, because one file cannot tell a rule from a habit:

  * `page.emf` - LibreOffice, given an 8x8 PNG. Draw imports the bitmap onto a default page, so the
    extents describe A4-ish page rather than the picture, and Pillow's GDI-backed opener reports the
    header's bounds as the image size, which is the external check on those four integers.
  * `gdi.emf` - Windows' own GDI (`CreateEnhMetaFileW` / `Rectangle` / `Ellipse` / `TextOutW` /
    `CloseEnhMetaFile` through ctypes), so the second file is written by the implementation the format
    is specified for.

What the two disagree about is recorded rather than smoothed over: GDI's record count matches the walk,
LibreOffice's is one short of it - the header record - so the reader prints both numbers side by side
and claims neither. And the resolutions differ (a screen at ~162 DPI against a page at 120), which is
why the dpi comes out of the pair rather than from a table.

One caveat for whoever regenerates these: GDI stamps the *host's* screen size and resolution into the
device pair, so `gdi.emf` is only byte-identical on a 1920x1200 @ ~162 dpi display. The committed bytes
are the fixture of record - `engine/tests/emf.rs` asserts those, and CI reads what is committed rather
than running this script - and a regeneration elsewhere is expected to move `device`/`dpi` and nothing
else.

Usage: temp/venv/Scripts/python.exe scripts/make-emf-fixtures.py
"""
import ctypes
import json
import os
import struct
import subprocess
import sys

from PIL import Image

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "emf-work"))
SOFFICE = r"C:\Program Files\LibreOffice\program\soffice.exe"
SIGNATURE = 0x464D4520  # the bytes ' EMF'
LISTED = 24


def u32(data, at):
    return int.from_bytes(data[at : at + 4], "little")


def walk(data):
    """(records, bytes walked, reached the end) - record zero is the header, and its own size is the
    step, which is what a player does and what makes a lying header show up as a broken walk."""
    at = 0
    records = []
    while at + 8 <= len(data):
        kind, size = u32(data, at), u32(data, at + 4)
        if size < 8 or at + size > len(data):
            return records, at, False
        records.append((kind, size, at))
        at += size
    return records, at, at == len(data)


def gdi_metafile(path):
    gdi = ctypes.windll.gdi32
    hdc = gdi.CreateEnhMetaFileW(None, path, None, None)
    if not hdc:
        raise SystemExit("CreateEnhMetaFileW failed")
    gdi.Rectangle(hdc, 4, 4, 60, 40)
    gdi.Ellipse(hdc, 10, 10, 50, 30)
    gdi.TextOutW(hdc, 8, 8, "emf probe", 9)
    handle = gdi.CloseEnhMetaFile(hdc)
    if not handle:
        raise SystemExit("CloseEnhMetaFile failed")
    gdi.DeleteEnhMetaFile(handle)


def libreoffice_metafile(png, out):
    made = subprocess.run(
        [SOFFICE, "--headless", "--convert-to", "emf:draw_emf_Export", "--outdir", out, png],
        capture_output=True,
        text=True,
    )
    path = os.path.join(out, os.path.splitext(os.path.basename(png))[0] + ".emf")
    if not os.path.exists(path):
        raise SystemExit(f"LibreOffice wrote no EMF: {made.stdout} {made.stderr}")
    return path


def rows_for(data):
    """The reader's own arithmetic, mirrored - so the assertions are computed, not transcribed."""
    n_size = u32(data, 4)
    bounds = struct.unpack_from("<4i", data, 8)
    frame = struct.unpack_from("<4i", data, 24)
    n_bytes = u32(data, 48)
    claimed = u32(data, 52)
    records, reached, complete = walk(data)
    px = (u32(data, 72), u32(data, 76))
    mm = (u32(data, 80), u32(data, 84))
    dpi = "" if min(mm) == 0 else "{:.2f}".format(px[0] * 25.4 / mm[0])
    broken = (n_bytes != len(data)) + (0 if complete else 1)
    version = u32(data, 44)
    rows = [
        "emf\t{}\tbroken\t{}\tversion\t{}.{}\tnsize\t{}\trecords\t{}\twalked\t{}".format(
            len(data),
            broken,
            version >> 16,
            version & 0xFFFF,
            n_size,
            claimed,
            len(records),
        )
    ]
    rows.append(
        "bounds\t{}\t{}\t{}\t{}\twh\t{}x{}".format(
            *bounds, bounds[2] - bounds[0], bounds[3] - bounds[1]
        )
    )
    rows.append(
        "frame\t{}\t{}\t{}\t{}\tmm\t{}x{}".format(
            *frame,
            "{:.2f}".format((frame[2] - frame[0]) / 100),
            "{:.2f}".format((frame[3] - frame[1]) / 100),
        )
    )
    rows.append("device\tpx\t{}x{}\tmm\t{}x{}\tdpi\t{}".format(px[0], px[1], mm[0], mm[1], dpi))
    for index, (kind, size, at) in enumerate(records[:LISTED]):
        rows.append("record\t{}\ttype\t{}\tsize\t{}".format(index, kind, size))
    if len(records) > LISTED:
        rows.append("cut\trecords\t{}".format(len(records)))
    kinds = sorted(set(kind for kind, _, _ in records))
    rows.append(
        "types\tcounted\t{}\tdistinct\t{}\tlast\t{}".format(
            len(records), len(kinds), records[-1][0] if records else -1
        )
    )
    rows.append("walked\tend" if complete else "stopped\tat\t{}".format(reached))
    return rows


def check(name, data):
    assert u32(data, 0) == 1, f"{name}: first record is not the header"
    assert u32(data, 40) == SIGNATURE, f"{name}: no ' EMF' signature at 40"
    assert u32(data, 48) == len(data), f"{name}: header byte count {u32(data, 48)} != {len(data)}"
    records, reached, complete = walk(data)
    assert complete, f"{name}: record walk stopped at {reached} of {len(data)}"
    bounds = struct.unpack_from("<4i", data, 8)
    return bounds, records


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    built = {}

    png = os.path.join(SCRATCH, "dot.png")
    Image.new("RGB", (8, 8), (200, 10, 10)).save(png)
    made = libreoffice_metafile(png, SCRATCH)
    page = open(made, "rb").read()
    with open(os.path.join(OUT, "page.emf"), "wb") as handle:
        handle.write(page)

    gdi_path = os.path.join(SCRATCH, "gdi.emf")
    if os.path.exists(gdi_path):
        os.remove(gdi_path)
    gdi_metafile(gdi_path)
    gdi_bytes = open(gdi_path, "rb").read()
    with open(os.path.join(OUT, "gdi.emf"), "wb") as handle:
        handle.write(gdi_bytes)

    for label, data in (("page.emf", page), ("gdi.emf", gdi_bytes)):
        path = os.path.join(OUT, label)
        bounds, records = check(label, data)
        # Pillow's EMF support is GDI's own: the size it reports is the header's bounds read back by
        # the operating system, which is what puts those four integers outside this repo's arithmetic.
        seen = Image.open(path)
        seen.load()
        want = (bounds[2] - bounds[0], bounds[3] - bounds[1])
        if seen.size != want:
            raise SystemExit(f"{label}: GDI reports {seen.size}, header bounds say {want}")
        rows = rows_for(data)
        print("==", label, len(data), "bytes", seen.size, "GDI size agrees with bounds")
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {"bytes": len(data), "gdiSize": list(seen.size), "rows": rows}

    with open(os.path.join(OUT, "emf.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote page.emf, gdi.emf and emf.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
