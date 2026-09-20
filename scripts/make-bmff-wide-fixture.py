#!/usr/bin/env python3
"""Write `test/fixtures/wide.mov`: the MOV whose two 64-bit fields nothing else here carries.

ISO base-media boxes state their length in a 32-bit slot, and `1` in that slot means "the real length
is the 64-bit one that follows the type". `mvhd` version 1 does the same widening to its time fields.
Both are read big-endian - and both were read little-endian here, which no fixture in the tree could
show, because an ordinary file has neither. This one is built by hand for exactly that reason, so the
two witnesses below are what makes it more than a self-assertion:

  * `mutagen.mp4.Atom` (GPL-2.0+, installed) parses the same bytes with `struct.unpack(">Q", ...)` at
    box start + 8 and rejects a 64-bit length below 16 - an independent implementation of the rule,
    which is asked for the number the reader has to print.
  * `ffprobe` reports the `creation_time` that lives in the version-1 `mvhd`, so a 64-bit big-endian
    slot 12 bytes before the timescale is read the same way by a second program.

The byte order is then *proved to matter* rather than assumed: the same file with the 64-bit lengths
byte-swapped is handed to mutagen too, and if the two readings did not differ there would be no point
in the fixture.

Usage: temp/venv/Scripts/python.exe scripts/make-bmff-wide-fixture.py
"""
import json
import os
import struct
import subprocess
import sys

from mutagen.mp4 import Atom, AtomError

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MATRIX = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
# 2024-01-01T00:00:00 in unix seconds, and QuickTime stamps count from 1904-01-01.
STAMP = 1704067200 + 2082816000
TIMESCALE = 44100
DURATION = 110250  # 2.5 seconds, and a value whose two byte orders are nowhere near each other


def box(kind, body, wide=False):
    """A box, with the size-1 form when `wide` asks for the 64-bit length.

    The order inside the header is size, then type, then the 64-bit length - which is the one detail
    of this fixture that mutagen's own reader settled rather than memory.
    """
    if wide:
        return struct.pack(">I4sQ", 1, kind, 16 + len(body)) + body
    return struct.pack(">I4s", 8 + len(body), kind) + body


def mvhd_v1():
    tail = (
        struct.pack(">IHH", 0x00010000, 0x0100, 0)
        + b"\0" * 8
        + MATRIX
        + b"\0" * 24
        + struct.pack(">I", 2)
    )
    body = (
        struct.pack(">B3s", 1, b"\0\0\0")
        + struct.pack(">QQ", STAMP, STAMP)
        + struct.pack(">IQ", TIMESCALE, DURATION)
        + tail
    )
    made = box(b"mvhd", body)
    assert len(made) == 120, len(made)
    return made


def build(swapped=False):
    """The file, or the same file with both 64-bit lengths reversed - which is what an
    accidentally little-endian reader would be asking for."""
    atoms = [
        box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isom"),
        box(b"moov", mvhd_v1()),
        box(b"mdat", b"\x5a" * 32, wide=True),
    ]
    data = b"".join(atoms)
    if swapped:
        data = swap_64(data)
    return data


def swap_64(data):
    """Reverse the 8 bytes of the mdat length and the 8 bytes of the mvhd duration."""
    mdat = data.rfind(b"mdat") - 4  # the box starts four bytes before the type field names it
    out = bytearray(data)
    out[mdat + 8 : mdat + 16] = data[mdat + 8 : mdat + 16][::-1]
    mvhd = data.find(b"mvhd")
    # `mvhd` names the type field, which is four bytes into the box; the version byte follows it, then
    # the two 64-bit stamps and the 32-bit timescale, so the duration starts 28 bytes along.
    at = mvhd + 28
    out[at : at + 8] = data[at : at + 8][::-1]
    return bytes(out)


def mutagen_lengths(path):
    """The atom tree mutagen itself computes from the file: name -> (length, offset)."""
    seen = {}
    with open(path, "rb") as handle:

        def walk(level=0):
            while True:
                here = handle.tell()
                try:
                    atom = Atom(handle, level)
                except (AtomError, EOFError):
                    return
                seen[atom.name.decode("latin1")] = (atom.length, atom.offset)
                handle.seek(atom.offset + atom.length)
                if handle.tell() >= os.path.getsize(path):
                    return

        walk()
    return seen


def probe_ffprobe(path):
    out = subprocess.run(
        ["ffprobe", "-hide_banner", "-show_format", "-of", "ini", path],
        capture_output=True,
        text=True,
    )
    for line in out.stdout.splitlines():
        if "creation_time" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"ffprobe gave no creation_time for {path}: {out.stderr[:200]}")


def walk(data):
    """A private mirror of the reader's own walk, so the rows are computed and not transcribed."""
    rows = [
        "ftyp\t%s\t%d" % (data[8:12].decode("latin1"), int.from_bytes(data[12:16], "big")),
    ]
    at = 16
    first = int.from_bytes(data[0:4], "big")
    while at + 4 <= first:
        rows.append("brand\t%s" % data[at : at + 4].decode("latin1"))
        at += 4
    cursor = 0
    while cursor + 8 <= len(data):
        size = int.from_bytes(data[cursor : cursor + 4], "big")
        header = 8
        if size == 1:
            size = int.from_bytes(data[cursor + 8 : cursor + 16], "big")
            header = 16
        elif size == 0:
            size = len(data) - cursor
        kind = data[cursor + 4 : cursor + 8].decode("latin1")
        rows.append("box\t%s\t%d\t%d%s" % (kind, size, cursor, "\twide" if header == 16 else ""))
        if kind == "moov":
            inner = cursor + 8
            limit = min(cursor + size, len(data))
            while inner + 8 <= limit:
                inner_size = int.from_bytes(data[inner : inner + 4], "big")
                inner_header = 8
                if inner_size == 1:
                    inner_size = int.from_bytes(data[inner + 8 : inner + 16], "big")
                    inner_header = 16
                elif inner_size == 0:
                    inner_size = limit - inner
                inner_kind = data[inner + 4 : inner + 8].decode("latin1")
                rows.append(
                    "child\t%s\t%d\t%d%s"
                    % (inner_kind, inner_size, inner, "\twide" if inner_header == 16 else "")
                )
                if inner_kind == "mvhd":
                    version = data[inner + 8]
                    if version == 1:
                        timescale = int.from_bytes(data[inner + 28 : inner + 32], "big")
                        duration = int.from_bytes(data[inner + 32 : inner + 40], "big")
                    else:
                        timescale = int.from_bytes(data[inner + 20 : inner + 24], "big")
                        duration = int.from_bytes(data[inner + 24 : inner + 28], "big")
                    rows.append(
                        "duration\t%d\t%d\t%d"
                        % (timescale, duration, duration * 1000 // timescale)
                    )
                if inner_size < 8 or inner + inner_size > limit:
                    break
                inner += inner_size
        if size < 8 or cursor + size > len(data):
            break
        cursor += size
    if cursor == len(data):
        rows.append("walked\tend")
    return rows


def main():
    data = build()
    path = os.path.join(OUT, "wide.mov")
    with open(path, "wb") as handle:
        handle.write(data)

    rows = walk(data)
    print("== wide.mov", len(data), "bytes")
    for row in rows:
        print("   ", row.replace("\t", " | "))

    # Witness one: mutagen, reading the same bytes, has to arrive at the same 64-bit length.
    lengths = mutagen_lengths(path)
    print("== mutagen", lengths)
    if lengths.get("mdat") != (48, len(data) - 48):
        raise SystemExit(f"mutagen disagrees about the 64-bit box: {lengths}")

    # Witness two: the byte order has to be a real question, not a formality.
    swapped = os.path.join(OUT, "..", "..", "temp", "wide-swapped.mov")
    with open(swapped, "wb") as handle:
        handle.write(build(swapped=True))
    wrong = mutagen_lengths(swapped)
    if wrong.get("mdat") == lengths.get("mdat"):
        raise SystemExit("swapping the 64-bit length changed nothing, so nothing was proved")
    print("== mutagen on the byte-swapped file:", wrong.get("mdat"), "(reader must not agree)")

    stamp = probe_ffprobe(path)
    print("== ffprobe creation_time:", stamp)
    if "2023-12-31" not in stamp and "2024-01-01" not in stamp:
        raise SystemExit(f"ffprobe did not read the version-1 64-bit stamp: {stamp}")

    with open(os.path.join(OUT, "wide.probe.json"), "w", encoding="utf8") as handle:
        json.dump(
            {
                "bytes": len(data),
                "rows": rows,
                "mutagen": {k: list(v) for k, v in sorted(lengths.items())},
                "mutagen_swapped": {k: list(v) for k, v in sorted(wrong.items())},
                "ffprobe_creation_time": stamp,
                "timescale": TIMESCALE,
                "duration": DURATION,
            },
            handle,
            indent=1,
            sort_keys=True,
        )
    print("wrote test/fixtures/wide.mov and wide.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
