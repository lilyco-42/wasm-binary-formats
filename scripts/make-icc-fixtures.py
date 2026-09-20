#!/usr/bin/env python3
"""Write ICC profile fixtures with littleCMS (via Pillow) and print the rows a reader has to match.

An ICC profile is a big-endian fixed header over a tag table, and the file states its own length in
the first four bytes with `acsp` at 36 - the same "the size must close" shape as binary STL, which is
why both are only claimed when the arithmetic and the signature agree. littleCMS builds the profiles
from its own tables (`createProfile("sRGB")` is not a copy of a file), and it answers questions about
the result, so the class, colour space and the copyright text below are the writer's own reading of
bytes it produced.

Usage: temp/venv/Scripts/python.exe scripts/make-icc-fixtures.py
"""
import json
import os
import struct

from PIL import ImageCms

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MAX_TAGS = 48
INTENTS = {0: "perceptual", 1: "relative", 2: "saturation", 3: "absolute"}


def token(data, at):
    """Four-byte ICC signatures are space padded: `RGB ` and `RGB` are the same space."""
    raw = data[at : at + 4]
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "" for b in raw).strip()
    return text or "?"


def be(data, start, stop):
    return int.from_bytes(data[start:stop], "big")


def walk(data):
    if len(data) < 132 or data[36:40] != b"acsp":
        return None
    declared = be(data, 0, 4)
    # The version is two bytes, not one nibble pair: 04 40 is "4.4".
    major, minor = data[8], (data[9] >> 4) & 0xF
    tags = be(data, 128, 132)
    # Twelve bytes per record, and the whole table has to be in the file: past the real end there is
    # only payload, and reading that as a directory would invent rows.
    if 132 + tags * 12 > len(data):
        return None
    body = []
    listed = min(tags, MAX_TAGS)
    end = 132 + tags * 12
    outside = 0
    for index in range(listed):
        base = 132 + index * 12
        signature = token(data, base)
        offset, size = be(data, base + 4, base + 8), be(data, base + 8, base + 12)
        if offset + size > declared or offset < 128:
            # Counted, not followed: the bytes a wild pointer names are not part of this profile.
            outside += 1
        else:
            end = max(end, offset + size)
        body.append(
            "tag\t%d\t%s\tsig\t%s\tat\t%d\tlen\t%d"
            % (index, signature, token(data, offset), offset, size)
        )
    if tags > listed:
        body.append("cut\ttags\t%d" % tags)
    body.append(
        "table\ttags\t%d\tlisted\t%d\toutside\t%d\tdata_end\t%d\ttail\t%d"
        % (tags, listed, outside, end, max(0, declared - end))
    )
    # The header row is built last: it carries how many checks the walk ended up failing.
    broken = (declared != len(data)) + (132 + tags * 12 > declared) + bool(outside)
    head = [
        "icc\t%d\tdeclared\t%d\tbroken\t%d\tversion\t%d.%d\tcmm\t%s"
        % (
            len(data),
            declared,
            broken,
            major,
            minor,
            token(data, 4),
        ),
        "profile\tclass\t%s\tspace\t%s\tpcs\t%s\tintent\t%s\tcreator\t%s"
        % (
            token(data, 12),
            token(data, 16),
            token(data, 20),
            INTENTS.get(be(data, 64, 68), be(data, 64, 68)),
            token(data, 80),
        ),
    ]
    return head + body + ["walked\tend" if broken == 0 else "stopped\tbroken\t%d" % broken]


def main():
    built = {}
    for label, name in (("srgb.icc", "sRGB"), ("xyz.icc", "XYZ")):
        profile = ImageCms.ImageCmsProfile(ImageCms.createProfile(name))
        data = profile.tobytes()
        with open(os.path.join(OUT, label), "wb") as handle:
            handle.write(data)
        rows = walk(data)
        assert rows is not None, f"{label}: littleCMS wrote something without acsp"
        # littleCMS reading the same bytes back is the cross-check: its own idea of the profile's
        # name, copyright and colour space has to match what the header says.
        checked = ImageCms.getProfileName(profile).strip()
        space = ImageCms.getProfileCopyright(profile).strip()
        probe = {
            "bytes": len(data),
            "rows": rows,
            "profile_name": checked,
            "copyright": space,
            "pcs": ImageCms.getProfileName(profile).strip(),
        }
        built[label] = probe
        print("==", label, len(data), "bytes,", checked)
        for row in rows:
            print("   ", row.replace("\t", " | "))

    with open(os.path.join(OUT, "icc.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote test/fixtures/icc.probe.json for", ", ".join(sorted(built)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
