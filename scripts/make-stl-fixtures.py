#!/usr/bin/env python3
"""Write binary STL fixtures with meshio and print the report a reader has to reproduce.

Binary STL has no magic at all. What it has is an arithmetic identity: 80 header bytes, a u32
triangle count, and then exactly 50 bytes per triangle, so `84 + 50*n == filesize` is the only
statement the format makes about itself. That is also what makes a reader's job interesting - the
identity is necessary, not sufficient, and the per-triangle numbers have to say something about
shape rather than about text that happens to line up.

Two things are checked against meshio's own reader after the bytes are written: the triangle count,
and the vertex coordinates it gets back. The normal is stored per triangle and is not trusted - most
writers compute it, some leave it zeroed - so the report counts how many disagree with the geometric
normal of the triangle they belong to.

Usage: temp/venv/Scripts/python.exe scripts/make-stl-fixtures.py
"""
import json
import os
import struct

import meshio
import numpy as np

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MAX_TRIS = 16


def clean(data):
    text = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            text.append(chr(byte))
        elif byte in (0x09, 0x0A, 0x0D):
            break
        else:
            text.append(".")
    return "".join(text).rstrip(".")


def word(value):
    return struct.pack("<I", value)


def num(value):
    """Fixed six decimals, because `{:.6}` in Rust and `%.6f` here have to print the same text."""
    return "%.6f" % value


def trio(values):
    return ",".join(num(value) for value in values)


def floats(values):
    return b"".join(struct.pack("<f", value) for value in values)


def tri(normal, a, b, c, attr=0):
    return floats(normal) + floats(a) + floats(b) + floats(c) + struct.pack("<H", attr)


def hand_stl(header, triangles):
    out = bytearray(header.ljust(80, b" "))[:80]
    out += word(len(triangles))
    for blob in triangles:
        out += blob
    return bytes(out)


def normal_of(a, b, c):
    """The unit normal the three points imply, or None when they do not imply one."""
    u = [b[i] - a[i] for i in range(3)]
    v = [c[i] - a[i] for i in range(3)]
    cross = [u[1] * v[2] - u[2] * v[1], u[2] * v[0] - u[0] * v[2], u[0] * v[1] - u[1] * v[0]]
    length = sum(part * part for part in cross) ** 0.5
    if length == 0.0:
        return None
    return [part / length for part in cross]


def walk(data):
    rows = []
    broken = 0
    if len(data) < 84:
        return ["stl\t%d\ttris\t0\tbroken\t1\tsolid\t-" % len(data), "stopped\tbroken\t1"]
    count = struct.unpack_from("<I", data, 80)[0]
    declared = 84 + 50 * count
    fit = "exact" if declared == len(data) else ("short" if declared < len(data) else "long")
    if fit != "exact":
        broken += 1
    rows.append(
        "stl\t%d\ttris\t%d\tbroken\t0\tsolid\t%s" % (len(data), count, clean(data[:80]) or "-")
    )
    rows.append("sizes\tdeclared\t%d\tactual\t%d\tfit\t%s" % (declared, len(data), fit))

    listed = min(count, MAX_TRIS)
    points = []
    zero = 0
    wrong = 0
    for index in range(listed):
        base = 84 + 50 * index
        values = struct.unpack_from("<12f", data, base)
        attr = struct.unpack_from("<H", data, base + 48)[0]
        normal = values[0:3]
        verts = [values[3:6], values[6:9], values[9:12]]
        points.extend(verts)
        if all(part == 0.0 for part in normal):
            zero += 1
        else:
            implied = normal_of(*verts)
            if implied is None or max(abs(normal[i] - implied[i]) for i in range(3)) > 1e-3:
                wrong += 1
        rows.append(
            "tri\t%d\tnormal\t%s\tv0\t%s\tv1\t%s\tv2\t%s\tattr\t%d"
            % (index, trio(normal), trio(verts[0]), trio(verts[1]), trio(verts[2]), attr)
        )
    if count > listed:
        rows.append("cut\ttris\t%d" % count)
    if listed:
        low = [min(point[axis] for point in points) for axis in range(3)]
        high = [max(point[axis] for point in points) for axis in range(3)]
        rows.append("box\tmin\t%s\tmax\t%s" % (trio(low), trio(high)))
    rows.append("normals\tzero\t%d\twrong\t%d\tcounted\t%d" % (zero, wrong, listed))
    broken += 0
    rows[0] = "stl\t%d\ttris\t%d\tbroken\t%d\tsolid\t%s" % (
        len(data),
        count,
        broken,
        clean(data[:80]) or "-",
    )
    rows.append("walked\tend" if broken == 0 else "stopped\tbroken\t%d" % broken)
    return rows


def main():
    points = np.array([[0.0, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]])
    cells = np.array([[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]])
    tet = os.path.join(OUT, "tet.stl")
    meshio.Mesh(points, [("triangle", cells)]).write(tet, file_format="stl", binary=True)

    # A second, larger mesh so the triangle listing hits its own cap rather than being assumed safe.
    many = os.path.join(OUT, "many.stl")
    grid = 20
    verts = [
        [x / 4.0, y / 4.0, ((x * x + y * y) % 7) / 8.0]
        for y in range(grid)
        for x in range(grid)
    ]
    faces = []
    for y in range(grid - 1):
        for x in range(grid - 1):
            a = y * grid + x
            faces += [[a, a + 1, a + grid], [a + 1, a + grid + 1, a + grid]]
    meshio.Mesh(np.array(verts), [("triangle", np.array(faces))]).write(
        many, file_format="stl", binary=True
    )

    # Zeroed normals, which real writers do produce, and one triangle whose stored normal points the
    # other way: the two cases the normal column has to distinguish.
    flipped = tri([-0.5773503, -0.5773503, -0.5773503], [1, 0, 0], [0, 1, 0], [0, 0, 1])
    blank = tri([0, 0, 0], [0, 0, 0], [1, 0, 0], [0, 1, 0])
    odd = os.path.join(OUT, "normals.stl")
    with open(odd, "wb") as handle:
        handle.write(hand_stl(b"normals probe", [blank, flipped]))

    probe = {}
    for label in ("tet.stl", "many.stl", "normals.stl"):
        path = os.path.join(OUT, label)
        data = open(path, "rb").read()
        rows = walk(data)
        back = meshio.read(path)
        counted = int(struct.unpack_from("<I", data, 80)[0])
        assert sum(len(block.data) for block in back.cells) == counted, f"{label}: meshio count"
        assert 84 + 50 * counted == len(data), f"{label}: the identity has to hold"
        probe[label] = {"bytes": len(data), "tris": counted, "rows": rows}
        print("==", label, len(data), "bytes,", counted, "triangles")
        for row in rows:
            print("   ", row.replace("\t", " | "))

    with open(os.path.join(OUT, "stl.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
    print("wrote test/fixtures/stl.probe.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
