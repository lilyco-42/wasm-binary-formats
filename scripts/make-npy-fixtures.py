#!/usr/bin/env python3
"""Write the `.npy` fixtures with numpy's own writer, and record what the header says versus what
numpy computes.

    temp/venv/Scripts/python.exe scripts/make-npy-fixtures.py

`npy` has no Kaitai spec in the pinned bundle, and the producer here is the library that invented the
format: `numpy.save` writes the file, and the probe next to the fixtures records `arr.nbytes` and
`arr.dtype.itemsize` for it. That matters because the two numbers a reader can get wrong are exactly
the two a header does not state: the item size (it is spelled `'<f8'`, `'|S4'`, `'<U4'`, or a whole
nested list of fields) and the element count (a shape tuple, including the empty tuple for a scalar).
Their product has to equal the bytes after the header, so `nbytes` from numpy is the outside witness
for the arithmetic this repo's reader does.

Header widths are per version, and that is read off the files rather than assumed: version 1 keeps the
header length in a little-endian u16 after the eight signature bytes, versions 2 and 3 in a u32.
Version 3 also writes the field names as UTF-8, which the probe keeps verbatim so a reader that
assumed latin-1 cannot pass unnoticed.
"""

import json
import pathlib
import sys

import numpy as np

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"


def describe(name, array, **write):
    path = OUT / name
    if write:
        np.lib.format.write_array(path.open("wb"), array, **write)
    else:
        np.save(path, array)
    data = path.read_bytes()
    major, minor = data[6], data[7]
    width = 2 if major == 1 else 4
    header_len = int.from_bytes(data[8 : 8 + width], "little")
    header_at = 8 + width
    header = data[header_at : header_at + header_len].decode("latin-1")
    assert header.startswith("{") and header.rstrip(" \n").endswith("}"), f"{name}: odd header"
    reloaded = np.load(path)
    assert reloaded.shape == array.shape, f"{name}: numpy cannot read the shape back"
    probe = {
        "length": len(data),
        "version": [major, minor],
        "header_len": header_len,
        "header_at": header_at,
        "data_at": header_at + header_len,
        "header": header.rstrip(" \n"),
        "descr": array.dtype.descr if array.dtype.fields else array.dtype.str,
        "itemsize": array.dtype.itemsize,
        "shape": list(array.shape),
        "fortran_order": bool(array.flags.f_contiguous and len(array.shape) > 1),
        "nbytes": int(array.nbytes),
        "data_bytes": len(data) - (header_at + header_len),
    }
    assert probe["nbytes"] == probe["data_bytes"], f"{name}: numpy's size is not the file's size"
    print(f"{name}: v{major}.{minor} {probe['descr']} {array.shape} -> {probe['data_bytes']} bytes")
    return probe


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    probes = {
        "f64": describe("f64.npy", np.arange(6, dtype="<f8")),
        "i32": describe("i32.npy", np.arange(12, dtype=">i4").reshape(3, 4)),
        "uint16": describe("uint16.npy", np.asfortranarray(np.arange(6, dtype="<u2").reshape(2, 3))),
        "scalar": describe("scalar.npy", np.array(3.5)),
        "bools": describe("bools.npy", np.array([True, False, True])),
        "bytes4": describe("bytes4.npy", np.array(["ab", "cd"], dtype="S4")),
        "unicode": describe("unicode.npy", np.array(["ab", "cd"], dtype="U4")),
        "v2": describe(
            "v2.npy",
            np.zeros((3, 4), dtype=[("alpha", "f4"), ("beta", "i1"), ("gamma", "<f8")]),
            version=(2, 0),
        ),
        "v3": describe(
            "v3.npy",
            np.zeros((2, 2), dtype=[("unicode", "<U4")]),
            version=(3, 0),
        ),
    }
    (OUT / "npy.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
