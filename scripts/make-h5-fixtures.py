#!/usr/bin/env python3
"""Write the HDF5 fixtures with h5py, twice, so the two superblock generations are both real.

    temp/venv/Scripts/python.exe scripts/make-h5-fixtures.py

`h5` has no Kaitai spec in the pinned bundle. h5py 3.16 (HDF5 2.0 in this build) writes it, and
`libver` selects the *superblock generation*: `earliest` gives the old v0 layout with its symbol
table, local heap and v1 B-tree, `latest` gives v3 with object-header v2 messages and link messages.
Both files are opened again by h5py before being committed, and their contents checked.

What the probe records is deliberately positional rather than declarative. The v0 and v3 layouts
differ in where things sit, and a reader written from a remembered field table gets them mixed up -
so this script searches each file for the little-endian 64-bit values that are *known from outside*
the format: the file's own length, and the addresses that hold a four-byte structure tag. Those hits
are what `engine/tests/h5.rs` asserts, which is also why the reader reports a pointer together with
the tag it lands on instead of naming superblock fields one by one.
"""

import json
import pathlib
import sys

import h5py
import numpy as np

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"
TAGS = (b"TREE", b"HEAP", b"SNOD", b"SOMF", b"OHDR", b"OCHK", b"GCOL", b"LNGT", b"FREE")


def build(name, libver):
    path = OUT / name
    with h5py.File(path, "w", libver=libver) as book:
        book.create_dataset("numbers", data=np.arange(10, dtype="<f8"))
        group = book.create_group("sub")
        group.attrs["note"] = "hi"
        group.create_dataset("small", data=np.array([1, 2, 3], dtype="<i4"))
    data = path.read_bytes()
    with h5py.File(path, "r") as book:
        assert list(book.keys()) == ["numbers", "sub"], name
        assert book["numbers"][:].tolist() == list(range(10)), name
        assert book["sub"]["small"][:].tolist() == [1, 2, 3], name
        assert book["sub"].attrs["note"] == "hi", name
    return data


def probe(name, data):
    version, at = data[8], 8
    offset_size, length_size = (data[13], data[14]) if version == 0 else (data[9], data[10])
    slots, pointers = [], []
    while at + 8 <= min(len(data), 128):
        value = int.from_bytes(data[at : at + 8], "little")
        if value == len(data):
            slots.append({"at": at, "value": value, "means": "file length"})
        elif 8 <= value + 4 <= len(data) and data[value : value + 4] in TAGS:
            pointers.append({"at": at, "value": value, "tag": data[value : value + 4].decode()})
        at += 4
    return {
        "length": len(data),
        "version": version,
        "offset_size": offset_size,
        "length_size": length_size,
        "eof_slots": slots,
        "pointers": pointers,
        "first_bytes": data[:48].hex(" "),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    probes = {}
    for stem, libver in (("tree-v0", "earliest"), ("links-v3", "latest")):
        data = build(f"{stem}.h5", libver)
        probes[stem] = probe(f"{stem}.h5", data)
        print(
            f"{stem}.h5: {len(data)} bytes, superblock v{data[8]}, "
            f"{len(probes[stem]['pointers'])} pointers, eof at "
            f"{[slot['at'] for slot in probes[stem]['eof_slots']]}"
        )
    (OUT / "h5.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(probes, indent=1, sort_keys=True)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
