#!/usr/bin/env python3
"""Write the binary-plist fixtures with CPython's own writer, then read them back with a
hand-decoded walk and store what the walk measured.

`applebplist` has no Kaitai spec in the pinned bundle, so the only independent producer here is
`plistlib` (FMT_BINARY). Every fixture is dumped by that writer and never edited; the probe next to
it is produced by a decoder that reads the trailer and the offset table with `struct`, not by
`plistlib.loads`, so the numbers the Rust test asserts were measured off the bytes twice by two
different pieces of code before this repo claimed any of them.

    python3 scripts/make-plist-fixtures.py

Things plistlib will not write, and so not claimed by this repo's reader either: sets (0xB) and
ordered sets (0xC) - plistlib refuses a Python `set` outright - and the bplist15/bplist16 versions.
"""

import datetime
import json
import pathlib
import plistlib
import struct
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"

PLAIN = {
    "name": "apk-lens",
    "count": 42,
    "huge": 2**33,
    "neg": -7,
    "ratio": 0.5,
    "on": True,
    "off": False,
    "when": datetime.datetime(2001, 1, 1, 0, 0, 0),
    "later": datetime.datetime(2026, 9, 20, 2, 47, 12),
    "blob": b"\x89PNG\r\n\x1a\n",
    "utf": "h\u00e9llo\u4e16\u754c",
    "list": [1, 2, "three"],
    "range": list(range(20)),
    "nested": {"a": [True]},
}

# The shape every KeyedArchiver file on disk has: $top names an object by UID, $objects holds the
# graph, and the UIDs are the only reason a reader has to follow references instead of reading
# fields in order.
KEYED = {
    "$archiver": "NSKeyedArchiver",
    "$objects": [
        None,
        "NSSecureCoding",
        {"$class": plistlib.UID(4)},
        b"\x01\x02\x03\x04",
        {"$classname": "NSData", "$classes": [plistlib.UID(3)]},
    ],
    "$top": {"root": plistlib.UID(2)},
    "$version": 100000,
}

EMPTY = {}


def walk(data):
    """Decode the trailer and object table from the bytes, independently of plistlib."""
    trailer = data[-32:]
    offset_size, ref_size = trailer[6], trailer[7]
    num, top, table_at = struct.unpack(">QQQ", trailer[8:32])
    table_end = table_at + num * offset_size
    offsets = [
        int.from_bytes(data[table_at + i * offset_size : table_at + (i + 1) * offset_size], "big")
        for i in range(num)
    ]
    kinds = {}
    for offset in offsets:
        marker = data[offset]
        kinds[marker >> 4] = kinds.get(marker >> 4, 0) + 1
    return {
        "version": data[:8].decode("latin-1"),
        "file_length": len(data),
        "offset_size": offset_size,
        "ref_size": ref_size,
        "objects": num,
        "top": top,
        "table_at": table_at,
        "table_end": table_end,
        "offsets_monotonic": all(b > a for a, b in zip(offsets, offsets[1:])),
        "first_offset": offsets[0] if offsets else None,
        "high_nibbles": {str(k): v for k, v in sorted(kinds.items())},
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    probes = {}
    for name, value in [("tiny", PLAIN), ("keyed", KEYED), ("empty", EMPTY)]:
        data = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
        path = OUT / f"{name}.bplist"
        path.write_bytes(data)
        assert plistlib.loads(data) == value, f"{name}: plistlib cannot read its own output"
        probes[name] = {"length": len(data), **walk(data)}
        print(f"{name}.bplist {len(data)} bytes")
    (OUT / "plist.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(probes, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
