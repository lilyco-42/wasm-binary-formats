#!/usr/bin/env python3
"""Write the .torrent fixtures with `bencode.py`, and record what that library reads back from them.

`torrent` is one of magika's 219 binary labels (`application/x-bittorrent`), and its container format -
bencode - is the third one here that checks itself with lengths rather than with a magic: every string
carries its own byte count, every list and dict ends with `e`, so a walk either lands exactly on the end
of the file or the file is broken, and there is no third answer. Two of the format's rules are therefore
things a reader can demand rather than assume, and both are what these fixtures are for:

  * `pieces` is a flat string of 20-byte SHA-1 hashes, so its length has to divide by 20;
  * BEP-3 says dict keys are sorted by their raw byte values, so an unsorted dict is a defect in the
    file, not in the reader.

`bencode.py` is both the producer and the witness - it writes the bytes and decodes them again, and the
probe records what it gets back (root keys, how many values the decoded tree holds and how deep it goes,
each value's type, the `info` keys, the length of `pieces`). That is one library agreeing with itself
about *encoding*, which is weaker than the FreeType/psd-tools pairs elsewhere in this repo, so the claim
is kept to what the lengths alone can prove: the reader reports structure, and no row prints a hash, a
name it did not have to, or a byte it cannot show safely.

Two fixtures rather than one because the format has two shapes: a single-file `info` with `length`, and a
multi-file one with a `files` list whose entries each carry a `path` list.

Usage: temp/venv/Scripts/python.exe scripts/make-torrent-fixtures.py
"""
import json
import os
import sys

import bencode

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "torrent-work"))
PIECE = bytes(range(0, 20))
TRACKER = b"udp://tracker.example.invalid:1337/announce"


def single():
    return {
        b"announce": TRACKER,
        b"announce-list": [[TRACKER], [b"http://tracker.example.invalid/announce"]],
        b"comment": b"a lab fixture, not a real download",
        b"created by": b"bencode.py",
        b"creation date": 1700000000,
        b"info": {
            b"name": b"lab.bin",
            b"piece length": 16384,
            b"pieces": PIECE + bytes(reversed(PIECE)),
            b"length": 4096,
        },
    }


def multi():
    return {
        b"announce": TRACKER,
        b"creation date": 1700000001,
        b"info": {
            b"files": [
                {b"length": 1024, b"path": [b"lab-dir", b"first.bin"]},
                {b"length": 2048, b"path": [b"lab-dir", b"second.bin"]},
            ],
            b"name": b"lab-dir",
            b"piece length": 16384,
            b"pieces": PIECE,
        },
    }


def describe(value):
    """The decoded structure, in a form that survives JSON.

    `bencode.py` hands back `str` for a byte string and `int` for a number, so `str` is the text case and
    anything else is the integer - getting that backwards would label the tracker URL an integer and the
    probe would be quietly wrong.
    """
    if isinstance(value, dict):
        return {
            "type": "dict",
            "keys": sorted(describe_key(k) for k in value),
            "items": {describe_key(k): describe(v) for k, v in value.items()},
        }
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "items": [describe(each) for each in value]}
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value)}
    if isinstance(value, str):
        return {"type": "text", "length": len(value)}
    if isinstance(value, int):
        return {"type": "int", "value": value}
    raise SystemExit("what is a {!r}?".format(type(value)))


def describe_key(key):
    return key.decode("utf8", "replace") if isinstance(key, bytes) else str(key)


def measure(value, depth=1):
    """(nodes, deepest) counted over the decoded tree, by the same convention the reader uses.

    A dictionary's *keys* are not nodes - only its values are - because bencode reads a key as a string
    and then reads whatever follows it, so counting both would double the tree. Recursing over the
    library's decoded structure rather than the bytes is the point: the reader's `nodes` and `depth` are
    walk statistics, and this says what an independent parse of the same file walks to.
    """
    if isinstance(value, dict):
        each = [measure(v, depth + 1) for v in value.values()]
    elif isinstance(value, list):
        each = [measure(v, depth + 1) for v in value]
    else:
        each = []
    return 1 + sum(n for n, _ in each), max([depth] + [d for _, d in each])


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    report = {}
    for label, data in (("lab.torrent", single()), ("lab-multi.torrent", multi())):
        raw = bencode.bencode(data)
        path = os.path.join(SCRATCH, label)
        with open(path, "wb") as handle:
            handle.write(raw)
        back = bencode.bdecode(raw)
        # Re-encoding what the library decoded must give the same bytes: that is the statement that the
        # file is canonical bencode and not merely something a decoder tolerated.
        if bencode.bencode(back) != raw:
            raise SystemExit("{} did not re-encode to itself".format(label))
        if raw[:1] != b"d" or raw[-1:] != b"e":
            raise SystemExit("{} is not a dict: {!r}".format(label, raw[:8]))
        keys = sorted(back.keys())
        if "info" not in keys:
            raise SystemExit("{} has no info dictionary".format(label))
        info = back["info"]
        pieces = info["pieces"]
        if len(pieces) % 20:
            raise SystemExit("pieces is {} bytes, not a multiple of a SHA-1".format(len(pieces)))
        walked, deepest = measure(back)
        if "info" not in back or walked < 2:
            raise SystemExit("{} is not a tree worth recording".format(label))
        report[label] = {
            "bytes": len(raw),
            "keys": len(keys),
            "nodes": walked,
            "depth": deepest,
            "root_keys": keys,
            "info_keys": sorted(info.keys()),
            "pieces": len(pieces),
            "piece_length": info["piece length"],
            "name": info["name"],
            "single": "length" in info,
            "files": len(info.get("files", [])),
            "decoded": describe(back),
        }
        with open(os.path.join(OUT, label), "wb") as handle:
            handle.write(raw)
        print("== {} {} bytes, keys {} nodes {} depth {}".format(label, len(raw), len(keys), walked, deepest))
        print("   info {} pieces {} x20 ok".format(sorted(info.keys()), len(pieces)))
    with open(os.path.join(OUT, "torrent.probe.json"), "w", encoding="utf8", newline="\n") as handle:
        json.dump(report, handle, indent=1, sort_keys=True, default=lambda each: {
            "type": type(each).__name__})
    print("wrote lab.torrent, lab-multi.torrent and torrent.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
