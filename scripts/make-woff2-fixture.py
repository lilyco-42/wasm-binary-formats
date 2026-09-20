#!/usr/bin/env python3
"""Write `tiny.woff2` with fontTools and probe what the finished bytes really say.

    temp/venv/Scripts/python.exe scripts/make-woff2-fixture.py      # needs brotli
    python3 scripts/make-woff2-fixture.py                          # says so, and stops

Running with the plain interpreter on PATH is fine for everything except the encoder itself: WOFF2
compresses its table data with brotli, which only the project venv has
(`python -m venv --system-site-packages temp/venv && temp/venv/Scripts/python.exe -m pip install
fonttools brotli`). The script refuses to write a partial probe rather than quietly producing a
fixture from a different font.

Three things are recorded, because each is witnessed by something other than this repo's opinion:

  * the 48-byte header and the table directory, decoded with fontTools' *own* `woff2KnownTags` list
    and its transform rule, and dumped into the probe verbatim - so the 63-entry name table the Rust
    reader carries is checked against a second implementation, not against a recollection;
  * every `origLength` compared with the length the same table has in `test/fixtures/tiny.ttf`, the
    uncompressed font this one was made from: the two agree, which is what says the directory was
    walked with the right widths rather than a plausible guess;
  * `totalCompressedSize` against the space that is actually left, plus the alignment padding, so a
    reader that lost the directory's length would show up as a mismatch instead of silence.
"""

import pathlib
import struct
import sys

try:
    from fontTools.ttLib import woff2 as w2
    from fontTools import ttLib
except ImportError as error:  # pragma: no cover
    raise SystemExit(f"fontTools is required: {error}")

import brotli  # noqa: F401  (the import is the point: without it the writer produces nothing)

ROOT = pathlib.Path(__file__).resolve().parent.parent
TTF = ROOT / "test" / "fixtures" / "tiny.ttf"
OUT = ROOT / "test" / "fixtures" / "tiny.woff2"
PROBE = ROOT / "test" / "fixtures" / "woff2.probe.json"


def base128(data, at):
    value = 0
    for _ in range(5):
        byte = data[at]
        at += 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, at
    raise ValueError("UIntBase128 longer than five bytes")


def main():
    font = ttLib.TTFont(str(TTF))
    font.flavor = "woff2"
    font.save(str(OUT))
    data = OUT.read_bytes()
    assert data[:4] == b"wOF2", "fontTools did not write a WOFF2 file"

    signature, flavor, length, tables, reserved, sfnt_size, compressed = struct.unpack(
        ">4sIIHHII", data[:24]
    )
    major, minor = struct.unpack(">HH", data[24:28])
    meta_off, meta_len, meta_orig, priv_off, priv_len = struct.unpack(">IIIII", data[28:48])
    assert length == len(data), "the header does not describe its own file"

    at, directory = 48, []
    for index in range(tables):
        flags = data[at]
        at += 1
        tag_index = flags & 0x3F
        version = flags >> 6
        if tag_index == w2.woff2UnknownTagIndex:
            tag = data[at : at + 4].decode("latin-1")
            at += 4
        else:
            tag = w2.woff2KnownTags[tag_index]
        original, at = base128(data, at)
        transformed = None
        if tag in w2.woff2TransformedTableTags and version == 0:
            transformed, at = base128(data, at)
        directory.append(
            {
                "index": index,
                "tag": tag,
                "tag_index": tag_index,
                "version": version,
                "orig": original,
                "transform": transformed,
            }
        )
    padded = (at + compressed + 3) // 4 * 4
    assert padded == len(data), f"directory {at} + compressed {compressed} != {len(data)}"

    uncompressed = pathlib.Path(TTF).read_bytes()
    count = struct.unpack(">H", uncompressed[4:6])[0]
    ttf_sizes = {}
    for entry in range(count):
        start = 12 + 16 * entry
        tag = uncompressed[start : start + 4].decode("latin-1")
        ttf_sizes[tag] = struct.unpack(">I", uncompressed[start + 12 : start + 16])[0]
    for row in directory:
        if row["transform"] is None:
            assert ttf_sizes.get(row["tag"]) == row["orig"], (
                f"{row['tag']}: woff2 says {row['orig']}, tiny.ttf says {ttf_sizes.get(row['tag'])}"
            )

    reopened = ttLib.TTFont(str(OUT))
    assert reopened.flavor == "woff2", "fontTools cannot read back what it wrote"
    assert sorted(row["tag"] for row in directory) == sorted(ttf_sizes), "directory and sfnt disagree"
    print(
        f"tiny.woff2: {len(data)} bytes, {tables} tables, {compressed} compressed,"
        f" directory ends at {at}, every untransformed length agrees with tiny.ttf"
    )
    import json

    PROBE.write_text(
        json.dumps(
            {
                "length": len(data),
                "ttf_length": len(uncompressed),
                "header": {
                    "flavor": flavor,
                    "num_tables": tables,
                    "reserved": reserved,
                    "total_sfnt_size": sfnt_size,
                    "total_compressed_size": compressed,
                    "version": [major, minor],
                    "meta": [meta_off, meta_len, meta_orig],
                    "priv": [priv_off, priv_len],
                },
                "directory_end": at,
                "tables": directory,
                "ttf_table_sizes": ttf_sizes,
                "known_tags": list(w2.woff2KnownTags),
                "transformed_tags": list(w2.woff2TransformedTableTags),
                "unknown_tag_index": w2.woff2UnknownTagIndex,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
