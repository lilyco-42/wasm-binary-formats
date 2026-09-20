#!/usr/bin/env python3
"""Write the Avro object-container fixtures with fastavro, and check the container's own arithmetic.

    temp/venv/Scripts/python.exe scripts/make-avro-fixtures.py

`avro` has no Kaitai spec in the pinned bundle. fastavro writes the object container - `Obj\\x01`, a
metadata map, a 16-byte synchronisation marker, then blocks of record count + byte size + data + a
copy of that marker - and reads it back, which gives the two independent numbers this repo's reader is
allowed to compare against: how many records the library returns, and what the blocks add up to.

The probe records the walk (pairs, codec, schema length, per-block counts and sizes, the offset the
block chain ends at, and whether every block repeats the header's sync marker). Where the walk and
fastavro disagree the script exits non-zero, so no fixture is committed on the strength of one reader.
`many.avro` is written with `sync_interval=1000` so that it really is several blocks, because a
single-block file cannot tell a block loop from a block that happens to reach the end of the file.
"""

import io
import json
import pathlib
import sys

import fastavro

OUT = pathlib.Path(__file__).resolve().parent.parent / "test" / "fixtures"

SCHEMA = {
    "type": "record",
    "name": "Sample",
    "fields": [{"name": "id", "type": "long"}, {"name": "name", "type": "string"}],
}


def zigzag(data, at):
    result, shift = 0, 0
    while True:
        byte = data[at]
        at += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return (result >> 1) ^ -(result & 1), at


def write(name, records, **options):
    buffer = io.BytesIO()
    fastavro.writer(buffer, SCHEMA, records, **options)
    data = buffer.getvalue()
    (OUT / name).write_bytes(data)

    at, pairs = 4, []
    count, at = zigzag(data, at)
    for _ in range(count):
        key_len, at = zigzag(data, at)
        key = data[at : at + key_len].decode()
        at += key_len
        value_len, at = zigzag(data, at)
        pairs.append((key, data[at : at + value_len].decode("latin-1")))
        at += value_len
    if data[at] != 0:
        raise AssertionError(f"{name}: metadata map did not terminate")
    at += 1
    sync, blocks = data[at : at + 16], []
    at += 16
    while at < len(data):
        records_in, at = zigzag(data, at)
        size, at = zigzag(data, at)
        at += size
        copy = data[at : at + 16]
        if copy != sync:
            raise AssertionError(f"{name}: block sync marker differs from the header's")
        blocks.append({"records": records_in, "bytes": size})
        at += 16
    walked = at
    read = list(fastavro.reader(io.BytesIO(data)))
    total = sum(block["records"] for block in blocks)
    assert walked == len(data), f"{name}: block chain ended at {walked} of {len(data)}"
    assert total == len(read), f"{name}: blocks add up to {total}, fastavro returns {len(read)}"
    codec = dict(pairs).get("avro.codec", "absent")
    print(
        f"{name}: {len(data)} bytes, {len(blocks)} block(s), {total} records, codec {codec}, "
        f"{len(read)} read back"
    )
    return {
        "length": len(data),
        "pairs": [[key, value] for key, value in pairs],
        "codec": codec,
        "schema_bytes": len(dict(pairs)["avro.schema"]),
        "sync": sync.hex(),
        "blocks": blocks,
        "records": total,
        "read_back": len(read),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    three = [{"id": i + 1, "name": word} for i, word in enumerate(("one", "two", "three"))]
    many = [{"id": i, "name": f"row-{i}"} for i in range(500)]
    probes = {
        "rows": write("rows.avro", three),
        "deflate": write("deflate.avro", three, codec="deflate"),
        "many": write("many.avro", many, sync_interval=1000),
    }
    for name, probe in probes.items():
        assert probe["records"] == probe["read_back"], name
    assert len(probes["many"]["blocks"]) > 1, "sync_interval did not produce more than one block"
    (OUT / "avro.probe.json").write_text(
        json.dumps(probes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
