#!/usr/bin/env python3
"""Write Arrow IPC fixtures with pyarrow and record what pyarrow itself says about them.

Arrow has two framings on purpose here. The stream framing has no magic at all - an encapsulated
message is a 0xFFFFFFFF continuation, an int32 metadata length, a flatbuffer, and then a body whose
length only lives *inside* that flatbuffer - so a walk that skips just the metadata desynchronises
on the second message. The file framing adds `ARROW1` at both ends and puts a non-encapsulated
Footer behind an int32 length, and the block index in that footer is the only thing that makes the
columns seekable.

Every number that ends up in engine/tests/arrow.rs comes from one of two places: the byte walk
mirrored below (`walk`), or pyarrow reading the same bytes back (`py_read`). The script refuses to
write the probe unless the two agree field for field, so a wrong vtable slot cannot pass by being
wrong in the reader and in this script at once - pyarrow's C++ is the third party. Header and type
ordinals are collected from the pairs actually observed, never recalled.

Usage: temp/venv/Scripts/python.exe scripts/make-arrow-fixtures.py
"""
import json
import os
import struct

import pyarrow as pa

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MAGIC = b"ARROW1"
EOS = 8


# --------------------------------------------------------------------------------------
# flatbuffer reading - the mirror of what read_arrow does in Rust
# --------------------------------------------------------------------------------------
def u8(b, at):
    return None if at is None or at + 1 > len(b) else b[at]


def i16(b, at):
    return None if at is None or at + 2 > len(b) else struct.unpack_from("<h", b, at)[0]


def u16(b, at):
    return None if at is None or at + 2 > len(b) else struct.unpack_from("<H", b, at)[0]


def i32(b, at):
    return None if at is None or at + 4 > len(b) else struct.unpack_from("<i", b, at)[0]


def u32(b, at):
    return None if at is None or at + 4 > len(b) else struct.unpack_from("<I", b, at)[0]


def i64(b, at):
    return None if at is None or at + 8 > len(b) else struct.unpack_from("<q", b, at)[0]


def vslot(b, table, want):
    """Absolute position of a table field, or None when the writer left it at its default.

    The i32 at a table is an offset *backwards* to the vtable, and the vtable lists one u16 per
    field slot; a zero entry means "default", so it is absent rather than zero.
    """
    soff = i32(b, table)
    if soff is None:
        return None
    vt = table - soff
    ivt = u16(b, vt)
    if vt < 0 or ivt is None or ivt < 4 or 4 + 2 * want >= ivt:
        return None
    off = u16(b, vt + 4 + 2 * want)
    return None if not off else table + off


def vinfo(b, table):
    soff = i32(b, table)
    vt = table - soff
    return vt, u16(b, vt), u16(b, vt + 2)


def vref(b, table, want):
    """Follow a uoffset field to its referent."""
    p = vslot(b, table, want)
    return None if p is None else p + u32(b, p)


def vstr(b, table, want):
    at = vref(b, table, want)
    if at is None:
        return None
    n = u32(b, at)
    return b[at + 4 : at + 4 + n].decode("utf-8", "replace")


def vvec(b, table, want):
    """(first element, count) of a vector field."""
    at = vref(b, table, want)
    if at is None:
        return None, 0
    return at + 4, u32(b, at)


def vtable(b, at):
    """Root of the flatbuffer at `at` -> absolute table position."""
    root = u32(b, at)
    return None if root is None else at + root


# MessageHeader union ordinals, keyed by what pyarrow's own Message.type calls them.
HEAD_NAMES = {
    0: ("NONE", "none"),
    1: ("Schema", "schema"),
    2: ("DictionaryBatch", "dictionary"),
    3: ("RecordBatch", "record batch"),
    4: ("Tensor", "tensor"),
    5: ("SparseTensor", "sparse tensor"),
    6: ("Middleware", "middleware"),
    8: ("Footer", "footer"),
}

# CompressionType ordinals, keyed by the option string pyarrow was told to use. lz4_frame is the
# enum's zero value so its file writes no codec field at all; zstd has to appear explicitly, which
# is what pins the ordering instead of a guess.
CODEC_NAMES = {0: "lz4_frame", 1: "zstd"}


def read_compression(b, table):
    """BlockCompression: slot 0 codec, 1 method, 2 frame_length, 3 compressed_length."""
    at = vref(b, table, 3)
    if at is None:
        return None

    def number(slot, wide):
        p = vslot(b, at, slot)
        if p is None:
            return 0
        # codec is declared `int8` in the schema, so it occupies one byte: reading two would
        # swallow the next field's padding and report 1281 for zstd.
        return i64(b, p) if wide else u8(b, p)

    return {"codec": number(0, False), "frame": number(2, True), "compressed": number(3, True)}


def read_batch(b, table):
    """RecordBatch: slot 0 length, 1 field nodes, 2 buffers, 3 compression."""
    nodes_at, nodes = vvec(b, table, 1)
    buffers_at, buffers = vvec(b, table, 2)
    out = {
        "rows": i64(b, vslot(b, table, 0)) if vslot(b, table, 0) else 0,
        "nodes": nodes,
        "buffers": buffers,
    }
    if nodes and nodes_at is not None:
        out["node0"] = [i64(b, nodes_at), i64(b, nodes_at + 8)]
    comp = read_compression(b, table)
    if comp:
        out["compression"] = comp
    return out


def read_fields(b, table):
    """Schema: slot 0 endianness, 1 fields; each Field: 0 name, 1 nullable, 2 type ordinal."""
    ref, count = vvec(b, table, 1)
    fields = []
    for i in range(count or 0):
        ft = vtable(b, ref + 4 * i)
        fields.append(
            {
                "name": vstr(b, ft, 0),
                "nullable": u8(b, vslot(b, ft, 1)) or 0,
                "type": u8(b, vslot(b, ft, 2)) or 0,
                "children": vvec(b, ft, 5)[1],
            }
        )
    return {"endianness": i16(b, vslot(b, table, 0)) if vslot(b, table, 0) else 0, "fields": fields}


def read_header(b, message):
    h = message["header_at"]
    kind = message["head"]
    if h is None:
        return {}
    if kind == 1:
        return read_fields(b, h)
    if kind == 3:
        return read_batch(b, h)
    if kind == 2:
        data = vref(b, h, 1)
        out = {
            "dict_id": i64(b, vslot(b, h, 0)) if vslot(b, h, 0) else 0,
            "is_delta": u8(b, vslot(b, h, 2)) or 0,
        }
        inner = read_batch(b, data)
        out["data"] = inner
        return out
    if kind == 8:
        blocks_at, blocks = vvec(b, h, 3)
        dicts_at, dicts = vvec(b, h, 2)
        out = {
            "fversion": i16(b, vslot(b, h, 0)) if vslot(b, h, 0) else 0,
            "schema": read_fields(b, vref(b, h, 1))["fields"],
            "dictionaries": dicts,
            "batches": blocks,
        }
        if blocks:
            out["blocks"] = [
                {
                    "offset": i64(b, blocks_at + 24 * i),
                    "meta": i64(b, blocks_at + 24 * i + 8),
                    "body": i64(b, blocks_at + 24 * i + 16),
                }
                for i in range(blocks)
            ]
        if dicts and dicts_at is not None:
            out["dict_blocks"] = [
                {
                    "offset": i64(b, dicts_at + 24 * i),
                    "meta": i64(b, dicts_at + 24 * i + 8),
                    "body": i64(b, dicts_at + 24 * i + 16),
                }
                for i in range(dicts)
            ]
        return out
    return {}


def walk_message(b, at):
    """One encapsulated message: envelope arithmetic plus the fields inside the flatbuffer."""
    if at + 8 > len(b) or u32(b, at) != 0xFFFFFFFF:
        return None
    meta = u32(b, at + 4)
    if meta == 0:
        return {"at": at, "eos": True}
    fb = at + 8
    if fb + meta > len(b):
        return None
    table = vtable(b, fb)
    if table is None or table + 4 > len(b):
        return None
    head = u8(b, vslot(b, table, 1))
    body = i64(b, vslot(b, table, 3)) if vslot(b, table, 3) else 0
    m = {
        "at": at,
        "meta": meta,
        "version": i16(b, vslot(b, table, 0)) if vslot(b, table, 0) else 0,
        "head": head,
        "body": body,
        "header_at": vref(b, table, 2),
        "next": fb + meta + body,
    }
    m["fields"] = read_header(b, m)
    return m


def walk(b):
    """Whole file: both framings, and the tail structure the file format hides at the end."""
    limit = len(b)
    framing, at = "stream", 0
    footer_len, footer_at, pad, tail_magic, head_at = None, None, None, None, None
    if b[:6] == MAGIC and limit >= 14:
        framing = "file"
        at = 8
        # The int32 before the trailing magic is the footer's length, and the padding between the
        # two grows with the footer's size, so take the first position whose value decodes.
        for cand in range(4, 12):
            pos = limit - cand - 6
            value = i32(b, pos)
            if value is None or value <= 0 or pos - value < 8:
                continue
            start = pos - value
            table = vtable(b, start)
            if table is None or table + 4 > limit:
                continue
            try:
                vt, ivt, _ = vinfo(b, table)
            except TypeError:
                continue
            if ivt is None or ivt < 4 or vt < 0:
                continue
            footer_len, footer_at, pad, tail_magic, head_at = value, start, cand - 4, None, pos
            tail_magic = b[limit - 6 :] == MAGIC
            break
    messages, eos = [], False
    stop = footer_at if framing == "file" else limit
    while at + 8 <= stop:
        m = walk_message(b, at)
        if m is None:
            break
        if m.get("eos"):
            eos = True
            at += EOS
            break
        messages.append(m)
        at = m["next"]
    out = {
        "framing": framing,
        "messages": messages,
        "eos": eos,
        "walk_end": at,
        "stopped": at < stop,
    }
    if framing == "file":
        out["footer"] = {
            "length": footer_len,
            "at": footer_at,
            "padding": pad,
            "head_at": head_at,
            "tail_magic": bool(tail_magic),
            "leading_magic": b[:8] == MAGIC + b"\0\0",
            "pad_before": None if footer_at is None else footer_at - out["walk_end"],
        }
        if footer_at is not None:
            fm = {"head": 8, "header_at": vtable(b, footer_at)}
            out["footer_fields"] = read_header(b, fm)
    return out


# --------------------------------------------------------------------------------------
# pyarrow readback - the independent witness
# --------------------------------------------------------------------------------------
def py_read(path, file_format):
    got = {"batches": [], "messages": [], "schema": None, "rows": 0}
    src = pa.memory_map(path, "r")
    if file_format:
        rd = pa.ipc.open_file(src)
        got["schema"] = str(rd.schema)
        got["names"] = rd.schema.names
        got["types"] = [str(f.type) for f in rd.schema]
        got["nullable"] = [f.nullable for f in rd.schema]
        got["num_record_batches"] = rd.num_record_batches
        got["batches"] = [rd.get_batch(i).num_rows for i in range(rd.num_record_batches)]
        got["columns"] = [rd.get_batch(i).num_columns for i in range(rd.num_record_batches)]
        got["rows"] = sum(got["batches"])
    src.close()
    src = pa.memory_map(path, "r")
    if file_format:
        src.seek(8)
    while True:
        try:
            msg = pa.ipc.read_message(src)
        except (pa.ArrowInvalid, EOFError):
            break
        got["messages"].append(
            {
                "type": msg.type,
                "meta": msg.metadata.size,
                "body": msg.body.size,
                "version": int(msg.metadata_version),
                "version_name": msg.metadata_version.name,
                "end": src.tell(),
            }
        )
    src.close()
    if not file_format:
        stream = pa.ipc.open_stream(path)
        got["schema"] = str(stream.schema)
        got["names"] = stream.schema.names
        got["types"] = [str(f.type) for f in stream.schema]
        got["nullable"] = [f.nullable for f in stream.schema]
        got["batches"], got["columns"] = [], []
        while True:
            try:
                batch = stream.read_next_batch()
            except StopIteration:
                break
            got["batches"].append(batch.num_rows)
            got["columns"].append(batch.num_columns)
        got["rows"] = sum(got["batches"])
    return got


def agree(name, w, py, compressed_with=None):
    """The mirror must reproduce pyarrow's numbers, message for message and column for column."""
    heads = [m for m in w["messages"]]
    assert len(heads) == len(py["messages"]), f"{name}: {len(heads)} walked vs {len(py['messages'])} read"
    for m, p in zip(heads, py["messages"]):
        assert HEAD_NAMES[m["head"]][1] == p["type"], f"{name}: head {m['head']} vs {p['type']}"
        assert m["meta"] == p["meta"], f"{name}: meta {m['meta']} vs {p['meta']}"
        assert m["body"] == p["body"], f"{name}: body {m['body']} vs {p['body']}"
        assert m["version"] == p["version"], f"{name}: version {m['version']} vs {p['version']}"
        assert m["next"] == p["end"], f"{name}: next {m['next']} vs tell {p['end']}"
    if w["framing"] == "stream":
        assert w["eos"], f"{name}: stream has no end-of-stream marker"
        assert not w["stopped"], f"{name}: walk stopped early at {w['walk_end']} of {len(open(path_of(name),'rb').read())}"
    expected_end = w["messages"][-1]["next"] + (EOS if w["eos"] else 0)
    assert expected_end == w["walk_end"], f"{name}: walk ended inside an envelope"
    batches = [m for m in heads if m["head"] == 3]
    assert [m["fields"]["rows"] for m in batches] == py["batches"], f"{name}: row counts"
    assert [m["fields"]["nodes"] for m in batches] == py["columns"], f"{name}: node count vs columns"
    schemas = [m for m in heads if m["head"] == 1]
    fields = schemas[0]["fields"]["fields"]
    assert [f["name"] for f in fields] == py["names"], f"{name}: field names"
    assert [bool(f["nullable"]) for f in fields] == py["nullable"], f"{name}: nullable"
    if w["framing"] == "file":
        footer = w["footer"]
        assert footer["tail_magic"] and footer["leading_magic"], f"{name}: magic missing"
        assert footer["at"] + footer["length"] == footer["head_at"], f"{name}: footer span"
        assert 0 <= footer["pad_before"] < 8, f"{name}: {footer['pad_before']} bytes before the footer"
        assert footer["padding"] == 0, f"{name}: trailing padding {footer['padding']}"
        assert w["footer_fields"]["batches"] == py["num_record_batches"], f"{name}: footer block count"
        assert [f["name"] for f in w["footer_fields"]["schema"]] == py["names"], f"{name}: footer schema"
        blocks = w["footer_fields"]["blocks"]
        # A footer Block indexes the message by its envelope position, and its metaDataLength is
        # the metadata *plus* the 8-byte encapsulation prefix - so body = offset + metaDataLength.
        # Reading both as pure metadata sizes lands 8 bytes into every body.
        assert [blk["offset"] for blk in blocks] == [m["at"] for m in batches], f"{name}: block offsets"
        assert [blk["meta"] for blk in blocks] == [
            m["meta"] + 8 for m in batches
        ], f"{name}: block meta lengths"
        assert [blk["body"] for blk in blocks] == [m["body"] for m in batches], f"{name}: block body lengths"
        assert [blk["offset"] + blk["meta"] for blk in blocks] == [
            m["at"] + 8 + m["meta"] for m in batches
        ], f"{name}: block body positions"
        dicts = [m for m in heads if m["head"] == 2]
        assert w["footer_fields"]["dictionaries"] == len(dicts), f"{name}: dictionary block count"
        assert [blk["offset"] for blk in w["footer_fields"].get("dict_blocks", [])] == [
            m["at"] for m in dicts
        ], f"{name}: dictionary block offsets"
    if compressed_with:
        codec = batches[0]["fields"]["compression"]["codec"]
        assert CODEC_NAMES[codec] == compressed_with, f"{name}: codec {codec} vs {compressed_with}"
    return w, py


def path_of(name):
    return os.path.join(OUT, name)


def write_stream(name, schema, batches, options=None):
    with open(path_of(name), "wb") as sink:
        writer = pa.ipc.new_stream(sink, schema, options=options)
        for batch in batches:
            writer.write_batch(batch)
        writer.close()


def write_file(name, schema, batches, options=None):
    with open(path_of(name), "wb") as sink:
        writer = pa.ipc.new_file(sink, schema, options=options)
        for batch in batches:
            writer.write_batch(batch)
        writer.close()


def main():
    os.makedirs(OUT, exist_ok=True)
    plain = pa.schema([pa.field("id", pa.int32()), pa.field("name", pa.string())])
    rows = [
        pa.record_batch([pa.array([1, 2, 3], pa.int32()), pa.array(["one", "two", "three"], pa.string())], plain.names),
    ]
    many = [
        pa.record_batch([pa.array([1, 2], pa.int32()), pa.array(["a", "b"], pa.string())], plain.names),
        pa.record_batch([pa.array([3], pa.int32()), pa.array(["c"], pa.string())], plain.names),
        pa.record_batch([pa.array([4, 5, 6], pa.int32()), pa.array(["d", "e", "f"], pa.string())], plain.names),
    ]
    colors = pa.array(["red", "green", "red", "blue"], pa.dictionary(pa.int8(), pa.string()))
    dict_schema = pa.schema([pa.field("color", colors.type)])
    dict_batch = pa.record_batch([colors], ["color"])
    # A file may only carry one dictionary per field, so this pair repeats the same batch: the
    # footer then indexes one dictionary block and two record batches.

    write_stream("rows.arrow", plain, rows)
    write_stream("batches.arrow", plain, many)
    write_stream("dict.arrow", dict_schema, [dict_batch])
    write_stream("lz4.arrow", plain, rows, options=pa.ipc.IpcWriteOptions(compression="lz4_frame"))
    write_stream("zstd.arrow", plain, rows, options=pa.ipc.IpcWriteOptions(compression="zstd"))
    write_file("file.arrow", plain, [rows[0], many[1]])
    write_file("file_dict.arrow", dict_schema, [dict_batch, dict_batch])

    plan = [
        ("rows.arrow", False, None),
        ("batches.arrow", False, None),
        ("dict.arrow", False, None),
        ("lz4.arrow", False, "lz4_frame"),
        ("zstd.arrow", False, "zstd"),
        ("file.arrow", True, None),
        ("file_dict.arrow", True, None),
    ]
    probes, ordinals, types, codecs, versions = {}, {}, {}, {}, {}
    for name, file_format, codec in plan:
        path = path_of(name)
        b = open(path, "rb").read()
        w, py = agree(name, walk(b), py_read(path, file_format), codec)
        for m in w["messages"]:
            ordinals[m["head"]] = HEAD_NAMES[m["head"]]
            versions[m["version"]] = m["version"]
        for m in w["messages"]:
            c = m["fields"].get("compression") or (m["fields"].get("data") or {}).get("compression")
            if c:
                codecs[c["codec"]] = CODEC_NAMES[c["codec"]]
        schema_fields = [m for m in w["messages"] if m["head"] == 1][0]["fields"]["fields"]
        for f, tname in zip(schema_fields, py["types"]):
            types.setdefault(f["type"], set()).add(tname)
        probes[name] = {
            "bytes": len(b),
            "head": b[:8].hex(),
            "tail": b[-16:].hex(),
            "framing": w["framing"],
            "eos": w["eos"],
            "walk_end": w["walk_end"],
            "footer": w.get("footer"),
            "messages": [
                {
                    "at": m["at"],
                    "meta": m["meta"],
                    "version": m["version"],
                    "head": m["head"],
                    "head_name": HEAD_NAMES[m["head"]][0],
                    "body": m["body"],
                    "next": m["next"],
                    "fields": m["fields"],
                }
                for m in w["messages"]
            ],
            "footer_fields": w.get("footer_fields"),
            "pyarrow": py,
        }
        print(
            name,
            len(b),
            w["framing"],
            "eos" if w["eos"] else "",
            [HEAD_NAMES[m["head"]][0] for m in w["messages"]],
            "footer@%s+%s pad %s" % (w["footer"]["at"], w["footer"]["length"], w["footer"]["padding"])
            if w["framing"] == "file"
            else "",
        )
    probes["_observed"] = {
        "header_ordinals": {str(k): list(v) for k, v in sorted(ordinals.items())},
        "field_type_ordinals": {str(k): sorted(v) for k, v in sorted(types.items())},
        "codecs": codecs,
        "versions": sorted(versions),
        "note": "field_type_ordinals maps the Type union id pyarrow wrote to the type it printed; "
        "the reader reports the number only, so no name is claimed for an unobserved ordinal",
    }
    with open(os.path.join(OUT, "arrow.probe.json"), "w", encoding="utf-8", newline="\n") as sink:
        json.dump(probes, sink, indent=1, sort_keys=True, ensure_ascii=False)
        sink.write("\n")
    print("header ordinals:", {k: v for k, v in sorted(ordinals.items())})
    print("field type ordinals:", {k: sorted(v) for k, v in sorted(types.items())})
    print("codecs:", codecs)
    print("wrote arrow.probe.json")


main()
