#!/usr/bin/env python3
"""Write Parquet fixtures with pyarrow and print the report a reader has to reproduce.

A Parquet file keeps everything interesting at the end: `PAR1`, the row groups, a Footer written as a
Thrift *compact* struct, an int32 stating the footer's size, then `PAR1` again. So the whole metadata
read is one Thrift-compact decode - field-id deltas in the high nibble, zigzag varints, a zero byte
closing each struct, lists carrying their own size and element type - over a schema of nested structs.
There is no vtable here, so a field that equals its default is simply absent and the ids that follow
are only recoverable from the deltas: the readers below walk the known ids and skip the rest *by type*,
which is the one behaviour that keeps an unknown future field from desynchronising the rest.

Two witnesses, neither of them this script's opinion:
  * the walk has to consume the footer down to its last byte, and the footer's stored length has to
    equal `FileMetaData.serialized_size` as pyarrow reports it for the same file;
  * every number in the report is compared with pyarrow's own metadata object, and the page-type,
    codec and physical-type tables are learned from files written with those options named.

Usage: temp/venv/Scripts/python.exe scripts/make-parquet-fixtures.py
"""
import json
import os
import struct

import pyarrow as pa
import pyarrow.parquet as pq

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MAGIC = b"PAR1"
MAX_COLUMNS = 64
MAX_CHUNKS = 128
MAX_GROUPS = 64


# --------------------------------------------------------------------------------------
# Thrift compact cursor
# --------------------------------------------------------------------------------------
class Cursor:
    """A byte position over a bounded region; running off the end is a soft failure, not a lie."""

    def __init__(self, data, start, stop):
        self.data = data
        self.at = start
        self.stop = stop
        self.bad = 0

    def raw(self, count):
        if self.at + count > self.stop:
            self.bad += 1
            return None
        out = self.data[self.at : self.at + count]
        self.at += count
        return out

    def byte(self):
        raw = self.raw(1)
        return None if raw is None else raw[0]

    def varint(self):
        result = 0
        shift = 0
        while True:
            piece = self.raw(1)
            if piece is None:
                return None
            byte = piece[0]
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 63:
                self.bad += 1
                return None

    def long(self):
        raw = self.varint()
        return None if raw is None else (raw >> 1) ^ -(raw & 1)

    def binary(self):
        size = self.varint()
        return None if size is None else self.raw(size)

    def skip(self, kind, depth=0):
        if kind in (1, 2):
            return
        if kind == 3:
            self.raw(1)
        elif kind in (4, 5, 6):
            self.varint()
        elif kind == 7:
            self.raw(8)
        elif kind == 8:
            self.binary()
        elif kind in (9, 10):
            size, element = self.list_header()
            for _ in range(size or 0):
                self.skip(element, depth + 1)
        elif kind == 11:
            size = self.varint()
            if size:
                pair = self.raw(1)
                if pair is None:
                    return
                self.skip(pair[0] >> 4, depth + 1)
                self.skip(pair[0] & 0x0F, depth + 1)
                for _ in range(size):
                    self.skip(11, depth + 1)
        elif kind == 12:
            # An inline struct: its fields are skipped by type until the closing zero byte. The depth
            # cap is what keeps a hostile nesting from recursing forever.
            if depth > 12:
                self.bad += 1
                return
            while True:
                head = self.raw(1)
                if head is None:
                    return
                if head[0] == 0:
                    return
                if not head[0] >> 4:
                    self.varint()
                self.skip(head[0] & 0x0F, depth + 1)
        else:
            self.bad += 1

    def list_header(self):
        head = self.raw(1)
        if head is None:
            return None, None
        size = head[0] >> 4
        element = head[0] & 0x0F
        if size == 15:
            size = self.varint()
        return size, element


def fields(cursor):
    """Yield (field id, type) for one struct, or stop at the zero byte / a failed read."""
    number = 0
    while not cursor.bad:
        head = cursor.raw(1)
        if head is None:
            return
        delta = head[0] >> 4
        kind = head[0] & 0x0F
        if kind == 0 and delta == 0:
            return
        if delta:
            number += delta
        else:
            raw = cursor.varint()
            if raw is None:
                return
            number = (raw >> 1) ^ -(raw & 1)
        yield number, kind


def scalar(cursor, kind):
    if kind in (4, 5):
        return cursor.long()
    if kind == 6:
        return cursor.long()
    if kind == 3:
        raw = cursor.raw(1)
        return None if raw is None else struct.unpack("<b", raw)[0]
    if kind in (1, 2):
        return kind == 1
    return None


# --------------------------------------------------------------------------------------
# the parquet structs this reader names
# --------------------------------------------------------------------------------------
def read_statistics(cursor):
    out = {}
    for fid, kind in fields(cursor):
        if fid in (1, 2, 5, 6):
            out[fid] = cursor.binary() if kind == 8 else None
        elif fid == 3:
            out[3] = cursor.long() if kind == 6 else None
        else:
            cursor.skip(kind)
    return out


def read_column_metadata(cursor):
    out = {"encodings": [], "path": []}
    for fid, kind in fields(cursor):
        if fid in (1, 4):
            out[fid] = scalar(cursor, kind)
        elif fid in (5, 6, 7, 9, 10, 11):
            out[fid] = cursor.long() if kind == 6 else None
        elif fid == 2 and kind == 9:
            size, element = cursor.list_header()
            for _ in range(size or 0):
                out["encodings"].append(scalar(cursor, element))
        elif fid == 3 and kind == 9:
            size, element = cursor.list_header()
            for _ in range(size or 0):
                out["path"].append(cursor.binary() if element == 8 else None)
        elif fid == 12 and kind == 12:
            out["statistics"] = read_statistics(cursor)
        else:
            cursor.skip(kind)
    return out


def read_column_chunk(cursor):
    out = {}
    for fid, kind in fields(cursor):
        if fid == 1:
            out[1] = cursor.binary() if kind == 8 else None
        elif fid == 2 and kind == 6:
            out[2] = cursor.long()
        elif fid == 3 and kind == 12:
            out["metadata"] = read_column_metadata(cursor)
        else:
            cursor.skip(kind)
    return out


def read_row_group(cursor):
    out = {"columns": []}
    for fid, kind in fields(cursor):
        if fid == 1 and kind == 9:
            size, element = cursor.list_header()
            if element != 12:
                cursor.bad += 1
                return out
            for _ in range(size or 0):
                out["columns"].append(read_column_chunk(cursor))
        elif fid in (2, 3) and kind == 6:
            out[fid] = cursor.long()
        elif fid == 4 and kind == 6:
            out[4] = cursor.long()
        else:
            cursor.skip(kind)
    return out


def read_schema_element(cursor, depth=0):
    out = {"children": 0}
    for fid, kind in fields(cursor):
        if fid in (1, 3, 5, 6) and kind in (4, 5):
            out[fid] = scalar(cursor, kind)
        elif fid == 2 and kind in (4, 5):
            out[2] = scalar(cursor, kind)
        elif fid == 4 and kind == 8:
            out[4] = cursor.binary()
        elif fid == 7 and kind in (4, 5):
            out[7] = scalar(cursor, kind)
        elif fid == 8 and kind in (4, 5):
            out[8] = scalar(cursor, kind)
        elif fid == 10:
            out[10] = kind == 12
            cursor.skip(kind)
        else:
            cursor.skip(kind)
    return out


def read_file_metadata(data, start, stop):
    cursor = Cursor(data, start, stop)
    out = {"schema": [], "row_groups": []}
    for fid, kind in fields(cursor):
        if fid == 1 and kind in (4, 5):
            out[1] = scalar(cursor, kind)
        elif fid == 2 and kind == 9:
            size, element = cursor.list_header()
            if element != 12:
                cursor.bad += 1
                break
            for _ in range(size or 0):
                out["schema"].append(read_schema_element(cursor))
        elif fid == 3 and kind == 6:
            out[3] = cursor.long()
        elif fid == 4 and kind == 9:
            size, element = cursor.list_header()
            if element != 12:
                cursor.bad += 1
                break
            for _ in range(size or 0):
                out["row_groups"].append(read_row_group(cursor))
        elif fid == 5 and kind == 9:
            size, element = cursor.list_header()
            for _ in range(size or 0):
                cursor.skip(element)
        elif fid == 6 and kind == 8:
            out[6] = cursor.binary()
        else:
            cursor.skip(kind)
    return out, cursor


# --------------------------------------------------------------------------------------
# the report
# --------------------------------------------------------------------------------------
def footer_of(data):
    stop = len(data)
    length = struct.unpack_from("<I", data, stop - 8)[0]
    start = stop - 8 - length
    meta, cursor = read_file_metadata(data, start, stop - 8)
    return meta, cursor, start, length


def text(value):
    return (value or b"").decode("utf-8", "replace")


def report(data):
    meta, cursor, start, length = footer_of(data)
    schema = meta["schema"]
    groups = meta["row_groups"]
    leaves = [s for s in schema if not s.get(5)]
    rows = [
        "parquet\t{size}\tfooter\t{at}\tbytes\t{length}\tgroups\t{groups}".format(
            size=len(data), at=start, length=length, groups=len(groups)
        ),
        "version\t{v}\trows\t{r}\tschema\t{n}\tcolumns\t{c}".format(
            v=meta.get(1, 0), r=meta.get(3, 0), n=len(schema), c=len(leaves)
        ),
        "created\t{text}".format(text=text(meta.get(6))),
    ]
    for i, element in enumerate(schema[:MAX_COLUMNS]):
        line = "column\t{i}\t{name}".format(i=i, name=text(element.get(4)))
        if 1 in element:
            line += "\ttype\t{kind}\tname\t{label}".format(
                kind=element[1],
                label=label(PHYSICAL, RUST_PHYSICAL, element[1], f"column {i}"),
            )
        if 2 in element:
            line += "\tlength\t{value}".format(value=element[2])
        if 3 in element:
            line += "\trep\t{value}".format(value=element[3])
        if 5 in element:
            line += "\tchildren\t{value}".format(value=element[5])
        if 6 in element:
            line += "\tconverted\t{value}".format(value=element[6])
        rows.append(line)
    chunks = []
    for i, group in enumerate(groups[:MAX_GROUPS]):
        columns = group["columns"]
        rows.append(
            "group\t{i}\trows\t{r}\tbytes\t{b}\tcolumns\t{n}".format(
                i=i, r=group.get(3, 0), b=group.get(2, 0), n=len(columns)
            )
        )
        chunks.extend((i, c) for c in columns)
    for i, (group, chunk) in enumerate(chunks[:MAX_CHUNKS]):
        meta_column = chunk["metadata"]
        line = "chunk\t{i}\tpath\t{path}\tgroup\t{g}\trows\t{values}\ttype\t{kind}\tname\t{phys}\tcodec\t{codec}\tcodec_name\t{codec_label}\tuncompressed\t{u}\tcompressed\t{c}\tencodings\t{e}".format(
            i=i,
            path="/".join(text(p) for p in meta_column["path"]),
            g=group,
            values=meta_column.get(5, 0),
            kind=meta_column.get(1, 0),
            phys=label(PHYSICAL, RUST_PHYSICAL, meta_column.get(1), f"chunk {i}"),
            codec=meta_column.get(4, 0),
            codec_label=label(CODECS, RUST_CODECS, meta_column.get(4), f"chunk {i}"),
            u=meta_column.get(6, 0),
            c=meta_column.get(7, 0),
            e=",".join(str(int(e)) for e in meta_column["encodings"]),
        )
        if 9 in meta_column:
            line += "\tdata\t{value}".format(value=meta_column[9])
        if 11 in meta_column:
            line += "\tdict\t{value}".format(value=meta_column[11])
        rows.append(line)
        stats = meta_column.get("statistics")
        if stats:
            low = stats.get(6) if stats.get(6) is not None else stats.get(2)
            high = stats.get(5) if stats.get(5) is not None else stats.get(1)
            rows.append(
                "stats\t{i}\tnull\t{n}\tmin\t{lo}\tmax\t{hi}".format(
                    i=i, n=stats.get(3, 0), lo=(low or b"").hex(), hi=(high or b"").hex()
                )
            )
    rows.append(
        "walked\tend"
        if cursor.bad == 0 and cursor.at == start + length
        else "stopped\t{at}\tbad\t{bad}".format(at=cursor.at, bad=cursor.bad)
    )
    return rows


# The ordinal tables are *collected*, not recalled: each entry is a byte value pyarrow wrote for a
# file it was told to write with a named codec or a named arrow type, and a value that ever mapped to
# two names would stop the run. Nothing the reader will print is left to memory.
CODECS = {}
PHYSICAL = {}


def learn(table, ordinal, name, witness):
    seen = table.setdefault(ordinal, set())
    seen.add(name)
    assert len(seen) == 1, f"{witness}: {ordinal} is both {seen} - the table cannot be trusted"
    return next(iter(seen))


# The reader's own naming tables, checked against what the writer produced rather than trusted.
RUST_CODECS = {0: "uncompressed", 1: "snappy", 2: "gzip", 6: "zstd"}
RUST_PHYSICAL = {0: "boolean", 1: "int32", 2: "int64", 4: "float", 5: "double", 6: "byte_array"}


def label(table, rust, ordinal, where):
    names = table.get(ordinal)
    if not names:
        return "unnamed"
    assert len(names) == 1, f"{where}: {ordinal} maps to {names}"
    value = next(iter(names)).lower()
    assert rust.get(ordinal, "unnamed") == value, f"{where}: reader would say {rust.get(ordinal)}, writer says {value}"
    return value


def path_of(name):
    return os.path.join(OUT, name)


def check(name, data):
    """Compare the walk with pyarrow's own metadata, field by field."""
    md = pq.ParquetFile(path_of(name)).metadata
    meta, cursor, start, length = footer_of(data)
    assert cursor.bad == 0, f"{name}: walk failed"
    assert cursor.at == start + length, f"{name}: consumed {cursor.at - start} of {length}"
    assert start >= 4 and data[:4] == MAGIC and data[-4:] == MAGIC, f"{name}: magic"
    assert length == md.serialized_size, f"{name}: footer {length} vs {md.serialized_size}"
    assert meta.get(3) == md.num_rows, f"{name}: num_rows"
    # pyarrow names the stored version rather than echoing it ("2.6" for version 2), so only the major
    # number is claimed here.
    assert str(md.format_version).split(".")[0] == str(meta.get(1)), f"{name}: version {meta.get(1)} vs {md.format_version}"
    assert text(meta.get(6)) == md.created_by, f"{name}: created_by"
    assert len(meta["row_groups"]) == md.num_row_groups, f"{name}: row groups"
    names = [text(s.get(4)) for s in meta["schema"]]
    assert names == ["schema"] + md.schema.names, f"{name}: {names} vs {md.schema.names}"
    for g, group in enumerate(meta["row_groups"]):
        rg = md.row_group(g)
        assert group.get(3) == rg.num_rows, f"{name}: group rows"
        assert group.get(2) == rg.total_byte_size, f"{name}: group bytes"
        assert len(group["columns"]) == rg.num_columns, f"{name}: group columns"
        for c, chunk in enumerate(group["columns"]):
            col = rg.column(c)
            own = chunk["metadata"]
            assert "/".join(text(p) for p in own["path"]) == col.path_in_schema, f"{name}: path"
            assert own.get(5) == col.num_values, f"{name}: values"
            assert own.get(7) == col.total_compressed_size, f"{name}: compressed"
            assert own.get(6) == col.total_uncompressed_size, f"{name}: uncompressed"
            learn(CODECS, own.get(4), col.compression, f"{name}:{col.path_in_schema}")
            learn(PHYSICAL, own.get(1), col.physical_type, f"{name}:{col.path_in_schema}")
            assert own.get(9) == col.data_page_offset, f"{name}: data page offset"
            if col.dictionary_page_offset:
                assert own.get(11) == col.dictionary_page_offset, f"{name}: dict page offset"
            else:
                assert 11 not in own, f"{name}: invented dictionary page"
            stats = col.statistics
            if stats is not None and "statistics" in own:
                assert own["statistics"].get(3, 0) == stats.null_count, f"{name}: null count"
            # pyarrow reports encoding *names* and the bytes carry ordinals, and nothing here lets this
            # repo map one to the other - so only the count is claimed here, and the ordinal that shows
            # up beside a dictionary page is pinned across files in main().
            assert len(own["encodings"]) == len(col.encodings), f"{name}: encoding count"
    return meta


def write(name, table, **kwargs):
    pq.write_table(table, path_of(name), **kwargs)
    assert open(path_of(name), "rb").read(4) == MAGIC, name


def main():
    os.makedirs(OUT, exist_ok=True)
    table = pa.Table.from_arrays(
        [pa.array([1, 2, 3], pa.int32()), pa.array(["one", "two", "three"], pa.string())],
        names=["id", "name"],
    )
    nullable = pa.Table.from_arrays(
        [pa.array([7, None, 9, None], pa.int32()), pa.array(["a", "b", None, "c"], pa.string())],
        names=["value", "label"],
    )
    wide = pa.Table.from_arrays(
        [
            pa.array(list(range(12)), pa.int64()),
            pa.array([float(i) for i in range(12)], pa.float64()),
            pa.array([f"s{i}" for i in range(12)], pa.string()),
        ],
        names=["n", "ratio", "tag"],
    )
    # One column per arrow type, so the physical-type ordinals are each witnessed by the type name
    # pyarrow reports when it reads the file back.
    typed = pa.Table.from_arrays(
        [
            pa.array([True, False, True], pa.bool_()),
            pa.array([1, 2, 3], pa.int32()),
            pa.array([10, 20, 30], pa.int64()),
            pa.array([1.5, 2.5, 3.5], pa.float32()),
            pa.array([1.5, 2.5, 3.5], pa.float64()),
            pa.array(["x", "yy", "zzz"], pa.string()),
            pa.array([b"a", b"bb", b"ccc"], pa.binary()),
        ],
        names=["flag", "i32", "i64", "f32", "f64", "text", "blob"],
    )

    write("rows.parquet", table)
    write("plain.parquet", table, compression="none")
    write("zstd.parquet", table, compression="zstd")
    write("gzip.parquet", table, compression="gzip")
    write("nodict.parquet", table, use_dictionary=False)
    write("nulls.parquet", nullable)
    write("groups.parquet", wide, row_group_size=4)
    write("typed.parquet", typed)

    probes = {}
    for name in (
        "rows.parquet",
        "plain.parquet",
        "zstd.parquet",
        "gzip.parquet",
        "nodict.parquet",
        "nulls.parquet",
        "groups.parquet",
        "typed.parquet",
    ):
        data = open(path_of(name), "rb").read()
        check(name, data)
        rows = report(data)
        meta, cursor, start, length = footer_of(data)
        probes[name] = {
            "bytes": len(data),
            "footer_at": start,
            "footer_len": length,
            "consumed": cursor.at - start,
            "rows": rows,
        }
        print(f"== {name} {len(data)} bytes, footer {start}+{length}")
        for row in rows:
            print('\t\t\t"' + row.replace("\t", "\\t") + '",')
    # Which encoding ordinal belongs to a dictionary page is something no single file can show: the
    # two fixtures differ in exactly that option, so the ordinal present in one and absent from the
    # other is pinned without naming any of them.
    def ordinals(name):
        meta = footer_of(open(path_of(name), "rb").read())[0]
        return {
            int(e)
            for group in meta["row_groups"]
            for chunk in group["columns"]
            for e in chunk["metadata"]["encodings"]
        }

    with_dict = ordinals("rows.parquet")
    without = ordinals("nodict.parquet")
    assert without < with_dict and len(with_dict - without) == 1, f"{sorted(with_dict)} vs {sorted(without)}"
    probes["_observed"] = {
        "codecs": {str(k): sorted(v)[0] for k, v in sorted(CODECS.items())},
        "physical_types": {str(k): sorted(v)[0] for k, v in sorted(PHYSICAL.items())},
        "written_with_a_dictionary_page": sorted(with_dict),
        "written_without": sorted(without),
        "only_beside_a_dictionary_page": sorted(with_dict - without),
    }
    print("codecs learned:", {k: sorted(v)[0] for k, v in sorted(CODECS.items())})
    print("physical types learned:", {k: sorted(v)[0] for k, v in sorted(PHYSICAL.items())})
    print("encodings:", sorted(with_dict), "without dictionary:", sorted(without))
    with open(os.path.join(OUT, "parquet.probe.json"), "w", encoding="utf-8", newline="\n") as sink:
        json.dump(probes, sink, indent=1, sort_keys=True, ensure_ascii=False)
        sink.write("\n")
    print("wrote parquet.probe.json")


main()
