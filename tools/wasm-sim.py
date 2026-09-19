"""Mirror of the planned Rust `read_wasm`, run over the artifact CI builds.

The row strings printed here become the assertions in engine/tests/wasmmod.rs, so the test compares
against an observation of real LLVM output rather than against a layout recalled from the spec.
"""

import sys

NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}
# Sections whose body begins with a vec count that is worth naming.
COUNTS = {
    1: "types",
    2: "imports",
    3: "functions",
    4: "tables",
    5: "memories",
    6: "globals",
    7: "exports",
    9: "elements",
    10: "code_bodies",
    11: "data_segments",
    12: "data_count",
}


def leb(data, at):
    value = 0
    shift = 0
    size = 0
    while True:
        if at + size >= len(data):
            return None, 0
        byte = data[at + size]
        value |= (byte & 0x7F) << shift
        size += 1
        shift += 7
        if not byte & 0x80:
            return value, size
        if size > 5:
            return None, 0


def name_at(data, at):
    length, size = leb(data, at)
    if length is None:
        return "", at
    start = at + size
    return data[start : start + length].decode("utf-8", "replace"), start + length


def walk(data):
    if len(data) < 12 or data[:4] != b"\x00asm":
        return None
    version = int.from_bytes(data[4:8], "little")
    rows = []
    counts = {}
    customs = []
    sections = 0
    bad = 0
    at = 8
    truncated = 0
    while at < len(data):
        sid = data[at]
        size, consumed = leb(data, at + 1)
        if size is None or at + 1 + consumed + size > len(data):
            truncated = 1
            break
        body = at + 1 + consumed
        label = NAMES.get(sid, "unknown-%d" % sid)
        rows.append("section\t%s\t%d\t%d" % (label, size, body))
        sections += 1
        if sid in COUNTS:
            value, _ = leb(data, body)
            counts[COUNTS[sid]] = value
        elif sid == 0:
            cname, _ = name_at(data, body)
            customs.append((cname, size))
        if sid not in NAMES:
            bad += 1
        at = body + size
    out = ["wasm\t%d\t%d\t%d" % (version, sections, bad)]
    out.extend(rows)
    for key in (
        "types",
        "imports",
        "functions",
        "tables",
        "memories",
        "globals",
        "exports",
        "elements",
        "code_bodies",
        "data_segments",
        "data_count",
    ):
        if key in counts:
            out.append("%s\t%d" % (key, counts[key]))
    if "functions" in counts and "code_bodies" in counts:
        out.append(
            "code_matches_functions\t%d" % int(counts["functions"] == counts["code_bodies"])
        )
    for cname, size in customs[:16]:
        out.append("custom\t%s\t%d" % (cname, size))
    out.append("truncated\t%d" % truncated)
    if at == len(data):
        out.append("walked\tend")
    return out


for path in sys.argv[1:]:
    print("===", path)
    rows = walk(open(path, "rb").read())
    if rows is None:
        print("rejected")
        continue
    for row in rows:
        print(row)
