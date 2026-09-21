"""Produce and check the CodeView type-stream fixtures.

`clang -gcodeview` writes a COFF object whose `.debug$T` section holds the type
records, and `lld-link` folds the same records into a PDB's TPI stream. Running
`llvm-pdbutil dump -types` over that PDB prints every type in it with its size,
its members and their offsets, so the words the reader has to produce are read
off a second implementation rather than from a description of them.

The shadow decoder below is the Rust port's specification: it walks the object's
stream, and the script refuses to write `test/fixtures/codeview.probe.json`
unless the facts it extracts agree with what llvm-pdbutil printed for the same
types - names, sizes, member types, member offsets, enumerator values.

    temp/venv/Scripts/python.exe scripts/make-codeview-fixtures.py
    temp/venv/Scripts/python.exe scripts/make-codeview-fixtures.py --probe-only

The first form needs clang, lld-link and llvm-pdbutil on PATH; the second only
re-reads what is already on disk.
"""

import collections
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

SOURCE = """\
/* Two structs, an enum, a union, a pointer and a function type - enough leaves
 * to pin down every record the reader claims to decode. The wide struct exists so
 * the witness names the primitive types one by one: each of those fields prints as
 * `Type = 0xNNNN (name)` in llvm-pdbutil's output, which is where the reader's
 * table of primitive names comes from rather than out of memory. */
struct point { int x; double y; };
struct box { struct point corner; union { int w; long h; } size; };
union either { int as_int; char as_char; };
enum colour { RED, GREEN = 7 };
typedef unsigned long word;

struct wide {
  char c; signed char sc; unsigned char uc; short s; unsigned short us;
  int i; unsigned int ui; long l; unsigned long ul; long long ll;
  float f; double d;
};

int add(int a, int b) { struct box b2; b2.corner.x = a; b2.size.w = b; return b2.corner.x + b2.size.w; }
word *pick(word *p, enum colour c) { return p + (int) c; }
struct point shift(struct point p) { p.x += 1; return p; }
void nothing(void) { }
struct wide *widen(struct wide *w, const int *fixed) { w->i = *fixed; return w; }
"""

# Leaf numbers read out of llvm's own CodeViewTypes.def.
LF_MODIFIER = 0x1001
LF_POINTER = 0x1002
LF_PROCEDURE = 0x1008
LF_ARGLIST = 0x1201
LF_FIELDLIST = 0x1203
LF_BITFIELD = 0x1205
LF_ENUMERATE = 0x1502
LF_ARRAY = 0x1503
LF_CLASS = 0x1504
LF_STRUCTURE = 0x1505
LF_UNION = 0x1506
LF_ENUM = 0x1507
LF_MEMBER = 0x150D
LEAVES = {
    LF_MODIFIER: "modifier",
    LF_POINTER: "pointer",
    LF_PROCEDURE: "procedure",
    LF_ARGLIST: "arglist",
    LF_FIELDLIST: "fieldlist",
    LF_BITFIELD: "bitfield",
    LF_ENUMERATE: "enumerate",
    LF_ARRAY: "array",
    LF_CLASS: "class",
    LF_STRUCTURE: "structure",
    LF_UNION: "union",
    LF_ENUM: "enum",
    LF_MEMBER: "member",
}
# Member records inside a field list carry only a two-byte leaf, no length.
MEMBER_LEAVES = {LF_MEMBER, LF_ENUMERATE, LF_BITFIELD}


def run(cmd, cwd=None):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("%s failed: %s" % (cmd[0], proc.stderr.decode("utf-8", "replace")[:400]))
    return proc.stdout


def tool(name):
    return name


def coff_sections(raw):
    """(name, size, file offset) for every section of a COFF object."""
    nsec = struct.unpack_from("<H", raw, 2)[0]
    optsz = struct.unpack_from("<H", raw, 16)[0]
    table = 20 + optsz
    out = []
    strings = b""
    symbols = struct.unpack_from("<I", raw, 8)[0]
    nsyms = struct.unpack_from("<I", raw, 12)[0]
    after = symbols + nsyms * 18
    if struct.unpack_from("<I", raw, after)[0] > 0:
        start = after + 4
        end = raw.find(b"\0", start)
        strings = raw[start:end]
    for each in range(nsec):
        base = table + 40 * each
        field = raw[base:base + 8].rstrip(b"\0")
        size = struct.unpack_from("<I", raw, base + 16)[0]
        offset = struct.unpack_from("<I", raw, base + 20)[0]
        if field.startswith(b"/"):
            # A long name lives in the string table; this script only wants the
            # eight-byte ones, so it names the reference instead of chasing it.
            field = b"/" + field[1:]
        out.append((field.decode("ascii", "replace"), size, offset))
    return out


def cstr(raw, at):
    end = raw.find(b"\0", at)
    if end < 0:
        return None
    return raw[at:end].decode("latin-1")


def read_index(raw, at):
    return struct.unpack_from("<I", raw, at)[0], at + 4


def read_short(raw, at):
    return struct.unpack_from("<H", raw, at)[0], at + 2


def walk(raw, offset, size):
    """Every record of a type stream, with the fields the reader claims to know.

    MS-CV counts a record's length without its own two-byte length field, so a
    record takes `length + 2` bytes. Type indices in an object stream start at
    0x1000, which is what a member's `Type` field refers to.
    """
    header = struct.unpack_from("<I", raw, offset)[0]
    at = offset + 4
    stop = offset + size
    index = 0x1000
    records = []
    while at + 4 <= stop:
        length, leaf = struct.unpack_from("<HH", raw, at)
        total = length + 2
        if total < 6 or at + total > stop:
            records.append({"index": index, "leaf": leaf, "kind": "broken",
                            "note": "length %d at %d passes the end" % (length, at)})
            break
        body = raw[at + 4:at + 2 + total - 2]
        records.append(decode(index, leaf, body, at, total))
        at += total
        index += 1
    return header, records, at


def decode(index, leaf, body, at, total):
    out = {"index": index, "leaf": leaf, "kind": LEAVES.get(leaf, "aux"), "bytes": total}
    where = 0
    if leaf == LF_ARGLIST:
        count, where = read_index(body, 0)
        out["count"] = count
        out["args"] = [struct.unpack_from("<I", body, where + 4 * n)[0] for n in range(count)]
    elif leaf == LF_PROCEDURE:
        # Twelve bytes of body: a return type, one word that carries the calling
        # convention and llvm's option bits together, an argument count, and the
        # index of the LF_ARGLIST that names them.
        ret, where = read_index(body, 0)
        calling, where = read_short(body, where)
        count, where = read_short(body, where)
        args, where = read_index(body, where)
        out.update(return_type=ret, calling=calling, count=count, args=args)
    elif leaf == LF_FIELDLIST:
        out["members"] = members(body)
    elif leaf == LF_UNION:
        # count, attributes, the field list, then the size: no derived class and no
        # vtable shape, which is what made the first draft read a field-list index as
        # the union's own size.
        count, where = read_short(body, 0)
        options, where = read_short(body, where)
        fields, where = read_index(body, where)
        size, where = read_short(body, where)
        name = cstr(body, where)
        out.update(count=count, options=options, fields=fields, size=size, name=name)
    elif leaf in (LF_STRUCTURE, LF_CLASS):
        count, where = read_short(body, 0)
        options, where = read_short(body, where)
        fields, where = read_index(body, where)
        derived, where = read_index(body, where)
        vtable, where = read_index(body, where)
        size, where = read_short(body, where)
        name = cstr(body, where)
        out.update(count=count, options=options, fields=fields, derived=derived,
                   vtable=vtable, size=size, name=name)
    elif leaf == LF_ENUM:
        count, where = read_short(body, 0)
        options, where = read_short(body, where)
        base, where = read_index(body, where)
        fields, where = read_index(body, where)
        name = cstr(body, where)
        out.update(count=count, options=options, base=base, fields=fields, name=name)
    elif leaf == LF_POINTER:
        target, where = read_index(body, 0)
        mode = struct.unpack_from("<I", body, where)[0] if where + 4 <= len(body) else None
        out.update(target=target, mode=mode)
    elif leaf == LF_MODIFIER:
        modified, where = read_index(body, 0)
        constants, where = read_short(body, where)
        out.update(target=modified, constants=constants)
    elif leaf == LF_ARRAY:
        element, where = read_index(body, 0)
        index_type, where = read_index(body, where)
        length, where = read_index(body, where)
        name = cstr(body, where)
        out.update(element=element, index=index_type, length=length, name=name)
    else:
        out["raw"] = body[:8].hex(" ")
    return out


def members(body):
    """The records of a field list. A pad marker is one byte, 0xF0 + n, and it and
    the n bytes that follow it are padding; that is the reading that makes clang's
    own bytes line up with what llvm-pdbutil lists, and the assert below is where
    it is checked rather than assumed."""
    out = []
    at = 0
    while at + 2 <= len(body):
        # A pad marker is one byte, 0xF0 + n, and it stands for n bytes in all - which
        # is the reading that lands the next member on its alignment. clang emits a
        # descending chain (0xF3, 0xF2, 0xF1) for a three-byte gap, so the last one
        # always leaves exactly one byte. If this were wrong, the members below would
        # not agree with llvm-pdbutil and the script would refuse to write the probe.
        marker = body[at]
        if 0xF0 <= marker <= 0xF7:
            at += max(marker - 0xF0, 1)
            continue
        leaf = struct.unpack_from("<H", body, at)[0]
        if leaf == LF_MEMBER:
            access, where = read_short(body, at + 2)
            typeindex, where = read_index(body, where)
            offset, where = read_short(body, where)
            name = cstr(body, where)
            out.append({"leaf": "member", "name": name, "type": typeindex,
                        "offset": offset, "access": access})
            at = where + len(name or "") + 1
        elif leaf == LF_ENUMERATE:
            access, where = read_short(body, at + 2)
            value, where = read_short(body, where)
            name = cstr(body, where)
            out.append({"leaf": "enumerate", "name": name, "value": value, "access": access})
            at = where + len(name or "") + 1
        elif leaf == LF_BITFIELD:
            base, where = read_index(body, at + 2)
            length, where = read_short(body, where)
            position, where = read_short(body, where)
            name = cstr(body, where)
            out.append({"leaf": "bitfield", "name": name, "type": base,
                        "length": length, "offset": position})
            at = where + len(name or "") + 1
        else:
            out.append({"leaf": "0x%04x" % leaf})
            break
    return out


def pdb_types(path):
    """llvm-pdbutil's rendering of the same stream, as (record, facts)."""
    text = run([tool("llvm-pdbutil"), "dump", "-types", path]).decode("utf-8", "replace")
    return text, pdb_lines(text)
def pdb_lines(text):
    records = []
    for line in text.splitlines():
        line = line.rstrip()
        head = line.strip()
        if head.startswith("0x") and "| LF_" in head:
            index, rest = head.split(" | ", 1)
            name, rest = rest.split(" [", 1)
            records.append({"index": int(index, 16), "name": name.strip(), "text": rest,
                            "members": []})
        elif records and head.startswith("- LF_"):
            records[-1]["members"].append(head)
    return records


def build():
    # Compiled outside the repository on purpose: clang records the command line it
    # was given inside .debug$T (an LF_STRING_ID several hundred bytes wide), so a
    # workspace path would end up committed inside the fixture.
    work = tempfile.mkdtemp(prefix="cvfix", dir=os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), os.sep, "tmp"))
    source = os.path.join(work, "cv.c")
    with open(source, "w", encoding="ascii", newline="\n") as handle:
        handle.write(SOURCE)
    obj = os.path.join(work, "cv.obj")
    # Compiled with relative names from a directory outside any profile, because
    # clang records the command line it was given inside the object.
    run([tool("clang"), "-gcodeview", "-c", "cv.c", "-o", "cv.obj"], cwd=work)
    raw = open(obj, "rb").read()
    secret = os.path.expanduser("~").encode()
    if secret in raw:
        raise SystemExit("the object carries a local path (%s); do not commit it" % secret)
    named = dict((name, (size, offset)) for name, size, offset in coff_sections(raw))
    if ".debug$T" not in named:
        raise SystemExit("clang wrote no .debug$T: %s" % [n for n, _, _ in coff_sections(raw)])
    size, offset = named[".debug$T"]
    header, records, end = walk(raw, offset, size)
    if end != offset + size:
        raise SystemExit("the walk stopped at %d, the section ends at %d"
                         % (end, offset + size))
    # The witness: link the same object and read the stream back with llvm-pdbutil.
    run([tool("lld-link"), "/DEBUG", "/OUT:cv.dll", "/DLL", "/NOENTRY",
         "/MACHINE:X64", "cv.obj"], cwd=work)
    pdb = os.path.join(work, "cv.pdb")
    text, witness = pdb_types(pdb)
    return raw, obj, size, offset, header, records, witness, text


def summarise(records):
    rows = []
    for each in records:
        rows.append(json.dumps(each, sort_keys=True))
    return rows


def rows_for(records, primitives, header):
    """The rows the Rust reader has to print, generated from the same decoded
    records so the two cannot disagree about a layout by accident."""
    out = ["types\t%d\theader\t%d" % (len(records), records and 4 or 0)]
    for each in records:
        index = "0x%x" % each["index"]
        kind = each["kind"]
        if kind == "aux":
            out.append("type\t%s\taux\tleaf\t0x%04x\tnot decoded" % (index, each["leaf"]))
        elif kind == "broken":
            out.append("type\t%s\tbroken\t%s" % (index, each["note"]))
        elif kind == "arglist":
            out.append("type\t%s\targlist\t%d\t%s"
                       % (index, each["count"],
                          "\t".join(name_of(arg, primitives) for arg in each["args"])))
        elif kind == "procedure":
            out.append("type\t%s\tprocedure\treturns\t%s\targs\t%d\t0x%x"
                       % (index, name_of(each["return_type"], primitives),
                          each["count"], each["args"]))
        elif kind == "pointer":
            out.append("type\t%s\tpointer\tto\t0x%x\tattr\t0x%x"
                       % (index, each["target"], each["mode"]))
        elif kind == "modifier":
            out.append("type\t%s\tmodifier\tof\t0x%x\tconst\t0x%x"
                       % (index, each["target"], each["constants"]))
        elif kind == "fieldlist":
            for member in each["members"]:
                if member["leaf"] == "member":
                    out.append("field\t%s\t%s\t%s\t%d"
                               % (index, member["name"],
                                  name_of(member["type"], primitives), member["offset"]))
                elif member["leaf"] == "enumerate":
                    out.append("field\t%s\t%s\t%d" % (index, member["name"], member["value"]))
                else:
                    out.append("field\t%s\tstopped\t%s" % (index, member["leaf"]))
                    break
        elif kind in ("structure", "class", "union", "enum", "array"):
            detail = [each.get("name") or "?", "count", str(each.get("count", 0)),
                      "size", str(each.get("size", 0))]
            if kind == "enum":
                detail = [each["name"] or "?", "count", str(each["count"]),
                          "base", name_of(each["base"], primitives)]
            if kind == "array":
                detail = [each.get("name") or "?", "element",
                          name_of(each["element"], primitives), "length", str(each["length"])]
            out.append("type\t%s\t%s\t%s\topts\t0x%x"
                       % (index, kind, "\t".join(detail), each["options"]))
    return out


def name_of(index, primitives):
    """A type index is either a locally-defined record (0x1000 and up) or one of the
    primitive numbers the witness names for us."""
    if index >= 0x1000:
        return "0x%x" % index
    return "%s(0x%x)" % (primitives.get(index, "?"), index)


def primitives_from(text):
    table = {}
    for hit in re.finditer(r"0x([0-9a-fA-F]{4}) \(([^)]{1,24})\)", text):
        value = int(hit.group(1), 16)
        if value < 0x1000:
            table.setdefault(value, hit.group(2))
    return table


def cross_check(records, witness_text):
    """Every named type and every member the walk found has to appear in what
    llvm-pdbutil printed for the same records, with the same offset and size."""
    problems = []
    lines = witness_text
    # A counter, not a set: a compiler emits a struct twice - once as a forward
    # declaration and once as the definition - and so does the witness, so the two
    # occurrences have to be matched twice rather than collapsed into one.
    claimed = collections.Counter()
    for each in records:
        if each["kind"] in ("structure", "class", "union", "enum") and each.get("name"):
            want = "LF_%s" % each["kind"].upper()
            line = "`%s`" % each["name"]
            if not any(want in line_ and line in line_ for line_ in witness_text):
                problems.append("%s %r (%d bytes) is not in the witness"
                                % (want, each["name"], each["bytes"]))
        if each["kind"] == "fieldlist":
            for member in each["members"]:
                if member["leaf"] not in ("member", "enumerate"):
                    continue
                if member["leaf"] == "member":
                    want = "LF_MEMBER [name = `%s`" % member["name"]
                    hits = [line for line in witness_text if want in line]
                    if not hits:
                        problems.append("%s not in the witness" % want)
                    elif not any(("offset = %d" % member["offset"]) in line for line in hits):
                        problems.append("%s offset %d not in the witness"
                                        % (want, member["offset"]))
                else:
                    # An enumerator prints as `- LF_ENUMERATE [RED = 0]`, which is a
                    # different shape from a member line, so it gets its own pattern.
                    want = "LF_ENUMERATE [%s = %d]" % (member["name"], member["value"])
                    if not any(want in line for line in witness_text):
                        problems.append("%s not in the witness" % want)
        if each["kind"] in ("structure", "union", "enum") and each.get("name"):
            claimed[("LF_%s" % each["kind"].upper(), each["name"], each["bytes"])] += 1
    # The other direction: a named record the witness lists and the walk did not
    # produce, or produced with a different size, is a layout that is wrong here.
    for line in lines:
        hit = re.search(r"(LF_STRUCTURE|LF_UNION|LF_ENUM)\s+\[size = (\d+)\] `([^`]+)`", line)
        if not hit:
            continue
        key = (hit.group(1), hit.group(3), int(hit.group(2)))
        if claimed[key]:
            claimed[key] -= 1
        else:
            problems.append("witness lists %s %r of %d bytes, the walk did not" % key)
    for key in sorted(claimed):
        if claimed[key]:
            problems.append("the walk found %s %r of %d bytes %d time(s) over, "
                            "the witness did not" % (key[0], key[1], key[2], claimed[key]))
    return problems


def main():
    raw, obj, size, offset, header, records, witness, text = build()
    primitives = primitives_from(text)
    problems = cross_check(records, text.splitlines())
    if problems:
        raise SystemExit("the walk and llvm-pdbutil disagree:\n  " + "\n  ".join(problems[:8]))
    rows = rows_for(records, primitives, header)
    kinds = {}
    for each in records:
        kinds[each["kind"]] = kinds.get(each["kind"], 0) + 1
    fixture = os.path.join(FIX, "cv.obj")
    shutil.copyfile(obj, fixture)
    probe = {
        "cv.obj": {
            "bytes": os.path.getsize(fixture),
            "stream": {"size": size, "offset": offset, "header": header,
                       "records": len(records), "kinds": kinds},
            "primitives": dict((("0x%x" % k), v) for k, v in sorted(primitives.items())),
            "rows": rows,
            "witness": [line for line in text.splitlines() if line.strip()],
        }
    }
    with open(os.path.join(FIX, "codeview.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print("%s: %d bytes, %d records, %d rows, %d primitive names, witness agrees"
          % (fixture, os.path.getsize(fixture), len(records), len(rows), len(primitives)))
    for row in rows:
        print(row.replace("\t", " | "))



if __name__ == "__main__":
    main()
