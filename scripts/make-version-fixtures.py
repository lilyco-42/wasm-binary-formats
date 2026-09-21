"""Produce and check the version-info probe - what a PE says about itself, read two ways.

The body is already in a committed fixture: `test/fixtures/res.dll` carries a 564-byte VERSIONINFO that
`csc` wrote (the resource round proved how to reach it - directory 2, type 16, and the RVA walked
through the section table). This script parses that tree in Python and then asks Windows the same
questions through `version.dll`, and writes nothing unless the two agree on every number and every
string.

    python scripts/make-version-fixtures.py

Windows is the interesting half of the pair because it is the implementation that ships:
`GetFileVersionInfoSizeW` / `GetFileVersionInfoW` load the file's version block without running the file,
and `VerQueryValueW` answers for one path at a time. It cannot enumerate the string keys, so the keys
come from the walk and the API confirms each one - which is also exactly the shape the panel has.

Three things this run settled, none of which is obvious from a summary of the format:

  * `GetFileVersionInfoSizeW` returns 1132 for a body that is 564 bytes long - the API's size covers the
    block plus what it appends, so it is not a check on the resource's own length.
  * `VerQueryValueW` reports a length in **characters for a text node and in bytes for a binary one**.
    Reading the four-byte `Translation` value as eight invents a second language pair out of the
    `wLength` of whatever node follows it - `0x0194`, 404, the StringTable's own length.
  * A `Var` node can carry `wType = 1` (text) with `wValueLength = 0`, so the character multiplier is
    applied to zero and the child still starts on the next aligned byte.
"""

import ctypes as C
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

VERSIONINFO_TYPE = 16
SIGNATURE = 0xFEEF04BD
CAP = 32


version = C.WinDLL("version", use_last_error=True)
version.GetFileVersionInfoSizeW.argtypes = [C.c_wchar_p, C.POINTER(C.c_uint)]
version.GetFileVersionInfoSizeW.restype = C.c_uint
version.GetFileVersionInfoW.argtypes = [C.c_wchar_p, C.c_uint, C.c_uint, C.c_void_p]
version.GetFileVersionInfoW.restype = C.c_bool
version.VerQueryValueW.argtypes = [C.c_void_p, C.c_wchar_p, C.POINTER(C.c_void_p), C.POINTER(C.c_uint)]
version.VerQueryValueW.restype = C.c_bool


def align(at):
    return (at + 3) & ~3


# ------------------------------------------------------------------- the PE resource walk, again
def resource_body(raw, wanted):
    """The bytes of the first body under resource type `wanted`, found by walking the directory."""
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        return None
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    optsz = struct.unpack_from("<H", raw, pe + 20)[0]
    opt = pe + 24
    wide = struct.unpack_from("<H", raw, opt)[0] == 0x20B
    rva, size = struct.unpack_from("<II", raw, opt + (112 if wide else 96) + 16)
    table = opt + optsz
    spans = []
    for index in range(nsec):
        at = table + index * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, at + 8)
        if raw_size:
            spans.append((vaddr, max(vsize, raw_size), raw_ptr))

    def where(address):
        for base, span, place in spans:
            if base <= address < base + span:
                return place + (address - base)
        return None

    base = where(rva)
    if base is None or size == 0:
        return None

    def each(node_at):
        named, ids = struct.unpack_from("<HH", raw, node_at + 12)
        for slot in range(named + ids):
            key, child = struct.unpack_from("<II", raw, node_at + 16 + slot * 8)
            yield bool(child & 0x80000000), key & 0x7FFFFFFF, base + (child & 0x7FFFFFFF)

    for is_dir, type_id, type_where in each(base):
        if not is_dir or type_id != wanted:
            continue
        for name_dir, _name_id, name_where in each(type_where):
            if not name_dir:
                continue
            for lang_dir, _language, data_where in each(name_where):
                if lang_dir:
                    continue
                body_rva, body_size = struct.unpack_from("<II", raw, data_where)
                place = where(body_rva)
                return None if place is None else raw[place:place + body_size]
    return None


# ---------------------------------------------------------------------------- the structure, in python
def clean(text):
    """The same rule the reader applies: a tab or a newline in a value would invent a column."""
    return "".join(" " if ch in "\t\n\r" else ch for ch in text)


def node(raw, at):
    if at + 6 > len(raw):
        return None
    length, value_length, kind = struct.unpack_from("<HHH", raw, at)
    if length == 0:
        return None
    stop = min(at + length, len(raw))
    end = at + 6
    while end + 1 < stop and raw[end:end + 2] != b"\0\0":
        end += 2
    if end + 1 >= stop:
        return None
    key = raw[at + 6:end].decode("utf-16-le", "replace")
    value_at = align(end + 2)
    count = value_length * (2 if kind == 1 else 1)
    return key, raw[value_at:value_at + count], align(value_at + count), stop


def parse(raw):
    """(fixed words, tables, [(table, key, value)]) for one VS_VERSIONINFO body."""
    root = node(raw, 0)
    if root is None or root[0] != "VS_VERSION_INFO":
        return None
    fixed = struct.unpack("<13I", root[1][:52]) if len(root[1]) >= 52 else None
    tables = []
    strings = []

    def walk(at, stop, parent):
        while True:
            at = align(at)
            if at >= stop:
                return
            one = node(raw, at)
            if one is None:
                return
            key, value, kids, end = one
            if key == "Translation":
                pairs = [pair for pair in struct.iter_unpack("<HH", value)]
                tables.extend(pairs)
                strings.append((parent, "translation", " ".join("%04x%04x" % pair for pair in pairs)))
            elif parent.startswith("StringFileInfo") and value:
                strings.append((parent, key, value.decode("utf-16-le", "replace").rstrip("\0")))
            walk(kids, end, key if not parent else "%s\\%s" % (parent, key))
            at = end

    walk(root[2], root[3], "")
    return fixed, tables, strings


# ----------------------------------------------------------------------------------- the API's view
def api_view(path, keys):
    """What `version.dll` says about the file. It cannot enumerate, so `keys` come from the tree walk -
    which is why the probe can be asked about `Assembly Version`, a key no standard list carries."""
    size = version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    block = C.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path, 0, size, block):
        return None

    def query(where, characters):
        pointer = C.c_void_p()
        length = C.c_uint()
        if not version.VerQueryValueW(block, where, C.byref(pointer), C.byref(length)):
            return None
        body = C.string_at(pointer.value, length.value * (2 if characters else 1))
        # `characters` is the flag this API forces on the caller: a text node's reported length counts
        # UTF-16 units *including* the terminator, a binary node's counts bytes.
        return body.decode("utf-16-le", "replace").rstrip("\0") if characters else body

    fixed = query("\\", False)
    words = struct.unpack("<13I", fixed[:52]) if fixed else None
    blob = query("\\VarFileInfo\\Translation", False)
    tables = [pair for pair in struct.iter_unpack("<HH", blob or b"")]
    strings = {}
    for language, codepage in tables:
        table = "%04x%04x" % (language, codepage)
        for key in keys:
            found = query("\\StringFileInfo\\%s\\%s" % (table, key), True)
            if found is not None:
                strings[key] = found
    return {"size": size, "fixed": words, "tables": ["%04x%04x" % pair for pair in tables],
            "strings": strings}


def rows(fixed, tables, strings):
    out = ["version\tsignature\t0x%08x\tstruct\t%d.%d\tfile\t%d.%d.%d.%d\tproduct\t%d.%d.%d.%d"
           "\tflags-mask\t0x%x\tflags\t0x%x\tos\t0x%x\ttype\t0x%x\tsubtype\t0x%x\tdate\t%d"
           "\ttables\t%d\tstrings\t%d"
           % (fixed[0], fixed[1] >> 16, fixed[1] & 0xFFFF,
              fixed[2] >> 16, fixed[2] & 0xFFFF, fixed[3] >> 16, fixed[3] & 0xFFFF,
              fixed[4] >> 16, fixed[4] & 0xFFFF, fixed[5] >> 16, fixed[5] & 0xFFFF,
              fixed[6], fixed[7], fixed[8], fixed[9], fixed[10],
              (fixed[11] << 32) | fixed[12], len(tables),
              sum(1 for one in strings if one[1] != "translation"))]
    for index, (language, codepage) in enumerate(tables):
        out.append("translation\t%d\tlang\t0x%04x\tcodepage\t0x%04x" % (index, language, codepage))
    for _parent, key, value in strings:
        if key == "translation":
            continue
        out.append("string\t%s\t%s" % (key, clean(value)))
    return out


def main():
    probe = {}
    for name in ("res.dll", "rcres.dll"):
        path = os.path.join(FIX, name)
        raw = open(path, "rb").read()
        body = resource_body(raw, VERSIONINFO_TYPE)
        if body is None:
            size = version.GetFileVersionInfoSizeW(path, None)
            if size:
                raise SystemExit("%s: the tree holds no type %d, version.dll reports %d bytes"
                                 % (name, VERSIONINFO_TYPE, size))
            probe[name] = {"body": None, "api": None, "rows": [],
                           "note": "no resource of type %d" % VERSIONINFO_TYPE}
            print("%-10s no VERSIONINFO body, and the API agrees" % name)
            continue
        found = parse(body)
        if found is None:
            raise SystemExit("%s: the body is not a VS_VERSION_INFO tree" % name)
        fixed, tables, strings = found
        seen = api_view(path, sorted(set(one[1] for one in strings) - {"translation"}))
        if seen is None:
            raise SystemExit("%s: the file states a version block the API will not load" % name)
        if fixed[0] != SIGNATURE:
            raise SystemExit("%s: signature is 0x%08x, not 0x%08x" % (name, fixed[0], SIGNATURE))
        if fixed != seen["fixed"]:
            raise SystemExit("%s: walk %r, version.dll %r" % (name, fixed, seen["fixed"]))
        if ["%04x%04x" % pair for pair in tables] != seen["tables"]:
            raise SystemExit("%s: walk tables %r, version.dll %r"
                             % (name, tables, seen["tables"]))
        for _parent, key, value in strings:
            if key == "translation":
                continue
            if clean(value) != seen["strings"].get(key):
                raise SystemExit("%s: %s is %r to the walk and %r to version.dll"
                                 % (name, key, value, seen["strings"].get(key)))
        for key in seen["strings"]:
            if not any(one[1] == key for one in strings):
                raise SystemExit("%s: version.dll has %s, the file's tree does not list it" % (name, key))
        made = rows(fixed, tables, strings)
        probe[name] = {"body": len(body), "api": seen["size"], "rows": made,
                       "tables": ["%04x%04x" % pair for pair in tables],
                       "walk_strings": len(strings)}
        for row in made:
            print("%-10s %s" % (name, row.replace("\t", " | ")))
        print("%-10s body %d bytes, version.dll works with %d"
              % ("", probe[name]["body"], probe[name]["api"]))

    with open(os.path.join(FIX, "version.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d fixtures; the tree walk and version.dll agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
