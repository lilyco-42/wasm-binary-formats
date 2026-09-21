"""Produce and check the PE resource fixtures - the tree a viewer shows in its Resources window.

Two writers, so nothing here is one implementation's habit:

    csc (the .NET compiler service)  ->  res.dll:  ICON x2, GROUP_ICON, VERSIONINFO, MANIFEST, every
                                         identifier numeric, because that is all a managed compiler
                                         ever emits
    rc + llvm-cvtres + lld-link      ->  rcres.dll: three bodies hung on *string* names and string
                                         types, which is the other half of the name table and the half
                                         no .NET tool writes

Three readers have to agree before a probe is written:

    this file's own walk        ->  the directory tree read from the bytes, with the RVA -> file offset
                                    step that is the whole difficulty of the format
    llvm-readobj --coff-resources ->  a second implementation's listing of the same tree, down to
                                    DataRVA, DataSize and Codepage
    Windows itself, through ctypes ->  LoadLibraryExW(LOAD_LIBRARY_AS_DATAFILE), which maps the image
                                    without running a line of it, then EnumResourceTypesW for the set of
                                    types and FindResourceExW + SizeofResource + LockResource for each
                                    body. The last one is the oracle that matters: the bytes Windows
                                    hands back have to equal the bytes at the file offset this walk
                                    computed from the entry's RVA, which is the only way in this lab to
                                    prove the mapping rather than assert it.

    temp/venv/Scripts/python.exe scripts/make-resource-fixtures.py

`rc.exe` and `csc.exe` are both on this host and neither is in CI, so `resource.probe.json` is
regenerate-locally evidence in the class of `jsonc.probe.json` and `xsd.probe.json`: CI compares the
committed rows, it cannot re-make them.
"""

import ctypes as C
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")
SCRATCH = os.path.join(ROOT, "temp", "resource-build")

CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
RC = r"D:\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe"

CS = """using System;
public sealed class Marker {
  public static string Name() { return "lab"; }
}
"""

MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="Rembg.Lab.Res" type="win32"/>
  <description>lab resource fixture</description>
</assembly>
"""

# rc's grammar is `<name> <type> <file>`: the first line has a string name on a numeric type, the next
# two a numeric name on a string type, so both string branches of the tree are in one file.
RC_SOURCE = """LABTYPE 10 "labtype.txt"
11 "LABNAME" "labname.txt"
260 "OTHER" "other.txt"
"""

DIRECTORIES = 16
RESOURCE_DIRECTORY = 2
TABLE_ROWS = 4
ENTRY_ROWS = 3


# ------------------------------------------------------------------ the walk, in a second language
def sections(raw, pe):
    """(virtual address, virtual size, raw pointer, raw size) per section, from the section table."""
    count = struct.unpack_from("<H", raw, pe + 6)[0]
    # SizeOfOptionalHeader is a u16 at pe+20; reading it as a u32 swallows Characteristics and
    # sends the section table off the end of the file, which looks exactly like a PE with none.
    size = struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    table = optional + size
    found = []
    for index in range(count):
        at = table + index * 40
        if size < 40 or at + 40 > len(raw):
            continue
        name = raw[at:at + 8].rstrip(b"\0")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, at + 8)
        found.append((vaddr, vsize, raw_ptr, raw_size, name))
    return found, magic


def offset_of(sections, rva):
    for vaddr, vsize, raw_ptr, raw_size, _name in sections:
        span = max(vsize, raw_size)
        if vaddr <= rva < vaddr + span:
            return raw_ptr + (rva - vaddr)
    return None


def utf16(raw, at, units):
    """A resource identifier string: UTF-16LE, length in *characters*, no terminator of its own."""
    body = raw[at:at + units * 2]
    if len(body) != units * 2:
        return None
    return body.decode("utf-16-le", "replace")


def walk(raw):
    """Every (type, name, language, rva, size, codepage) in document order, plus the table's own words.

    A directory entry's high bit says whether it points at another directory or at a data entry, and an
    identifier with its high bit set on the *next* level's offset says the name is a string rather than
    a number. Nothing else in the format states where a level ends, so the walk is the parsing.
    """
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("no PE signature")
    machine, = struct.unpack_from("<H", raw, pe + 4)
    sections_table, magic = sections(raw, pe)
    base = pe + 24
    wide = magic == 0x20B
    directory = base + (112 if wide else 96)
    rva, size = struct.unpack_from("<II", raw, directory + RESOURCE_DIRECTORY * 8)
    at = offset_of(sections_table, rva)
    if at is None or size == 0:
        return machine, wide, rva, size, []
    found = []

    def each(node):
        """One directory's entries: (is a directory, key, key is a string, label, child offset)."""
        named, ids = struct.unpack_from("<HH", raw, node + 12)
        out = []
        for slot in range(named + ids):
            key, child = struct.unpack_from("<II", raw, node + 16 + slot * 8)
            label = key & 0x7FFF_FFFF
            string = bool(key & 0x80000000)
            if string:
                place = at + label
                units = struct.unpack_from("<H", raw, place)[0]
                label = utf16(raw, place + 2, units)
            out.append((bool(child & 0x80000000), key, string, label, at + (child & 0x7FFF_FFFF)))
        return out

    for _dir, type_key, type_string, type_label, type_where in each(at):
        for _name_dir, name_key, name_string, name_label, name_where in each(type_where):
            for _lang_dir, lang_key, _lang_string, _lang_label, data_where in each(name_where):
                data_rva, data_size, codepage, _reserved = struct.unpack_from("<IIII", raw, data_where)
                found.append({
                    "type": type_label if type_string else type_key,
                    "type_string": type_string,
                    "name": name_label if name_string else name_key,
                    "name_string": name_string,
                    "language": lang_key & 0xFFFF,
                    "rva": data_rva,
                    "size": data_size,
                    "codepage": codepage,
                    "offset": offset_of(sections_table, data_rva),
                })
    return machine, wide, rva, size, found


# --------------------------------------------------------------------------------- the llvm reader
def identifier(body):
    """`ICON (ID 3) [` -> (3, "ICON"); `"LABNAME" [` -> (None, "LABNAME"); `LABTYPE [` -> string name."""
    number = re.search(r"\(ID (\d+)\)", body)
    label = body.split("(ID", 1)[0].strip().rstrip("[").strip().strip('"')
    return (int(number.group(1)) if number else None, label or None)


def readobj(path):
    """`llvm-readobj --coff-resources`, read line by line on its own field names.

    The listing nests, so a brace-counting regex would eat real entries; one line at a time with the
    field's own colon is the only shape that has not misled here. A body is flushed when the next
    `Language:` line arrives, because the data fields are printed *below* the language they belong to.
    """
    made = subprocess.run(["llvm-readobj", "--coff-resources", path], capture_output=True, shell=False,
                          timeout=600)
    if made.returncode != 0:
        raise SystemExit("llvm-readobj refused %s: %s" % (path, made.stderr[:300]))
    text = made.stdout.decode("utf-8", "replace")
    entries = []
    current = {}

    def flush():
        if "rva" in current and "language" in current:
            entries.append(dict(current))

    for line in text.splitlines():
        one = line.strip()
        if one.startswith("Type:"):
            number, label = identifier(one.split(":", 1)[1])
            current = {"type": number if label is None or number is not None else label,
                       "type_id": number, "type_text": label}
        elif one.startswith("Name:"):
            number, label = identifier(one.split(":", 1)[1])
            current["name"] = number if label is None else label
            current["name_id"] = number
            current["name_text"] = label
        elif one.startswith("Language:"):
            number, _label = identifier(one.split(":", 1)[1])
            current["language"] = number
        elif one.startswith("DataRVA:"):
            current["rva"] = int(one.split(":", 1)[1].strip(), 16)
        elif one.startswith("DataSize:"):
            current["size"] = int(one.split(":", 1)[1].strip())
        elif one.startswith("Codepage:"):
            # The last field of a data block, so the entry is complete here and this is the one emit
            # point that does not depend on what line happens to come next.
            current["codepage"] = int(one.split(":", 1)[1].strip())
            flush()
    return entries, text


# -------------------------------------------------------------------------------- the Windows side
LOAD_LIBRARY_AS_DATAFILE = 0x00000002
kernel32 = C.WinDLL("kernel32", use_last_error=True)
# The three callbacks are not one shape: type gets (module, type, param), name gets (module, type,
# name, param), language adds a ushort before the parameter. Getting this wrong is silent - ctypes
# swallows the exception inside a callback and the enumerator just reports nothing.
ENUM_TYPE = C.WINFUNCTYPE(C.c_bool, C.c_void_p, C.c_void_p, C.c_ssize_t)
kernel32.LoadLibraryExW.argtypes = [C.c_wchar_p, C.c_void_p, C.c_uint]
kernel32.LoadLibraryExW.restype = C.c_void_p
kernel32.FreeLibrary.argtypes = [C.c_void_p]
kernel32.EnumResourceTypesW.argtypes = [C.c_void_p, ENUM_TYPE, C.c_ssize_t]
kernel32.EnumResourceTypesW.restype = C.c_bool
kernel32.FindResourceExW.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_ushort]
kernel32.FindResourceExW.restype = C.c_void_p
kernel32.SizeofResource.argtypes = [C.c_void_p, C.c_void_p]
kernel32.SizeofResource.restype = C.c_uint
kernel32.LoadResource.argtypes = [C.c_void_p, C.c_void_p]
kernel32.LoadResource.restype = C.c_void_p
kernel32.LockResource.argtypes = [C.c_void_p]
kernel32.LockResource.restype = C.c_void_p


def as_int(value):
    """An identifier is either an integer wearing a pointer or a pointer to a wide string."""
    number = value if isinstance(value, int) else (C.cast(value, C.c_void_p).value or 0)
    if number <= 0xFFFF:
        return number, None
    return None, C.wstring_at(number)


def windows_view(path, wanted):
    """The type set, and for each entry the size and the first bytes the loader hands over."""
    module = kernel32.LoadLibraryExW(path, None, LOAD_LIBRARY_AS_DATAFILE)
    if not module:
        raise SystemExit("LoadLibraryExW refused %s: %d" % (path, C.get_last_error()))
    types = []

    def each_type(_h, type_at, _param):
        number, text = as_int(type_at)
        types.append(number if number is not None else text)
        return True

    callback = ENUM_TYPE(each_type)
    if not kernel32.EnumResourceTypesW(module, callback, 0):
        raise SystemExit("EnumResourceTypesW failed on %s: %d" % (path, C.get_last_error()))
    seen = []
    keep = []
    for entry in wanted:
        kind = entry["type"]
        name = entry["name"]

        def identifier(value):
            # A numeric id goes in as the integer itself (that is what MAKEINTRESOURCE is); a string
            # one goes in as the address of a buffer that has to stay alive until the call returns.
            if isinstance(value, int):
                return C.c_void_p(value)
            buffer = C.create_unicode_buffer(value)
            keep.append(buffer)
            return C.cast(buffer, C.c_void_p)

        handle = kernel32.FindResourceExW(module, identifier(kind), identifier(name),
                                          entry["language"])
        if not handle:
            seen.append({"looked": "%s/%s/%d" % (kind, name, entry["language"]),
                         "found": False, "error": C.get_last_error()})
            continue
        size = kernel32.SizeofResource(module, handle)
        body = kernel32.LockResource(kernel32.LoadResource(module, handle))
        first = C.string_at(body, min(size, 24)) if body else b""
        seen.append({"looked": "%s/%s/%d" % (kind, name, entry["language"]), "found": True,
                     "size": size, "head": first.hex()})
    kernel32.FreeLibrary(module)
    return sorted(map(str, types)), seen


# ------------------------------------------------------------------------------------ the producers
def run(cmd, note, work):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=work, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:600]))
    return made


def build(work):
    from PIL import Image

    image = Image.new("RGBA", (32, 32))
    for x in range(32):
        for y in range(32):
            image.putpixel((x, y), (x * 8 % 256, y * 8 % 256, 128, 255))
    image.save(os.path.join(work, "a.ico"), format="ICO", sizes=[(16, 16), (32, 32)])
    write(work, "marker.cs", CS)
    write(work, "app.manifest", MANIFEST)
    run([CSC, "-nologo", "/target:library", "/out:res.dll", "/win32icon:a.ico",
         "/win32manifest:app.manifest", "marker.cs"], "csc", work)

    if not os.path.exists(RC):
        raise SystemExit("no rc.exe at %s - the string-named half of the tree needs it" % RC)
    write(work, "lab.rc", RC_SOURCE)
    for name, body in (("labtype.txt", "rc wrote this body\n"), ("labname.txt", "a string name\n"),
                       ("other.txt", "the third one\n")):
        write(work, name, body)
    run([RC, "-nologo", "/fo", "lab.res", "lab.rc"], "rc", work)
    # Microsoft's `rc` writes the tree - it is the only writer here that puts a *string* in the type
    # slot - and then GNU `windres` converts that `.res` into a COFF object and `gcc` links it, so the
    # container comes from a third project. `-nostdlib` keeps the fixture to its resource section
    # instead of dragging in the mingw runtime, which would put 80 KB of somebody else's code in the
    # repository for no reason.
    run(["windres", "-i", "lab.res", "-O", "coff", "-o", "labres.o"], "windres", work)
    run(["gcc", "-shared", "-nostdlib", "-o", "rcres.dll", "labres.o"], "gcc", work)
    for name in ("res.dll", "rcres.dll"):
        if not os.path.exists(os.path.join(work, name)):
            raise SystemExit("no %s was produced" % name)


def write(work, name, text):
    with open(os.path.join(work, name), "w", encoding="utf-8", newline="\r\n") as handle:
        handle.write(text)


def rows_for(machine, wide, directory, entries, words, cap=64):
    """Row 0 of totals, then one `type` row per level-one node and one `entry` row per body.

    Two lists, two caps, two stop rows: the tree is small on every real file and the bodies are not,
    and a report that ran out on one should not have to say so about the other.
    """
    order = []
    for one in entries:
        key = (one["type_string"], one["type"])
        found = next((item for item in order if item[0] == key), None)
        if found is None:
            order.append([key, 0])
            found = order[-1]
        found[1] += 1
    head = "\t".join(["resources",
                      "types\t%d" % len(order),
                      "entries\t%d" % len(entries),
                      "strings\t%d" % (sum(1 for one in entries if one["type_string"])
                                       + sum(1 for one in entries if one["name_string"])),
                      "dir\t%d" % RESOURCE_DIRECTORY,
                      "rva\t0x%x" % directory,
                      "machine\t%s" % ("x86" if machine == 0x14C else "0x%x" % machine),
                      "wide\t%s" % ("yes" if wide else "no")])
    rows = [head]
    for index, (key, bodies) in enumerate(order):
        if index >= cap:
            break
        is_string, value = key
        # The word is llvm's spelling of the identifier, and only for the identifiers these two
        # fixtures actually carry. Microsoft's own header calls the same number `RT_ICON`, so the
        # pair (number, thing) is witnessed twice while the spelling is witnessed once - which is why
        # the word rides in a column of its own instead of standing in for the number.
        word = "-" if is_string else words.get(value, "-")
        rows.append("type\t%d\t%s\t%s\tword\t%s\tbodies\t%d"
                    % (index, "text" if is_string else "id", printable(value), printable(word), bodies))
    listed = 0
    seen = {}
    for one in entries:
        key = (one["type_string"], one["type"])
        index = next(place for place, item in enumerate(order) if item[0] == key)
        number = seen.get(index, 0)
        seen[index] = number + 1
        if listed >= cap:
            break
        rows.append("entry\t%d\t%d\t%s\t%s\tlang\t%d\tbytes\t%d\trva\t0x%x\toff\t%d\tcodepage\t%d"
                    % (index, number,
                       "text" if one["name_string"] else "id", printable(one["name"]),
                       one["language"], one["size"], one["rva"],
                       -1 if one["offset"] is None else one["offset"], one["codepage"]))
        listed += 1
    if len(order) > cap:
        rows.append("cut\ttypes\t%d\tlisted\t%d" % (len(order), cap))
    if len(entries) > cap:
        rows.append("cut\tentries\t%d\tlisted\t%d" % (len(entries), cap))
    return rows


def word(value):
    """A name compared across readers, with the quotes one of them prints taken off."""
    return str(value).strip('"')


def printable(value):
    text = str(value)
    return "".join("?" if char == "\t" or ord(char) < 32 else char for char in text)


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    build(SCRATCH)

    probe = {}
    for name in ("res.dll", "rcres.dll"):
        path = os.path.join(SCRATCH, name)
        raw = open(path, "rb").read()
        machine, wide, directory, directory_size, entries = walk(raw)
        listing, text = readobj(path)
        words = dict((one["type_id"], one["type_text"]) for one in listing
                     if one.get("type_id") is not None and one.get("type_text"))
        if len(listing) != len(entries):
            raise SystemExit("%s: the walk found %d bodies, llvm printed %d\n%s"
                             % (name, len(entries), len(listing), text[:2000]))
        for mine, theirs in zip(entries, listing):
            # rc writes a *string type* with the quote characters inside the stored text, and
            # llvm-readobj prints the name with them taken off; the loader hands back the file's own
            # bytes. So the two are compared on the word, and the row keeps the spelling the file has.
            if (word(mine["type"]), word(mine["name"]), mine["language"]) != (
                    word(theirs["type"]), word(theirs["name"]), theirs["language"]):
                raise SystemExit("%s: walk %r/%r/%r, llvm %r/%r/%r"
                                 % (name, mine["type"], mine["name"], mine["language"],
                                    theirs["type"], theirs["name"], theirs["language"]))
            if (mine["rva"], mine["size"], mine["codepage"]) != (theirs["rva"], theirs["size"],
                                                                theirs["codepage"]):
                raise SystemExit("%s: walk %r, llvm %r" % (name, mine, theirs))
        types, seen = windows_view(path, entries)
        for one in entries:
            if str(one["type"]) not in types:
                raise SystemExit("%s: the loader has no type %r, it lists %s"
                                 % (name, one["type"], types))
        print("=== %s types from Windows: %s" % (name, types))
        for one, answer in zip(entries, seen):
            if not answer.get("found"):
                raise SystemExit("%s: Windows has no %s (%d)" % (name, answer["looked"], answer["error"]))
            if answer["size"] != one["size"]:
                raise SystemExit("%s: SizeofResource %d, the directory entry %d for %s"
                                 % (name, answer["size"], one["size"], answer["looked"]))
            if one["offset"] is None or one["offset"] + one["size"] > len(raw):
                raise SystemExit("%s: rva 0x%x maps nowhere" % (name, one["rva"]))
            head = raw[one["offset"]:one["offset"] + min(one["size"], 24)].hex()
            if head != answer["head"]:
                raise SystemExit("%s: the bytes at offset %d are %s, the loader says %s"
                                 % (name, one["offset"], head, answer["head"]))
        probe[name] = {"bytes": len(raw), "rows": rows_for(machine, wide, directory, entries, words),
                       "entries": [{k: v for k, v in one.items()} for one in entries],
                       "llvm": listing, "windows_types": types,
                       "windows_sizes": [answer["size"] for answer in seen]}
        for row in probe[name]["rows"]:
            print("%-11s %s" % (name, row.replace("\t", " | ")))

    for name in ("res.dll", "rcres.dll"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "resource.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("two fixtures; the walk, llvm-readobj and the Windows loader agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
