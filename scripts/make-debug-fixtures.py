"""Produce and check the PE debug-directory fixtures.

A PE's debug directory is a table of 28-byte entries, each pointing at a block elsewhere in the file
that says what kind of debug information it is and where to find more. It is also how a binary names the
program database it was linked with - the question IDA's Information window answers, and the reason this
window exists: a `.pdb`'s signature, its 16 GUID bytes and its age have to match what the entry states
before anything read out of that file's symbols can be trusted.

Three files, two of them built here and one already a fixture:

    clang --target=x86_64-w64-windows-gnu -c -g -gcodeview dbg.c -o dbg.obj
    lld-link /out:dbg.exe /subsystem:console /entry:lab_first dbg.obj /debug /pdbaltpath:dbg.pdb
    lld-link /out:nodbg.exe /subsystem:console /entry:lab_first dbg.obj

`/entry` is there because nothing on this host links a console `main` for a Windows target without the C
runtime, and `/pdbaltpath` twice over: without it lld records the *absolute* path of the PDB on the
machine that ran the linker - which a committed fixture has no business carrying - and the path a debug
entry holds is supposed to be the one a symbol service looks up, so naming just the file is also the
realistic shape. `nodbg.exe` is the same object linked with no `/debug`: its directory is empty, which
has to come back as nothing rather than as a file with a broken directory. `lab.exe`, already a fixture
from the image work, is a third shape - a CodeView entry whose path is the empty string - and `cv.obj`
is the fourth: a COFF object carries `.debug$S` *sections*, not a directory, so the answer is nothing.

Three readers have to agree before the probe is written:

    this file's walk                        ->  the directory, its entries and each body
    llvm-readobj --coff-debug-directory    ->  LLVM's listing
    pefile's DIRECTORY_ENTRY_DEBUG         ->  pefile's, parsed independently

Every entry's type number, time stamp, version pair, size and both locations are compared, and a
CodeView body's four-byte signature, its GUID, its age and its path are compared too. The GUID travels
as three little-endian integers followed by eight bytes, so the 32 hex digits a reader prints are not
the file's byte order: LLVM brackets them and pefile prints the same digits unbracketed, and both are
checked against the bytes here, which is what earns writing them at all. It is also why the placeholder
lld fills in still reads `LLD PDB.` in ASCII at the end.

One shape this lab cannot produce is the older `CV_INFO_PDB20` body, which rides on the same type number
as `RSDS` and is told apart by its signature alone. Nothing here writes one and no reader was asked to
agree about one, so the reader parses a body only when it starts with `RSDS` and reports any other
body's signature without claiming its fields.

    temp/venv/Scripts/python.exe scripts/make-debug-fixtures.py
"""

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
SCRATCH = os.path.join(ROOT, "temp", "debug-build")

DEBUG_DIRECTORY = 6
ENTRY_BYTES = 28
MAX_LISTED = 64
# Fixed, so that no byte of a committed fixture comes from the clock - the header stamp, the debug
# entry's own stamp and the GUID lld derives all follow from this one number.
STAMP = 1_700_000_000

SOURCE = "long lab_first(long a) { return a + 1; }\nlong use_it(long v) { return lab_first(v) * 2; }\n"


def run(cmd, note):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=SCRATCH, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:600]))
    return made


def build():
    os.makedirs(SCRATCH, exist_ok=True)
    with open(os.path.join(SCRATCH, "dbg.c"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(SOURCE)
    run(["clang", "--target=x86_64-w64-windows-gnu", "-c", "-g", "-gcodeview", "dbg.c", "-o", "dbg.obj"], "clang")
    stamp = "/timeStamp:%d" % STAMP
    run(["lld-link", "/out:dbg.exe", "/subsystem:console", "/entry:lab_first", "dbg.obj", "/debug",
         "/pdbaltpath:dbg.pdb", stamp], "lld-link /debug")
    run(["lld-link", "/out:nodbg.exe", "/subsystem:console", "/entry:lab_first", "dbg.obj", stamp], "lld-link")
    # A committed fixture and a committed probe have to say the same thing, so as little of the file as
    # possible may come from the clock: `/timeStamp` pins the header stamp, the entry's own stamp and
    # what the linker writes around them. What it does not pin is the PDB GUID, which lld randomises per
    # link - so the two files below have to agree everywhere but those sixteen bytes, and the fixture and
    # its probe still travel together.
    run(["lld-link", "/out:again.exe", "/subsystem:console", "/entry:lab_first", "dbg.obj", "/debug",
         "/pdbaltpath:dbg.pdb", stamp], "lld-link again")
    first = open(os.path.join(SCRATCH, "dbg.exe"), "rb").read()
    second = open(os.path.join(SCRATCH, "again.exe"), "rb").read()
    if without_guid(first) != without_guid(second):
        left, right = without_guid(first), without_guid(second)
        where = [one for one in range(min(len(left), len(right))) if left[one] != right[one]][:8]
        raise SystemExit("the link is reproducible except for the GUID: %d bytes differ, first at %s"
                         % (len([one for one in range(min(len(left), len(right)))
                                 if left[one] != right[one]]), where))
    for one in ("again.exe", "again.pdb"):
        where = os.path.join(SCRATCH, one)
        if os.path.exists(where):
            os.remove(where)


def without_guid(data):
    """The file with the sixteen randomised GUID bytes blanked, for the reproducibility check above."""
    found = directory(data)
    if found is None or not found[1]:
        raise SystemExit("dbg.exe is expected to carry one debug entry")
    table = image(data)[0]
    body = body_of(data, table, found[1][0])
    if body is None:
        raise SystemExit("dbg.exe's CodeView body does not map inside the file")
    at, _size = body
    return data[:at + 4] + bytes(16) + data[at + 20:]


# ---------------------------------------------------------------------------- the file's own words
def image(raw):
    """(section table, optional-header offset, magic) for a PE image, or None for anything else."""
    if raw[:2] != b"MZ" or len(raw) < 0x40:
        return None
    pe = struct.unpack_from("<I", raw, 0x3c)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        return None
    count = struct.unpack_from("<H", raw, pe + 6)[0]
    size = struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    table = []
    for index in range(count):
        at = optional + size + index * 40
        if size < 40 or at + 40 > len(raw):
            continue
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, at + 8)
        table.append((vaddr, vsize, raw_ptr, raw_size))
    return table, optional, magic


def where_lies(table, rva):
    for vaddr, vsize, raw_ptr, raw_size in table:
        span = max(vsize, raw_size)
        if vaddr <= rva < vaddr + span:
            return raw_ptr + (rva - vaddr)
    return None


def directory(raw):
    """((rva, offset, size), [(type, time, major, minor, kind, bytes, rva, ptr)]), or None for an object."""
    found = image(raw)
    if found is None:
        return None
    table, optional, magic = found
    if magic == 0x20b:
        at = optional + 112 + DEBUG_DIRECTORY * 8
    elif magic == 0x10b:
        at = optional + 96 + DEBUG_DIRECTORY * 8
    else:
        raise SystemExit("unknown optional-header magic %#x" % magic)
    rva, size = struct.unpack_from("<II", raw, at)
    base = where_lies(table, rva) if size else None
    if base is None:
        return (rva, None, size), []
    items = [struct.unpack_from("<IIHHIIII", raw, base + index * ENTRY_BYTES)
             for index in range(size // ENTRY_BYTES)]
    return (rva, base, size), items


def body_of(raw, table, entry):
    """(offset, length) of an entry's own body, or None where the address maps nowhere."""
    _type, _time, _major, _minor, _kind, size, rva, _ptr = entry
    at = where_lies(table, rva)
    if at is None or size == 0 or at + size > len(raw):
        return None
    return at, size


def path_of(raw, at, limit):
    """The NUL-terminated path at `at`, with tabs and control bytes kept as spaces, as the rows hold them."""
    end = raw.find(b"\0", at, min(at + limit, len(raw)))
    if end < 0:
        return None
    found = raw[at:end].decode("utf-8", "replace")
    return "".join(" " if ch == "\t" or ord(ch) < 32 else ch for ch in found)


# -------------------------------------------------------------------- the two external listings
def number(text, note):
    """The hex word a listing prints for one field; a field without one is a disagreement."""
    found = re.search(r"0x[0-9a-fA-F]+", text or "")
    if found is None:
        raise SystemExit("%s: %r carries no number" % (note, text))
    return int(found.group(0), 16)


def llvm(path):
    made = subprocess.run(["llvm-readobj", "--coff-debug-directory", path], capture_output=True,
                          shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("llvm-readobj refused %s" % path)
    out, current = [], None
    for line in made.stdout.decode("utf-8", "replace").splitlines():
        text = line.strip()
        if text == "DebugEntry {":
            current = {}
        elif text == "}" and current is not None:
            out.append(current)
            current = None
        elif current is not None:
            found = re.fullmatch(r"([A-Za-z]+): *(.*)", text)
            if found:
                current[found.group(1)] = found.group(2).strip()
    return out


def guid_spelled(raw, at):
    """The 16 GUID bytes as both readers spell them: 32 hex digits, no dashes.

    The first three groups are little-endian integers - a `u32`, then two `u16`s - and the last eight
    bytes go as they lie, so the digits are *not* the file's byte order. That is not this script's
    reading: LLVM prints the bracketed form and pefile prints the same digits unbracketed, and both are
    compared against the bytes below, which is what earns the rule. It is also why a GUID lld wrote with
    its placeholder reads `LLD PDB.` in ASCII at the end.
    """
    one, two, three = struct.unpack_from("<IHH", raw, at + 4)
    return "%08x%04x%04x%s" % (one, two, three, raw[at + 12:at + 20].hex())


def type_word(kind, llvm_value, pefile):
    """The word both readers give a debug type number, in LLVM's spelling, or None.

    LLVM writes `CodeView (0x2)` where pefile's map holds `IMAGE_DEBUG_TYPE_CODEVIEW`, so the *kind* is
    said twice and the *spelling* once - the same arrangement as the PE resource types, where the number
    therefore stays in the row and the word only rides beside it.
    """
    mine = re.fullmatch(r"([A-Za-z]+) *\(0x[0-9a-fA-F]+\)", llvm_value or "")
    other = pefile.DEBUG_TYPE.get(kind)
    if mine is None or other is None:
        return None
    if other.lower().replace("_", "") != "imagedebugtype" + mine.group(1).lower().replace("_", ""):
        raise SystemExit("type %d is %r to llvm and %r to pefile" % (kind, llvm_value, other))
    return mine.group(1)


def rows(name, raw, entries, bodies, words):
    (rva, base, size), items = entries
    if not items:
        # An empty directory and no directory at all are the same answer to give the page: nothing. The
        # walk does not report a header row for a list with no entries in it, so a reader cannot invent
        # one either.
        return []
    head = "\t".join(["debug",
                      "entries\t%d" % len(items),
                      "size\t%d" % size,
                      "dir\t%d" % DEBUG_DIRECTORY,
                      "rva\t0x%x" % rva,
                      "off\t%d" % (-1 if base is None else base),
                      "cv\t%d" % sum(1 for one in bodies if one is not None)])
    out = [head]
    for index, one in enumerate(items):
        if index >= MAX_LISTED:
            continue
        out.append("\t".join(["entry", str(index),
                              "type\t%d" % one[4],
                              "name\t%s" % (words[index] or "-"),
                              "time\t0x%x" % one[1],
                              "major\t%d" % one[2],
                              "minor\t%d" % one[3],
                              "bytes\t%d" % one[5],
                              "rva\t0x%x" % one[6],
                              "body\t%s" % (-1 if bodies[index] is None else bodies[index][0]),
                              "ptr\t%d" % one[7]]))
        at, length = bodies[index] if bodies[index] is not None else (None, None)
        if at is None or length < 4:
            continue
        sig = raw[at:at + 4]
        spelled = sig.decode("ascii") if all(32 <= ch < 127 for ch in sig) else "0x%x" % struct.unpack("<I", sig)[0]
        made = ["cv", str(index), "sig\t%s" % spelled]
        if sig == b"RSDS" and length >= 24:
            made.append("guid\t%s" % guid_spelled(raw, at))
            made.append("age\t%d" % struct.unpack_from("<I", raw, at + 20)[0])
            found = path_of(raw, at + 24, length - 24)
            made.append("path\t%s" % (found if found is not None else "-"))
        out.append("\t".join(made))
    if len(items) > MAX_LISTED:
        out.append("cut\tentries\t%d\tlisted\t%d" % (len(items), MAX_LISTED))
    return out


def check(name):
    """One fixture: the walk, LLVM's listing and pefile's, refusing to write unless all three agree."""
    path = os.path.join(SCRATCH, name)
    raw = open(path, "rb").read()
    found = directory(raw)
    listing = llvm(path)
    import pefile
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as error:
        if found is not None:
            raise SystemExit("%s: the walk finds an image, pefile refuses it: %s" % (name, error))
        if listing:
            raise SystemExit("%s: pefile refuses the file, llvm listed %d entries" % (name, len(listing)))
        return None
    try:
        seen = list(getattr(pe, "DIRECTORY_ENTRY_DEBUG", []))
    finally:
        pe.close()
    if found is None:
        if listing or seen:
            raise SystemExit("%s: no header here, yet llvm listed %d and pefile %d"
                             % (name, len(listing), len(seen)))
        return None
    table, _optional, _magic = image(raw)
    entries = found
    items = entries[1]
    bodies = [body_of(raw, table, one) for one in items]
    if len(items) != len(listing) or len(items) != len(seen):
        raise SystemExit("%s: walk %d, llvm %d, pefile %d" % (name, len(items), len(listing), len(seen)))
    words = [type_word(one[4], listing[index].get("Type"), pefile) for index, one in enumerate(items)]
    for index, (mine, one, two) in enumerate(zip(items, listing, seen)):
        note = "%s entry %d" % (name, index)
        for label, value in (("Type", mine[4]), ("TimeDateStamp", mine[1]), ("SizeOfData", mine[5]),
                             ("AddressOfRawData", mine[6]), ("PointerToRawData", mine[7]),
                             ("MajorVersion", mine[2]), ("MinorVersion", mine[3])):
            if number(one.get(label), note) != value:
                raise SystemExit("%s: %s is %d in the file, %r to llvm" % (note, label, value, one.get(label)))
        struct_ = two.struct
        if (struct_.Type, struct_.TimeDateStamp, struct_.SizeOfData, struct_.AddressOfRawData,
                struct_.PointerToRawData, struct_.MajorVersion, struct_.MinorVersion) != (
                mine[4], mine[1], mine[5], mine[6], mine[7], mine[2], mine[3]):
            raise SystemExit("%s: pefile disagrees on the numbers the file states" % note)
        body = bodies[index]
        parsed = getattr(two, "entry", None)
        if body is None:
            continue
        at, _length = body
        sig = raw[at:at + 4]
        spelled = getattr(parsed, "CvSignature", None) if parsed is not None else None
        if spelled is not None and spelled != sig:
            raise SystemExit("%s: the body starts with %r, pefile says %r" % (note, sig, spelled))
        if sig == b"RSDS" and spelled is not None:
            age = struct.unpack_from("<I", raw, at + 20)[0]
            if getattr(parsed, "Age", None) != age:
                raise SystemExit("%s: age is %d in the file, %r to pefile" % (note, age, parsed.Age))
            held = path_of(raw, at + 24, body[1] - 24)
            stated = getattr(parsed, "PdbFileName", b"")
            if held is not None and stated not in (held.encode(), (held + "\0").encode()):
                raise SystemExit("%s: the path reads %r, pefile says %r" % (note, held, stated))
            grouped = guid_spelled(raw, at)
            shown = re.search(r"([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})"
                              r"-([0-9A-Fa-f]{12})", one.get("PDBGUID", ""))
            if shown is None or "".join(shown.groups()) != grouped.upper():
                raise SystemExit("%s: the GUID bytes read %s, llvm prints %r" % (note, grouped, one.get("PDBGUID")))
            if getattr(parsed, "Signature_String", "")[:32].upper() != grouped.upper():
                raise SystemExit("%s: pefile's own spelling %r is not the file's bytes"
                                 % (note, parsed.Signature_String))
    return entries, bodies, words


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    build()
    import pefile
    probe = {}
    for name in ("dbg.exe", "nodbg.exe", "lab.exe", "cv.obj"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        found = check(name)
        raw = open(os.path.join(SCRATCH, name), "rb").read()
        if found is None:
            probe[name] = {"entries": 0, "rows": [], "note": "not a PE image"}
            print("%-11s no header here, and both readers agree" % name)
            continue
        entries, bodies, words = found
        table, _optional, _magic = image(raw)
        made = rows(name, raw, entries, bodies, words)
        probe[name] = {"entries": len(entries[1]), "rows": made}
        for row in made:
            print("%-11s %s" % (name, row.replace("\t", " | ")))
    for name in ("dbg.exe", "nodbg.exe"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "debug.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, llvm-readobj and pefile agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
