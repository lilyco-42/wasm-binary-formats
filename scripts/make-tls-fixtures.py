"""Produce and check the PE TLS-directory fixtures.

Directory 9 is the thread-local storage table: the template block a new thread's TLS area is copied
from, where the TLS index goes, and - the part that matters to an analyser - a list of callbacks the
loader runs before `DllMain` exists. IDA lists those callbacks as functions the program never calls,
and a reader that stops at "there is a TLS section" has not said anything about them.

Two files, both from `gcc` for its own Windows target, so the container comes from a third project
after `csc` and `lld`:

    gcc -shared -O1 -g0 -Wl,-s tls.c -o tls.dll   (a _Thread_local int and 70 TLS callbacks)
    gcc -shared -O1 -g0 -Wl,-s plain.c -o plain.dll (a translation unit with no thread-local object)

The second one is the more instructive of the pair: mingw supplies `_tls_used` in its own start code,
so a DLL built from a file that never mentions `_Thread_local` still carries a directory with two
callbacks in it. "There is no TLS here" is not something a reader may conclude from the source, and a
row set that only lists `tls.dll` would suggest otherwise.

Five readings have to agree before the probe is written:

    this file's walk                   ->  directory 9, the six fields, and the array behind the fourth
    llvm-readobj --coff-tls-directory  ->  LLVM's listing of the same six
    pefile's DIRECTORY_ENTRY_TLS       ->  pefile's, which keeps them as the file has them
    directory 5, the base relocations  ->  which slots the linker filled, and so how long the array is
    Windows, through ctypes            ->  which callbacks ran, and in what order

The last two are the ones worth having. Every entry the linker wrote an address into gets a base
relocation, and the terminating zero does not, so the fixup list enumerates the array without reading
it - which is what bounds its length independently of this script's stop rule. And each of the 70
callbacks records its own number in a table as it runs, so the order the loader walked the array in is
a fact taken from the loader rather than an assumption about section names: it is also the only way to
show that a callback is called at all, which no static reader can prove about itself. `tls.dll` walks
73 entries and reports 70 of them, which is the same thing seen from the other side - three of them
belong to the CRT and write nothing.

Both readers print the fields as virtual addresses (`0x2f6631000`), so a row carries the number the
file holds, that number as an RVA, the file offset the RVA maps to, and the section that owns it - for
every callback too, which is the only way to show a reader subtracted the base once and not twice.

What two runs of this script give back: the same rows - the probe came out byte-identical - and not
the same file. `SOURCE_DATE_EPOCH` is set for the link because `ld` otherwise writes the clock into the
header stamp, and it pins that one; two builds of the same source still differ in 206 bytes of
`tls.dll` and 61 of `plain.dll`, at the same size. Nothing here claims the files are reproducible, and
nothing downstream may hash them: the offsets the rows name are stable, the bytes beside them are not.
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
SCRATCH = os.path.join(ROOT, "temp", "tls-build")

TLS_DIRECTORY = 9
# The base relocations, which are the fifth directory - the sixth is the debug one, and mixing them up
# is easy enough to do silently, since both are just an RVA and a size.
RELOC_DIRECTORY = 5
MAX_LISTED = 64
# More callbacks than a panel lists, so the cut row is a measured thing rather than a hope.
CALLBACKS = 70

HEAD = """#include <windows.h>

_Thread_local int tls_counter = 7;

/* What the loader has run through: every callback below writes its own number at the next free slot,
   so the table read back after the load is the order the array was walked rather than a set, and the
   count says how many of them ran. */
static LONG ran;
static LONG order[256];

#define note(who)             \\
  do {                        \\
    LONG at = ran;            \\
    if (at < 256)             \\
      order[at] = (who) + 1;  \\
    ran = at + 1;             \\
  } while (0)

LONG __cdecl
lab_ran (void)
{
  return ran;
}

LONG __cdecl
lab_order (LONG at)
{
  return at >= 0 && at < 256 ? order[at] : -1;
}
"""

TAIL = """int __cdecl
use_tls (void)
{
  return ++tls_counter;
}
"""

# One callback and one array entry per number, both named so the export table can tie a slot to a body.
BODY = "".join(
    "void __cdecl\nlab_cb_%d (PVOID handle, DWORD reason, PVOID reserved)\n"
    "{\n  (void) handle; (void) reason; (void) reserved;\n  note (%d);\n}\n\n"
    '__attribute__((section(".CRT$XLB%02d"), used))\n'
    "void (__cdecl *p_cb_%d)(PVOID, DWORD, PVOID) = lab_cb_%d;\n\n" % (one, one, one, one, one)
    for one in range(CALLBACKS)
)

TLS_C = HEAD + BODY + TAIL
PLAIN_C = "int __cdecl plain_use (void) { return 42; }\n"


def link(args, note_text):
    """One `gcc` invocation, with the header stamp pinned to a date rather than to the clock."""
    here = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
    made = subprocess.run(args, capture_output=True, shell=False, cwd=SCRATCH, env=here, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note_text, (made.stdout + made.stderr).decode("utf-8", "replace")[:700]))
    return made


def build():
    write("tls.c", TLS_C)
    write("plain.c", PLAIN_C)
    link(["gcc", "-shared", "-O1", "-g0", "-Wl,-s", "tls.c", "-o", "tls.dll"], "gcc tls.dll")
    link(["gcc", "-shared", "-O1", "-g0", "-Wl,-s", "plain.c", "-o", "plain.dll"], "gcc plain.dll")


def write(name, text):
    with open(os.path.join(SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


# ------------------------------------------------------------------------------ the file's own words
def image(raw):
    """(section table, optional header offset, magic, image base) for a PE image, None for anything else."""
    if raw[:2] != b"MZ" or len(raw) < 0x40:
        return None
    pe = struct.unpack_from("<I", raw, 0x3c)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        return None
    count = struct.unpack_from("<H", raw, pe + 6)[0]
    size = struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    base = (struct.unpack_from("<Q", raw, optional + 24)[0] if magic == 0x20b
            else struct.unpack_from("<I", raw, optional + 28)[0])
    table = []
    for index in range(count):
        at = optional + size + index * 40
        if size < 40 or at + 40 > len(raw):
            continue
        name = raw[at:at + 8].rstrip(b"\0").decode("utf-8", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, at + 8)
        table.append((name, vaddr, vsize, raw_ptr, raw_size))
    return table, optional, magic, base


def where_lies(table, address):
    """The file offset an RVA names, or None where the file keeps no byte there.

    A section's virtual size can be wider than what the file gives it - `.bss` is the standing case, and
    it is exactly where a TLS index lives - so an address inside a section is not yet an address in the
    file, and this answers -1 for it rather than inventing a position.
    """
    for _name, vaddr, vsize, raw_ptr, raw_size in table:
        span = max(vsize, raw_size)
        if raw_ptr and vaddr <= address < vaddr + span and address - vaddr < raw_size:
            return raw_ptr + (address - vaddr)
    return None


def section_of(table, address):
    for name, vaddr, vsize, _raw_ptr, raw_size in table:
        if vaddr <= address < vaddr + max(vsize, raw_size):
            return name
    return "-"


def directory(raw):
    """((rva, offset, size), body, callbacks) for directory 9, or None when there is no image here.

    `callbacks` holds RVAs: the array is a list of virtual addresses, and everything downstream walks
    them through the sections, which wants the base taken off once.
    """
    found = image(raw)
    if found is None:
        return None
    table, optional, magic, base = found
    if magic == 0x20b:
        at, wide, step = optional + 112 + TLS_DIRECTORY * 8, True, 8
    elif magic == 0x10b:
        at, wide, step = optional + 96 + TLS_DIRECTORY * 8, False, 4
    else:
        raise SystemExit("unknown optional-header magic %#x" % magic)
    rva, size = struct.unpack_from("<II", raw, at)
    if size == 0:
        return (rva, None, size), None, []
    offset = where_lies(table, rva)
    if offset is None or offset + 4 * step + 8 > len(raw):
        return (rva, None, size), None, []
    fields = [struct.unpack_from("<Q" if wide else "<I", raw, offset + each * step)[0]
              for each in range(4)]
    zero, character = struct.unpack_from("<II", raw, offset + 4 * step)
    # The array behind the fourth field: walk it while the entries name a byte and stop at the zero,
    # which is what the loader does. How long the walk ran is checked against the fixup list, not here.
    callbacks = []
    place = where_lies(table, fields[3] - base)
    if place is not None:
        while len(callbacks) < 4096 and place + len(callbacks) * step + step <= len(raw):
            one = struct.unpack_from("<Q" if wide else "<I", raw, place + len(callbacks) * step)[0]
            if one == 0:
                break
            callbacks.append(one - base)
    return (rva, offset, size), (fields, zero, character, wide, base, table), callbacks


def fixups(raw):
    """The RVAs directory 5 says the linker filled with an address, and the type it used."""
    found = image(raw)
    if found is None:
        return None
    table, optional, magic, _base = found
    at = optional + (112 if magic == 0x20b else 96) + RELOC_DIRECTORY * 8
    rva, size = struct.unpack_from("<II", raw, at)
    if size == 0:
        return []
    place = where_lies(table, rva)
    if place is None:
        raise SystemExit("the base-relocation directory names no byte in the file")
    end, at, seen, kinds = rva + size, place, [], {}
    while rva < end:
        page, block = struct.unpack_from("<II", raw, at)
        if block < 8 or rva + block > end:
            break
        for each in range((block - 8) // 2):
            entry = struct.unpack_from("<H", raw, at + 8 + each * 2)[0]
            kind, where = entry >> 12, entry & 0xFFF
            if kind:
                kinds[kind] = kinds.get(kind, 0) + 1
                seen.append(page + where)
        rva += block
        at += block
    return {"wide": magic == 0x20b, "rvas": sorted(seen), "kinds": kinds}


# ---------------------------------------------------------------------------- the rows, as a panel sees them
def placed(table, value, base):
    relative = value - base
    where = where_lies(table, relative)
    return ["value\t0x%x" % value, "rva\t0x%x" % relative,
            "off\t%s" % (-1 if where is None else where),
            "section\t%s" % section_of(table, relative)]


def rows(name, found, exported):
    (rva, offset, size), body, callbacks = found
    if body is None:
        return []
    fields, zero, character, wide, base, table = body
    out = ["\t".join(["tls",
                      "dir\t%d" % TLS_DIRECTORY,
                      "rva\t0x%x" % rva,
                      "off\t%s" % (-1 if offset is None else offset),
                      "bytes\t%d" % size,
                      "bits\t%d" % (64 if wide else 32),
                      "base\t0x%x" % base,
                      "callbacks\t%d" % len(callbacks),
                      "zero\t%d" % zero,
                      "char\t0x%x" % character])]
    for label, value in zip(("start", "end", "index", "callbacks"), fields):
        out.append("\t".join(["field", label] + placed(table, value, base)))
    for index, one in enumerate(callbacks[:MAX_LISTED]):
        out.append("\t".join(["callback", str(index)]
                             + placed(table, one + base, base)
                             + ["name\t%s" % exported.get(one, "-")]))
    if len(callbacks) > MAX_LISTED:
        out.append("cut\tcallbacks\t%d\tlisted\t%d" % (len(callbacks), MAX_LISTED))
    return out


# ------------------------------------------------------------------- the two readers of the six fields
def llvm(path):
    made = subprocess.run(["llvm-readobj", "--coff-tls-directory", path], capture_output=True,
                          shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("llvm-readobj refused %s" % path)
    text = made.stdout.decode("utf-8", "replace")
    if "TLSDirectory" not in text:
        return None
    out = {}
    for line in text.splitlines():
        found = re.fullmatch(r"\s+([A-Za-z]+): *(0x[0-9a-fA-F]+|\d+) *", line)
        if found:
            out[found.group(1)] = int(found.group(2), 0)
    # Characteristics prints as `Characteristics [ (0x0)`, with the decoded bit names in the gap when a
    # bit is set. Nothing this producer sets is one, which is the only thing the row can claim.
    stamp = re.search(r"Characteristics \[(.*)\(0x([0-9a-fA-F]+)\)", text)
    if stamp:
        out["Characteristics"] = int(stamp.group(2), 16)
        out["names"] = stamp.group(1).strip()
    return out


def through_pefile(path):
    import pefile
    pe = pefile.PE(path)
    pe.parse_data_directories()
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return None
    entry = pe.DIRECTORY_ENTRY_TLS.struct
    return {"start": entry.StartAddressOfRawData, "end": entry.EndAddressOfRawData,
            "index": entry.AddressOfIndex, "callbacks": entry.AddressOfCallBacks,
            "zero": entry.SizeOfZeroFill, "char": entry.Characteristics}


def export_names(path):
    """{RVA: name} for the table LLVM prints - and pefile's, which has to say the same thing."""
    made = subprocess.run(["llvm-readobj", "--coff-exports", path], capture_output=True,
                          shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("llvm-readobj refused to list %s's exports" % path)
    text = made.stdout.decode("utf-8", "replace")
    pairs = {}
    for block in re.findall(r"Export \{(.*?)\}", text, re.S):
        one = re.search(r"Name: (\S+)", block)
        two = re.search(r"RVA: (0x[0-9a-fA-F]+)", block)
        if one and two:
            pairs[int(two.group(1), 16)] = one.group(1)
    import pefile
    pe = pefile.PE(path)
    pe.parse_data_directories()
    table = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    other = {}
    for each in getattr(table, "symbols", []) or []:
        if each.name and not each.forwarder:
            other[each.address] = each.name.decode("utf-8", "replace")
    if other != pairs:
        diff = {k: (pairs.get(k), other.get(k)) for k in set(other) | set(pairs) if pairs.get(k) != other.get(k)}
        raise SystemExit("%s: the two export tables disagree: %s" % (path, sorted(diff.items())[:4]))
    return pairs


# ------------------------------------------------------------- the loader, asked which ones actually ran
kernel32 = C.windll.kernel32
kernel32.LoadLibraryExW.argtypes = [C.c_wchar_p, C.c_void_p, C.c_uint]
kernel32.LoadLibraryExW.restype = C.c_void_p
kernel32.GetProcAddress.argtypes = [C.c_void_p, C.c_char_p]
kernel32.GetProcAddress.restype = C.c_void_p
kernel32.FreeLibrary.argtypes = [C.c_void_p]
kernel32.FreeLibrary.restype = C.c_bool


def through_loader(path):
    """What the callbacks recorded: (how many ran, the numbers they wrote, in order)."""
    module = kernel32.LoadLibraryExW(path, None, 0)
    if not module:
        raise SystemExit("the loader refused %s: %d" % (path, C.get_last_error()))
    try:
        count = C.CFUNCTYPE(C.c_long)(kernel32.GetProcAddress(module, b"lab_ran"))
        slot = C.CFUNCTYPE(C.c_long, C.c_long)(kernel32.GetProcAddress(module, b"lab_order"))
        if not count or not slot:
            raise SystemExit("%s exports neither lab_ran nor lab_order" % path)
        ran = count()
        return ran, [slot(each) for each in range(min(ran, 256))]
    finally:
        kernel32.FreeLibrary(C.c_void_p(module))


# --------------------------------------------------------------------------------------- the agreements
def check(name, raw, found, first, second, listed, ran, fixed):
    """One fixture against every reading; a disagreement means no probe is written."""
    (rva, offset, size), body, callbacks = found
    if body is None:
        if first or second:
            raise SystemExit("%s: the walk finds no directory, llvm %r, pefile %r" % (name, first, second))
        if ran and ran[0]:
            raise SystemExit("%s: nothing to run, yet %d callbacks reported" % (name, ran[0]))
        return
    fields, zero, character, wide, base, table = body
    if first is None or second is None:
        raise SystemExit("%s: the walk reads a TLS directory, llvm %r, pefile %r" % (name, first, second))
    pairs = (("StartAddressOfRawData", fields[0], "start"), ("EndAddressOfRawData", fields[1], "end"),
             ("AddressOfIndex", fields[2], "index"), ("AddressOfCallBacks", fields[3], "callbacks"))
    for label, mine, key in pairs:
        # Both readers print the number the file holds, base included - so neither is asked for an RVA,
        # and a row that carried only one of the two would hide a missed subtraction.
        if first.get(label) != mine:
            raise SystemExit("%s: %s is %#x in the file, llvm prints %r" % (name, label, mine, first.get(label)))
        if second[key] != mine:
            raise SystemExit("%s: %s is %#x in the file, pefile says %#x" % (name, label, mine, second[key]))
    if first.get("SizeOfZeroFill") != zero or second["zero"] != zero:
        raise SystemExit("%s: zero fill is %d, llvm %r, pefile %r"
                         % (name, zero, first.get("SizeOfZeroFill"), second["zero"]))
    if first.get("Characteristics") != character or second["char"] != character:
        raise SystemExit("%s: characteristics are %#x, llvm %r, pefile %r"
                         % (name, character, first.get("Characteristics"), second["char"]))
    if first.get("names"):
        raise SystemExit("%s: llvm decoded %#x as %r, which the row does not spell"
                         % (name, character, first["names"]))
    # The fixup list, which never reads the array: every address the linker wrote is one page-relative
    # RVA in directory 5, so the four fields and exactly the array's own slots show up there.
    wanted = 10 if wide else 2
    kinds = fixed["kinds"]
    if fixed["wide"] != wide:
        raise SystemExit("%s: the file is %s-bit, the fixups say otherwise" % (name, "64" if wide else "32"))
    if kinds.get(wanted, 0) == 0:
        raise SystemExit("%s: no type-%d fixups at all, so nothing here was relocated" % (name, wanted))
    filled = set(fixed["rvas"])
    step = 8 if wide else 4
    for each in range(4):
        slot = rva + each * step
        if slot not in filled:
            raise SystemExit("%s: field %d at %#x holds an address the linker left alone" % (name, each, slot))
    if rva + 4 * step in filled:
        raise SystemExit("%s: SizeOfZeroFill at %#x was fixed up, which is not an address"
                         % (name, rva + 4 * step))
    start = fields[3] - base
    for index, one in enumerate(callbacks):
        if start + index * step not in filled:
            raise SystemExit("%s: callback %d at %#x is not in the fixup list" % (name, index, start + index * step))
        if where_lies(fixed["table"], one) is None:
            raise SystemExit("%s: callback %#x maps outside every section" % (name, one))
    # The slot the walk stopped on: no fixup, and a zero - which is the stop rule and its own bound, read
    # from a list that never saw the array.
    after = start + len(callbacks) * step
    if after in filled:
        raise SystemExit("%s: the fixup list reaches past the %d callbacks the walk counted (%#x)"
                         % (name, len(callbacks), after))
    where = where_lies(fixed["table"], after)
    if where is None or struct.unpack_from("<Q" if wide else "<I", raw, where)[0] != 0:
        raise SystemExit("%s: the entry after the array at %#x is not the zero the walk stopped on"
                         % (name, after))
    # And the loader's own account: all of the file's callbacks ran, each one once, in the order the
    # array lists them. The anonymous ones the CRT contributes write nothing, so they are absent here.
    count, seen = ran
    mine = [index for index, one in enumerate(callbacks) if listed.get(one, "").startswith("lab_cb_")]
    if count < len(mine):
        raise SystemExit("%s: the array names %d callbacks the export table can name, %d ran"
                         % (name, len(mine), count))
    walked = [tag - 1 for tag in seen if tag]
    if walked != mine:
        raise SystemExit("%s: the loader ran %s, the array lists %s" % (name, walked[:6], mine[:6]))


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    build()
    probe = {}
    for name in ("tls.dll", "plain.dll", "reloc.dll", "answer.obj"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        path = os.path.join(SCRATCH, name)
        raw = open(path, "rb").read()
        found = directory(raw)
        if found is None:
            # Not an image at all - a COFF object says nothing here, and neither does a reader asked to
            # pretend otherwise, so the walk's own answer is the whole check.
            probe[name] = {"tls": False, "callbacks": 0, "rows": []}
            print("%-11s not an image, so no directory to read" % name)
            continue
        # An object file is not an image: LLVM, pefile and the loader are asked only where they answer.
        header = image(raw)
        table = header[0]
        listed = export_names(path) if name == "tls.dll" else {}
        fixed = fixups(raw) or {"wide": True, "rvas": [], "kinds": {}}
        fixed["table"] = table
        # Only the file the loader will run has an account to give; the borrowed fixtures export nothing.
        ran = through_loader(os.path.abspath(path)) if name == "tls.dll" else (0, [])
        check(name, raw, found, llvm(path), through_pefile(path), listed, ran, fixed)
        made = rows(name, found, listed)
        probe[name] = {"tls": bool(made), "callbacks": len(found[2]) if found else 0, "rows": made}
        if made:
            print("%-11s %d callbacks, the loader ran %d" % (name, len(found[2]), ran[0]))
            for row in made[:3] + made[-3:]:
                print("%-11s %s" % ("", row.replace("\t", " | ")))
        else:
            print("%-11s no TLS directory, and every reader agrees" % name)
    for name in ("tls.dll", "plain.dll"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "tls.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, llvm-readobj, pefile, the fixup list and the loader agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
