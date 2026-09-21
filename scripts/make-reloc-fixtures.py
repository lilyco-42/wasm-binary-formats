"""Produce and check the base-relocation fixtures - the fixups a PE loader applies to itself.

The directory is directory number five, and it is the only part of a Windows image that says "put the
real address of something here before running". IDA applies it and gets data cross-references from it;
an analyser that skips it sees a `.data` word as a number rather than as a pointer.

Two readers that are not this repo's were asked what a file holds, and the script writes a probe only
where they agree entry by entry:

    llvm-readobj --coff-basereloc    Type: DIR64        Address: 0x3000
    pefile                           rva=0x3000         type=10

That pairing is also how the type *numbers* get their names here. A number is written as a name only
when a fixture put that number next to that name; the pairing is collected across all three files, so
`0 -> ABSOLUTE` and `3 -> HIGHLOW` come from `lab.dll` (a PE32, which is the other half of the
optional-header branch) and `10 -> DIR64` from `reloc.dll` (a PE32+ with four address-taken objects).
A number no fixture paired stays a number in the rows - the loader would know what it means, this reader
does not claim to.

    temp/venv/Scripts/python.exe scripts/make-reloc-fixtures.py [--refresh]

`reloc.dll` is built here because no committed file has a relocation directory worth reading: `exp.dll`
has none at all and `lab.exe` is a freestanding image whose data needs no fixup. `lld-link` writes one
for a shared object, and the entry list is its doing, not this script's. `pefile` (MIT) is a local
witness only, like `jsonc-parser` elsewhere in this repo: it is not installed by CI, so the probe it
helped write is what a checkout reads.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

TARGET = "x86_64-pc-windows-msvc"

SOURCE = """\
/* Address-taken objects, so the linked image has fixups a loader must apply: a pointer to a function,
   a pointer to data, and a table holding both. Without one of these the linker has nothing to record,
   and an empty directory would be reported as a shape the reader had checked. */

int counter;
int table[4];

int take(int index) { return table[index]; }

int (*handler)(int) = take;
int* slot = &counter;
void* pairs[2] = {&counter, (void*)take};
"""


def run(cmd, work=None):
    out = subprocess.run(cmd, capture_output=True, shell=False, timeout=600, cwd=work)
    text = out.stdout.decode("utf-8", "replace") + out.stderr.decode("utf-8", "replace")
    if out.returncode:
        raise SystemExit("%s failed: %s" % (cmd[0], text[-800:]))
    return text


def tool(name):
    found = shutil.which(name)
    if not found:
        raise SystemExit("%s is not on PATH, so nothing here can be credited" % name)
    return found


def build():
    """A shared object with real fixups in it, or the committed one if it is already here."""
    keep = os.path.join(FIX, "reloc.dll")
    if os.path.exists(keep) and "--refresh" not in sys.argv:
        return open(keep, "rb").read()
    for name in ("clang", "lld-link"):
        if not shutil.which(name):
            raise SystemExit("%s is not on PATH and %s is missing" % (name, keep))
    work = tempfile.mkdtemp(prefix="reloc-")
    try:
        source = os.path.join(work, "reloc.c")
        with open(source, "w", newline="\n") as handle:
            handle.write(SOURCE)
        run(["clang", "--target=" + TARGET, "-c", source, "-o",
             os.path.join(work, "reloc.obj")], work=work)
        # `lld-link` takes its switches with either slash, and MSYS rewrites a leading one into a
        # path, so the dash form is the one that survives this shell.
        run([tool("lld-link"), "-dll", "-out:" + os.path.join(work, "reloc.dll"),
             "-noentry", os.path.join(work, "reloc.obj")], work=work)
        with open(os.path.join(work, "reloc.dll"), "rb") as handle:
            raw = handle.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if raw[:2] != b"MZ":
        raise SystemExit("lld-link did not write a PE image")
    with open(keep, "wb") as handle:
        handle.write(raw)
    return raw


def from_llvm(path):
    """`Type: NAME` and `Address: 0x…`, in the order the tool lists them."""
    text = run([tool("llvm-readobj"), "--coff-basereloc", path])
    out, pending = [], None
    for line in text.splitlines():
        found = re.match(r"\s+Type: (\S+)", line)
        if found:
            pending = found.group(1)
            continue
        found = re.match(r"\s+Address: 0x([0-9a-fA-F]+)", line)
        if found and pending is not None:
            out.append((int(found.group(1), 16), pending))
            pending = None
    return out


def from_pefile(path):
    """`(rva, type number, file offset, section name)` per entry, plus what the blocks say.

    The last two are the second implementation's own RVA-to-position arithmetic: `pefile` resolves the
    fixup address through the section table it parsed, so a row can be checked against it instead of
    only against this repo's arithmetic. A fixup no section covers is reported as such rather than
    dropped, because the loader would still have a page and an offset to write at.

    `pefile` names the directory's fields `VirtualAddress` and `Size` rather than the snake_case the
    optional header uses, and keeps the entries on the block rather than on its struct - both read here
    rather than recalled, because the first draft got both wrong and called a populated directory empty.
    """
    code = """
import json, sys
import pefile
pe = pefile.PE(sys.argv[1])
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
# The section table as pefile parsed it, with the span an address can fall in taken as the wider of
# virtual size and raw size - the rule the analyser's own map uses, written twice on purpose so the
# agreement between them means something. `get_section_by_rva` is not used: it answers None for a fixup
# whose section is there, which would have put `unmapped` in rows the file does cover.
table = []
for section in pe.sections:
    # A section the file gives no bytes to - a `.bss`, whose fixups the loader will invent rather than
    # read - is left out of the table on both sides, so an address that falls only in one is reported as
    # unmapped instead of as an offset into nothing.
    if section.SizeOfRawData == 0:
        continue
    name = section.Name.rstrip(b'\\x00').decode('utf-8', 'replace')
    table.append((section.VirtualAddress,
                  max(section.Misc_VirtualSize, section.SizeOfRawData),
                  section.PointerToRawData, name))


def where(rva):
    if rva == 0:
        return -1, 'none'
    for base, span, offset, name in table:
        if base <= rva < base + span:
            return rva - base + offset, name
    return -1, 'unmapped'


blocks = []
for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
    entries = []
    for entry in block.entries:
        place, label = where(entry.rva)
        entries.append([entry.rva, entry.type, place, label])
    blocks.append({'page': block.struct.VirtualAddress,
                   'size': block.struct.SizeOfBlock,
                   'entries': entries})
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
place, label = where(directory.VirtualAddress)
print(json.dumps({'rva': directory.VirtualAddress, 'size': directory.Size,
                  'off': place, 'section': label, 'blocks': blocks}))
"""
    text = run([sys.executable, "-c", code, path])
    parsed = json.loads(text.strip().splitlines()[-1])
    entries = [(one[0], one[1], one[2], one[3]) for block in parsed["blocks"] for one in block["entries"]]
    return parsed, entries


def check(files):
    """The two readers have to agree entry by entry, and the pairings give the type numbers their names.

    A number is written as a name only where a fixture put that number next to that name, so nothing here
    recalls which of them is 10; the requirement below is only that the shapes the rows claim - a 32-bit
    fixup, a 64-bit one, a padding entry, and a file with no directory at all - are present in the set.
    """
    paired = {}
    for name, seen in files.items():
        llvm, parsed, entries = seen["llvm"], seen["pefile"], seen["entries"]
        if len(llvm) != len(entries):
            raise SystemExit("%s: llvm-readobj listed %d entries, pefile listed %d"
                             % (name, len(llvm), len(entries)))
        for (rva, label), (second, kind, _, _) in zip(llvm, entries):
            if rva != second:
                raise SystemExit("%s: llvm says %#x where pefile says %#x" % (name, rva, second))
            known = paired.get(kind)
            if known is not None and known != label:
                raise SystemExit("%s: type %d is %s here and %s elsewhere"
                                 % (name, kind, label, known))
            paired[kind] = label
        if parsed["rva"] != 0 and not parsed["blocks"]:
            raise SystemExit("%s: a directory that names no block" % name)
    for kind in (0, 3, 10):
        if kind not in paired:
            raise SystemExit("no fixture pairs type %d with anything, so it stays a number" % kind)
    if not any(seen["pefile"]["rva"] == 0 for seen in files.values()):
        raise SystemExit("no fixture with an absent directory, so that answer is unclaimed")
    return dict(sorted(paired.items()))


def rows(name, seen, paired):
    """One line of totals, then a line per block and one per fixup, in the order the blocks carry them.

    No file name in the rows: the reader is handed bytes rather than a path, and the JSON key beside
    these lines says which image they came from. Where a fixup lands and which section owns it are the
    reader's own arithmetic on the headers, and `pefile`'s mapping is recorded beside it, so the row is
    checked against another implementation of that step and not only against this one.
    """
    parsed, entries = seen["pefile"], seen["entries"]
    named = sum(1 for one in entries if one[1] in paired)
    out = ["relocs\tdir\t0x%x\tbytes\t%d\toff\t%d\tsection\t%s\tblocks\t%d\tentries\t%d\tnamed\t%d"
           % (parsed["rva"], parsed["size"], parsed["off"], parsed["section"],
              len(parsed["blocks"]), len(entries), named)]
    for block in parsed["blocks"]:
        out.append("block\tpage\t0x%x\tsize\t%d\tentries\t%d"
                   % (block["page"], block["size"], len(block["entries"])))
        for rva, kind, where, section in block["entries"]:
            label = paired.get(kind)
            out.append("fixup\t0x%x\ttype\t%d%s\toff\t%d\tsection\t%s"
                       % (rva, kind, "" if label is None else "\tname\t" + label, where, section))
    return out


def main():
    build()
    names = ["reloc.dll", "lab.dll", "exp.dll"]
    files = {}
    for name in names:
        path = os.path.join(FIX, name)
        if not os.path.exists(path):
            raise SystemExit("%s is missing; lld-link and csc are what write it" % name)
        parsed, entries = from_pefile(path)
        files[name] = {"llvm": from_llvm(path), "pefile": parsed, "entries": entries}
    paired = check(files)
    report = {
        "type_names": {str(kind): paired[kind] for kind in paired},
        "files": {
            name: {
                "bytes": os.path.getsize(os.path.join(FIX, name)),
                "entries": [[one[0], one[1]] for one in files[name]["entries"]],
                "rows": rows(name, files[name], paired),
            }
            for name in names
        },
    }
    with open(os.path.join(FIX, "reloc.probe.json"), "w", newline="\n") as handle:
        json.dump(report, handle, indent=1)
        handle.write("\n")
    print("type pairings:", report["type_names"])
    for name in names:
        part = report["files"][name]
        print("%s: %d entries, %d B, %d rows"
              % (name, len(part["entries"]), part["bytes"], len(part["rows"])))
        for line in part["rows"][1:4]:
            print("   " + line.replace("\t", " "))


if __name__ == "__main__":
    main()
