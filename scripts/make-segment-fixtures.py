"""Check the ELF program-header rows against two readers that are not this repo's.

No new files are built: `lab.elf`, `lab.so`, `lab32.so` and `labarm.so` already exist for the relocation
and section rounds, and their program headers are the Segments window - what a loader is told to map, and
with which permissions. Three sources have to agree before a probe is written:

    the bytes at e_phoff         p_type, and p_flags - which sits at +4 in a 64-bit record and at +24 in
                                 a 32-bit one, so reading it at the same offset in both silently reports
                                 p_offset as a permission word
    readelf -lW                  LOAD   0x4f0 0x14f0 0x14f0 0xb0 0xb0 R E 0x1000
    llvm-readobj --segments      Type: PT_LOAD (0x1)   Offset: 0x4f0   FileSize: 176   Flags: R E

The two readers may differ in one way only: LLVM's word is readelf's with `PT_` in front. Every number -
offset, both addresses, both sizes, alignment - has to be identical in all three, and the permission word
has to come out of the file's own flag bits.

objdump -p was tried first as the second reader and dropped: it renders an alignment the file leaves at
zero as `2**0`, that is 1, and it wraps one record over two lines, so agreeing with it would have meant
agreeing about its formatting rather than about the bytes.

    temp/venv/Scripts/python.exe scripts/make-segment-fixtures.py
"""

import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

FILES = ["lab.elf", "lab.so", "lab32.so", "labarm.so"]


def run(cmd):
    done = subprocess.run(cmd, capture_output=True, shell=False, timeout=600, cwd=ROOT)
    if done.returncode != 0:
        raise SystemExit("%s failed: %s" % (" ".join(cmd), done.stderr.decode("utf-8", "replace")[:300]))
    return done.stdout.decode("utf-8", "replace")


def number(text):
    digits = re.match(r"^(?:0x([0-9a-fA-F]+)|(\d+))$", text.strip())
    if not digits:
        raise SystemExit("not a number this script reads: %r" % text)
    return int(digits.group(1) or digits.group(2), 16 if digits.group(1) else 10)


def from_readelf(name):
    """One entry per program header, as `readelf -lW` prints the table."""
    rows = []
    for line in run(["readelf", "-lW", os.path.join(FIX, name)]).splitlines():
        # The flags column is written with a space between the letters - `R E` for a text segment - so the
        # line is matched rather than split, or an executable row comes out as ten fields and vanishes.
        one = re.match(r"^\s*(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)"
                       r"\s+(0x[0-9a-f]+)\s+([RWEXA ]+)\s+(0x[0-9a-f]+|\d+)\s*$", line)
        if not one:
            continue
        rows.append({"type": one.group(1), "off": number(one.group(2)), "vaddr": number(one.group(3)),
                     "paddr": number(one.group(4)), "filesz": number(one.group(5)),
                     "memsz": number(one.group(6)), "flags": one.group(7).strip().replace(" ", ""),
                     "align": number(one.group(8))})
    return rows


def from_llvm(name):
    """The same headers as `llvm-readobj --segments` prints them, one `ProgramHeader { … }` block each.

    Block-wise rather than line-wise because LLVM opens a sub-list for the permissions -
    `Flags [ (0x4)` then `PF_R (0x4)` then `]` - and a line-based walk mistakes that closing bracket for
    the end of a record. The number beside `Flags` is the file's own `p_flags` word, which is what the
    comparison below wants.
    """
    text = run(["llvm-readobj", "--segments", os.path.join(FIX, name)])
    rows = []
    for block in re.findall(r"ProgramHeader \{(.*?)\n  \}", text, re.S):
        kind = re.search(r"Type:\s+(\S+)\s+\((0x[0-9a-fA-F]+)\)", block)
        words = re.search(r"Flags\s+\[\s+\((0x[0-9a-fA-F]+)\)", block)
        fields = dict(re.findall(r"(Offset|VirtualAddress|PhysicalAddress|FileSize|MemSize|Alignment):"
                                 r"\s+(\S+)", block))
        if not kind or not words or len(fields) != 6:
            raise SystemExit("%s: a segment block this script cannot read:\n%s" % (name, block))
        rows.append({"type": number(kind.group(2)), "word": kind.group(1),
                     "pflags": number(words.group(1)),
                     "off": number(fields["Offset"]), "vaddr": number(fields["VirtualAddress"]),
                     "paddr": number(fields["PhysicalAddress"]), "filesz": number(fields["FileSize"]),
                     "memsz": number(fields["MemSize"]), "align": number(fields["Alignment"])})
    return rows


def phdr_table(name):
    """(types, flags, records, is64, count) read out of the file, one record at a time."""
    blob = open(os.path.join(FIX, name), "rb").read()
    if blob[:4] != b"\x7fELF":
        raise SystemExit("%s is not an ELF file" % name)
    is64 = blob[4] == 2
    endian = "<" if blob[5] == 1 else ">"
    if is64:
        e_phoff, = struct.unpack_from(endian + "Q", blob, 0x20)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", blob, 0x36)
    else:
        e_phoff, = struct.unpack_from(endian + "I", blob, 0x1c)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", blob, 0x2a)
    types, flags, records = [], [], []
    for index in range(e_phnum):
        at = e_phoff + index * e_phentsize
        if at + e_phentsize > len(blob):
            raise SystemExit("%s: program header %d runs past the end of the file" % (name, index))
        if e_phentsize < (56 if is64 else 32):
            raise SystemExit("%s: e_phentsize %d is smaller than the class's own record"
                             % (name, e_phentsize))
        kind, = struct.unpack_from(endian + "I", blob, at)
        # The one field whose place moves: p_flags is word two in a 64-bit record and word seven in a
        # 32-bit one, and reading it from the same offset in both reports an address as permissions.
        place = 4 if is64 else 24
        pflags, = struct.unpack_from(endian + "I", blob, at + place)
        types.append(kind)
        flags.append(pflags)
        records.append((at, kind, pflags))
    return types, flags, records, is64, e_phnum


def bits_of(text):
    """The permission letters a reader prints, as a set.

    readelf writes only the bits that are set and uses `E` for execute - `R E` for a text segment - while
    the file's own word renders as `r-x`, so the two are compared as sets of permissions rather than as
    strings.
    """
    return set(one for one in text.upper().replace("E", "X") if one in "RWX")


def flags_text(pflags):
    return ("r" if pflags & 4 else "-") + ("w" if pflags & 2 else "-") + ("x" if pflags & 1 else "-")


def main():
    files = {}
    for name in FILES:
        readelf = from_readelf(name)
        llvm = from_llvm(name)
        types, pflags, records, is64, count = phdr_table(name)
        if not (len(readelf) == len(llvm) == len(types) == count):
            raise SystemExit("%s: readelf %d rows, llvm %d, the header table says %d/%d"
                             % (name, len(readelf), len(llvm), len(types), count))
        step = 8 if is64 else 4
        rows = []
        mapped = 0
        for index, (one, other, (at, kind, bits)) in enumerate(zip(readelf, llvm, records)):
            blob = open(os.path.join(FIX, name), "rb").read()
            # Byte five is the data encoding, and it has nothing to do with the class: a 32-bit little
            # endian file is the common case, and reading it big endian turns 0x34 into 0x34000000.
            endian = "<" if blob[5] == 1 else ">"
            # The fields are not six words in a row: in a 32-bit record p_flags sits between p_memsz and
            # p_align, so an unpack of six consecutive words reads a permission word as an alignment.
            places = ((8, 16, 24, 32, 40, 48) if is64 else (4, 8, 12, 16, 20, 28))
            width = "Q" if is64 else "I"
            off, vaddr, paddr, filesz, memsz, align = (
                struct.unpack_from(endian + width, blob, at + place)[0] for place in places)
            for mine, theirs, field in ((off, other["off"], "off"), (vaddr, other["vaddr"], "vaddr"),
                                         (paddr, other["paddr"], "paddr"), (filesz, other["filesz"], "filesz"),
                                         (memsz, other["memsz"], "memsz"), (align, other["align"], "align")):
                if mine != theirs:
                    raise SystemExit("%s: segment %d %s is %s to llvm and %s to the file"
                                     % (name, index, field, theirs, mine))
                if mine != one[field]:
                    raise SystemExit("%s: segment %d %s is %s to readelf and %s to the file"
                                     % (name, index, field, one[field], mine))
            if other["type"] != kind:
                raise SystemExit("%s: segment %d is type %d in the file and %d to llvm"
                                 % (name, index, kind, other["type"]))
            if other["word"] != "PT_" + one["type"]:
                raise SystemExit("%s: segment %d is %s to readelf and %s to llvm"
                                 % (name, index, one["type"], other["word"]))
            stated = flags_text(bits)
            if bits != other["pflags"]:
                raise SystemExit("%s: segment %d permission word is %#x in the file and %#x to llvm"
                                 % (name, index, bits, other["pflags"]))
            if bits_of(stated) != bits_of(one["flags"]):
                raise SystemExit("%s: segment %d permissions are %s in the file and %s to readelf"
                                 % (name, index, stated, one["flags"]))
            mapped += memsz
            rows.append("segment\t%d\ttype\t%d\tname\t%s\toff\t%d\tvaddr\t0x%x\tpaddr\t0x%x"
                        "\tfilesz\t%d\tmemsz\t%d\tflags\t%s\talign\t%d"
                        % (index, kind, one["type"], off, vaddr, paddr, filesz, memsz, stated, align))
        # The counts come out of the file's own type words and flag bits, never out of the printed rows: a
        # summary of a spelling would summarise a reader's formatting choices.
        loads = len([kind for kind in types if kind == 1])
        writable = len([one for one in pflags if one & 2])
        execed = len([one for one in pflags if one & 1])
        header = ("segments\ttotal\t%d\tload\t%d\twritable\t%d\texec\t%d\tmapped\t%d\tbits\t%d"
                  % (len(rows), loads, writable, execed, mapped, 64 if is64 else 32))
        files[name] = {"rows": [header] + rows, "kinds": types, "flags": pflags,
                       "bytes": os.path.getsize(os.path.join(FIX, name))}

    if len(files["lab.elf"]["rows"]) != 5 or len(files["lab.so"]["rows"]) < 10:
        raise SystemExit("the four files no longer cover both a spare and a busy header table")
    if files["lab32.so"]["flags"] == files["lab32.so"]["kinds"]:
        raise SystemExit("lab32.so's permission words came out of the wrong field")
    for name in FILES:
        for row in files[name]["rows"]:
            if "\tname\tUNKNOWN\t" in row:
                raise SystemExit("%s: a type no reader names; earn the word first" % name)
            if "\t" not in row:
                raise SystemExit("%s: a row with no tab is not a row: %r" % (name, row))
    with open(os.path.join(FIX, "segment.probe.json"), "w", encoding="utf-8") as handle:
        json.dump({"files": files}, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print(json.dumps({one: len(two["rows"]) for one, two in files.items()}))


if __name__ == "__main__":
    sys.exit(main())
