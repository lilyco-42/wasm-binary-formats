#!/usr/bin/env python3
"""Write COFF object fixtures with clang and print the rows a reader has to reproduce.

A COFF object is the file a compiler emits before a linker ever sees it: a 20-byte header, a section
table of 40-byte records, an optional header only when it is an image rather than an object, and - at
the end - a symbol table of 18-byte records followed by a string table for the names that do not fit
in eight bytes. That last pair is what makes an object file worth reading structurally: it is where the
names live, and `section /4` is not a name but a pointer into it.

The producers and the witnesses are both outside this repository:

  * `clang -target <triple> -c` writes the objects (LLVM 22.1.8 here, which is the toolchain the
    requirement names), deterministically enough that the timestamp is 0 in every file.
  * GNU `objdump -f/-h/-t` and `nm` then read them back. `objdump -f` names the architecture
    (`i386:x86-64` for 0x8664), `objdump -h` gives each section's size and file offset, and
    `objdump -t` the symbol's section, type, storage class, aux count and value - which is where the
    field layout below comes from rather than from memory. Anything those do not name stays a number:
    the machine of an aarch64 object is printed as hex because nothing on this host could say what it
    means. One thing the agreement does rule out: the `flags 0x3d` that `objdump -f` prints is not the
    header's Characteristics word - clang writes 0x0000 there while bfd lists HAS_RELOC/HAS_SYMS and
    friends from what it found in the file. So the characteristics are reported as the raw word the
    file holds, and objdump's list goes into the probe as an observation about that reader.

Usage: temp/venv/Scripts/python.exe scripts/make-coff-fixtures.py
"""
import json
import os
import re
import struct
import subprocess
import sys

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "coff-work"))
LISTED_SECTIONS = 24
LISTED_SYMBOLS = 24
# Only the pairs `objdump -f` was seen to state on this host.
MACHINES = {0x8664: "x86-64", 0x14C: "i386"}

TARGETS = [("answer.obj", "x86_64-w64-windows-gnu"), ("i686.obj", "i686-w64-windows-gnu")]
SOURCE = "int answer(void) { return 42; }\nvoid helper(void) { answer(); }\n"


def run(command):
    made = subprocess.run(command, capture_output=True, text=True, shell=False)
    if made.returncode != 0:
        raise SystemExit(f"{' '.join(command)} failed: {made.stderr[:200]}")
    return made.stdout


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def name_of(data, entry, strings):
    """A section or symbol name: eight bytes inline, or a reference into the string table.

    The two tables spell a long name differently - a section writes `/4`, a symbol leaves the first
    four bytes empty and puts the offset in the next four - so both forms are handled here and the
    difference is reported in the row.
    """
    raw = entry[:8]
    if raw[:4] == b"\x00\x00\x00\x00" and len(raw) == 8:
        offset = struct.unpack_from("<I", raw, 4)[0]
        end = data.find(b"\x00", strings + offset)
        return data[strings + offset : end].decode("latin1"), offset
    text = raw.split(b"\x00", 1)[0].decode("latin1")
    if text.startswith("/"):
        offset = int(text[1:])
        end = data.find(b"\x00", strings + offset)
        return data[strings + offset : end].decode("latin1"), offset
    return text, None


def sections(data, count, strings_at):
    out = []
    for index in range(count):
        at = 20 + u16(data, 16) + index * 40
        raw = data[at : at + 40]
        name, ref = name_of(data, raw, strings_at)
        vsize, vaddr, rawsize, rawptr, reloc, lines = struct.unpack_from("<IIIIII", raw, 8)
        chars = u32(raw, 36)
        out.append(
            {
                "name": name,
                "ref": ref,
                "vsize": vsize,
                "vaddr": vaddr,
                "rawsize": rawsize,
                "rawptr": rawptr,
                "reloc": reloc,
                "reloc_count": u16(raw, 32),
                "lines": lines,
                "line_count": u16(raw, 34),
                "chars": chars,
            }
        )
    return out


def string_table(data, symbols_at, symbols):
    """The table that follows the symbol records; its first word is its own length, including itself.

    With no records there is nothing for a table to follow, so its place is unknown rather than empty -
    the same distinction the reader prints, and the reason the row carries a `-` instead of `0@0`.
    """
    if symbols == 0:
        return 0, None
    at = symbols_at + symbols * 18
    if at + 4 > len(data):
        return at, 0
    size = u32(data, at)
    return at, size


def walk(data):
    if len(data) < 20:
        return None
    machine, count, stamp = struct.unpack_from("<HHI", data, 0)
    optsz, chars = struct.unpack_from("<HH", data, 16)
    symbols_at = u32(data, 8)
    symbols = u32(data, 12)
    # The same gate the reader applies: an object with an optional header is an image, and a section
    # table or symbol table that does not fit is not read at all.
    if optsz or not 1 <= count <= 96 or 20 + count * 40 > len(data):
        return None
    if symbols and (not symbols_at or symbols_at + symbols * 18 > len(data)):
        return None
    strings_at, strings_size = string_table(data, symbols_at, symbols)
    table = sections(data, count, strings_at)

    broken = 0
    if symbols and strings_at + strings_size != len(data):
        broken += 1
    for section in table:
        if section["rawsize"] and section["rawptr"] + section["rawsize"] > len(data):
            broken += 1

    rows = [
        "coff\t{}\tbroken\t{}\tmachine\t{:04x}({})\tsections\t{}\topts\t{}".format(
            len(data),
            broken,
            machine,
            MACHINES.get(machine, "?"),
            count,
            optsz,
        ),
        # The characteristics word as the file wrote it. `objdump -f` prints HAS_RELOC, HAS_LINENO,
        # HAS_DEBUG, HAS_SYMS and HAS_LOCALS for these same objects while clang leaves this word at
        # zero, so those words are bfd's reading of the contents and are not printed as if the header
        # had claimed them.
        "layout\tstamp\t{}\tsyms\t{}\tat\t{}\tstrings\t{}\tchars\t{:04x}".format(
            stamp,
            symbols,
            symbols_at,
            "-" if strings_size is None else "{}@{}".format(strings_size, strings_at),
            chars,
        ),
    ]
    for index, section in enumerate(table[:LISTED_SECTIONS]):
        rows.append(
            "section\t{}\t{}\tvsize\t{}\tvaddr\t{}\traw\t{}@{}\treloc\t{}x{}\tlines\t{}x{}\tchars\t{:08x}".format(
                index,
                section["name"],
                section["vsize"],
                section["vaddr"],
                section["rawsize"],
                section["rawptr"],
                section["reloc"],
                section["reloc_count"],
                section["lines"],
                section["line_count"],
                section["chars"],
            )
        )
    if count > LISTED_SECTIONS:
        rows.append("cut\tsections\t{}".format(count))
    # The 18-byte record is Name(8) Value(4) SectionNumber(2) Type(2) StorageClass(1)
    # NumberOfAuxSymbols(1), and each auxiliary record is another 18 bytes that belongs to the entry
    # before it - objdump prints the section symbol at [0] and its aux record right after, so skipping
    # them is what makes the two agree.
    at = symbols_at
    listed = 0
    index = 0
    stopped = False
    while index < symbols:
        if at + 18 > len(data):
            stopped = True
            break
        entry = data[at : at + 18]
        name, ref = name_of(data, entry, strings_at)
        value = u32(entry, 8)
        section = struct.unpack_from("<h", entry, 12)[0]
        sym_type = u16(entry, 14)
        storage, aux = entry[16], entry[17]
        if listed < LISTED_SYMBOLS:
            rows.append(
                "symbol\t{}\t{}\tvalue\t{:x}\tsect\t{}\ttype\t{:04x}\tscl\t{}\taux\t{}\tbase\t{}".format(
                    index, name, value, section, sym_type, storage, aux,
                    ref if ref is not None else "-"
                )
            )
            listed += 1
        index += 1 + aux
        at += 18 * (1 + aux)
    # The listing cap and this row are different facts: the loop runs to the record total the header
    # states, so a cut can only mean the walk left the file. Every object clang wrote here carries its
    # nineteen records, so neither row appears in the probe.
    if stopped:
        rows.append("cut\tsyms\t{}".format(symbols))
    rows.append("walked\tend" if broken == 0 else "stopped\tbroken\t{}".format(broken))
    return rows


def witness(path):
    """objdump's own reading of the same bytes, as a dict the rows have to agree with."""
    header = run(["objdump", "-f", path])
    flags = re.search(r"architecture:\s*(\S+),\s*flags\s*0x([0-9a-f]+)", header)
    listing = run(["objdump", "-h", path])
    table = []
    for line in listing.splitlines():
        parts = line.split()
        # Idx Name Size VMA LMA File-off Algn
        if len(parts) == 7 and parts[0].isdigit():
            table.append((parts[1], int(parts[2], 16), int(parts[5], 16)))
    symbols = run(["objdump", "-t", path])
    named = re.findall(r"\[\s*(\d+)\]\(sec\s*(\d+)\)\(fl 0x[0-9a-f]+\)\(ty\s*(\d+)\)\(scl\s*(\d+)\) \(nx (\d+)\) 0x([0-9a-f]+) (\S+)", symbols)
    return {
        "architecture": flags.group(1) if flags else "",
        "chars": int(flags.group(2), 16) if flags else -1,
        "sections": table,
        "symbols": [{"index": int(a), "sect": int(b), "type": int(c), "scl": int(d), "aux": int(e), "value": int(f, 16), "name": g} for a, b, c, d, e, f, g in named],
    }


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    source = os.path.join(SCRATCH, "answer.c")
    with open(source, "w", encoding="utf8") as handle:
        handle.write(SOURCE)

    built = {}
    for label, target in TARGETS:
        made = os.path.join(SCRATCH, label)
        if os.path.exists(made):
            os.remove(made)
        run(["clang", "-target", target, "-c", source, "-o", made])
        data = open(made, "rb").read()
        with open(os.path.join(OUT, label), "wb") as handle:
            handle.write(data)
        rows = walk(data)
        if rows is None:
            raise SystemExit(f"{label}: not even a 20-byte header")
        seen = witness(made)
        # The witness has to agree with the walk on what it can see: every section's name, size and
        # file offset. The characteristic word is deliberately not compared, for the reason above.
        if seen["chars"] == u16(data, 18):
            raise SystemExit(
                f"{label}: bfd's flags line matched the header word, so the distinction above is "
                "no longer worth claiming and the probe should say what the file says instead"
            )
        if len(seen["sections"]) != u16(data, 2):
            raise SystemExit(f"{label}: objdump lists {len(seen['sections'])} sections, header says {u16(data, 2)}")
        walked = [row for row in rows if row.startswith("section\t")]
        for (name, size, offset), row in zip(seen["sections"], walked):
            fields = row.split("\t")
            # section / i / name / vsize / v / vaddr / v / raw / size@offset / ...
            if fields[2] != name or "@" not in fields[8]:
                raise SystemExit(f"{label}: objdump says {name}, walk says {row}")
            raw_size, raw_at = (int(part) for part in fields[8].split("@"))
            if (raw_size, raw_at) != (size, offset):
                raise SystemExit(f"{label}: objdump says {name} is {size}@{offset}, walk says {fields[8]}")
        # Every symbol objdump -t names, with the record index it counts aux entries into.
        mine = {}
        for row in rows:
            if not row.startswith("symbol\t"):
                continue
            fields = row.split("\t")
            mine[int(fields[1])] = (fields[2], int(fields[4], 16), int(fields[6]), int(fields[8]), int(fields[10]))
        for symbol in seen["symbols"]:
            got = mine.get(symbol["index"])
            want = (symbol["name"], symbol["value"], symbol["sect"], symbol["type"], symbol["scl"])
            if got != want:
                raise SystemExit(f"{label}: objdump -t says {want}, walk says {got}")
        print("==", label, len(data), "bytes,", seen["architecture"], "per objdump,", len(seen["sections"]), "sections,", len(seen["symbols"]), "named symbols")
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {
            "bytes": len(data),
            "objdump": seen,
            "rows": rows,
        }

    with open(os.path.join(OUT, "coff.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote", ", ".join(label for label, _ in TARGETS), "and coff.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
