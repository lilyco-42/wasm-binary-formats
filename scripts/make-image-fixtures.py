#!/usr/bin/env python3
"""Write two linked images with clang + lld, and compute the byte-region map from the files' own tables.

The map answers one question per byte: *what names it?* The section table comes from `object` in the
reader, but a colour map also needs the header tables, and the honest form of "you could change this and
the program would not notice" is that no table and no loaded segment covers those bytes at all. So every
range here comes from an offset the file states for itself - ELF's e_phoff / e_shoff and their entry
sizes, PE's SizeOfHeaders, its section table right after the NT headers, and its certificate directory -
and the field offsets were checked against binutils rather than recalled.

Two fixtures, because the two formats disagree about everything the map needs:

  lab.elf  ELF64, EXEC, `-nostdlib -static`: 5 program headers, 9 sections, three alignment gaps, and
           the section header table as the last thing in the file - so it has no overlay tail.
  lab.exe  PE32+ (`x86_64-w64-windows-gnu`): a 1 024-byte header block and 512-byte file alignment, so
           each section is followed by hundreds of padding bytes that no table names.

Both are linked by `clang` 22.1.8 driving `ld.lld` with `-nostdlib -ffreestanding` - no sysroot, no C
runtime - which keeps them small enough to commit and puts the linker's own tables, not a hand-built
match to them, in front of the reader.

The witnesses are binutils: `readelf -h -l -S` and `objdump -h/-p`. The script refuses to write the probe
unless its own parse agrees with them - header offsets, and each section's file offset and size - which is
what caught this script's first draft reading ELF64's e_phentsize two bytes late.

`regions()` is the shadow the Rust port is written from: it prints the rows in the order the reader will,
so the assertions come from it rather than from a guess.

Usage: temp/venv/Scripts/python.exe scripts/make-image-fixtures.py [--probe-only]
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
OUT = os.path.join(ROOT, "test", "fixtures")
WORK = os.path.join(ROOT, "temp", "image-work")
SOURCE = ('const char msg[] = "a lab fixture string padded out to length!!";\n'
          'const char note[] = "a second literal the linker will place beside it";\n'
          'long entry(void) { return msg[0] + note[3]; }\n')
CFLAGS = ["-O1", "-fno-asynchronous-unwind-tables", "-fno-ident"]

# ELF, from the header layouts rather than from memory.
PT_LOAD = 1
SHT_NULL, SHT_PROGBITS, SHT_SYM_TAB, SHT_STR_TAB = 0, 1, 2, 3
SHT_RELA, SHT_HASH, SHT_NOTE, SHT_NOBITS, SHT_REL, SHT_DYN_SYM = 4, 5, 7, 8, 9, 11
SHT_GNU_HASH, SHT_GNU_VER_NEED = 0x6FFFFFF6, 0x6FFFFFFE
META_TYPES = {SHT_SYM_TAB, SHT_STR_TAB, SHT_RELA, SHT_REL, SHT_HASH, SHT_GNU_HASH, SHT_DYN_SYM,
              SHT_NOTE, SHT_GNU_VER_NEED}
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
# PE section characteristics.
SCN_CNT_CODE, SCN_CNT_INIT_DATA = 0x00000020, 0x00000040
SCN_MEM_EXECUTE, SCN_MEM_WRITE = 0x20000000, 0x80000000
MACHINE = {0x8664: "amd64", 0x14C: "i386", 0xAA64: "arm64"}
GAP = "gap"


def run(args):
    proc = subprocess.run(args, cwd=ROOT, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = proc.stdout.decode("utf8", "replace")
    if proc.returncode != 0:
        raise SystemExit("{} failed:\n{}".format(" ".join(args), text))
    return text


def tool(name):
    found = shutil.which(name)
    if not found:
        raise SystemExit("{} is not on PATH".format(name))
    return found


def build(home):
    if os.path.isdir(home):
        shutil.rmtree(home)
    os.makedirs(home)
    source = os.path.join(home, "x.c")
    with open(source, "w", encoding="utf8", newline="\n") as handle:
        handle.write(SOURCE)
    clang = tool("clang")
    run([clang, "--target=x86_64-unknown-linux-gnu", "-nostdlib", "-static", "-ffreestanding"]
        + CFLAGS + ["-Wl,-e,entry", "-o", os.path.join(home, "lab.elf"), source])
    run([clang, "--target=x86_64-w64-windows-gnu", "-nostdlib", "-ffreestanding"]
        + CFLAGS + ["-Wl,-e,entry", "-o", os.path.join(home, "lab.exe"), source])


def region(start, length, kind, name, note=""):
    if not length:
        return None
    return {"start": start, "length": length, "kind": kind, "name": name, "note": note}


def cstr(raw, at):
    end = raw.find(b"\0", at)
    return "?" if end < 0 else raw[at:end].decode("utf8", "replace")


class Reader:
    """Field reader over an image, parameterised once by the file's own class and byte order."""

    def __init__(self, raw, wide, little):
        self.raw = raw
        self.wide = wide
        self.fmt = ("<" if little else ">") + ("Q" if wide else "I")
        self.half = ("<" if little else ">") + "H"
        self.word = ("<" if little else ">") + "I"

    def addr(self, at):
        return struct.unpack_from(self.fmt, self.raw, at)[0]

    def addrsz(self):
        return 8 if self.wide else 4

    def u16(self, at):
        return struct.unpack_from(self.half, self.raw, at)[0]

    def u32(self, at):
        return struct.unpack_from(self.word, self.raw, at)[0]


def elf(raw):
    """ELF32/ELF64: the image header, the two table ranges, then every section's own span."""
    read = Reader(raw, raw[4] == 2, raw[5] == 1)
    entry = {"class": 64 if read.wide else 32,
             "endianness": "little" if raw[5] == 1 else "big",
             "type": read.u16(16), "machine": read.u16(18), "ehsize": read.u16(52 if read.wide else 40)}
    # e_ident is 16 bytes in both classes, then type, machine and version, so e_entry is at 24 either
    # way; from there every field is one pointer wide in ELF64 and one word wide in ELF32, which is what
    # shifts the two-byte tail of the header from 40 to 52.
    fields = {"entry": 24,
              "phoff": 28 if not read.wide else 32,
              "shoff": 32 if not read.wide else 40,
              "phentsize": 42 if not read.wide else 54,
              "phnum": 44 if not read.wide else 56,
              "shentsize": 46 if not read.wide else 58,
              "shnum": 48 if not read.wide else 60,
              "shstrndx": 50 if not read.wide else 62}
    entry["phoff"] = read.addr(fields["phoff"])
    entry["shoff"] = read.addr(fields["shoff"])
    phentsize, phnum = read.u16(fields["phentsize"]), read.u16(fields["phnum"])
    shentsize, shnum = read.u16(fields["shentsize"]), read.u16(fields["shnum"])
    tables_start = min(value for value in (entry["phoff"], entry["shoff"]) if value)
    found = [region(0, tables_start, "header", "elf header"),
             region(entry["phoff"], phentsize * phnum, "tables", "program headers"),
             region(entry["shoff"], shentsize * shnum, "tables", "section headers")]
    loaded = []
    for index in range(phnum):
        at = entry["phoff"] + index * phentsize
        p_type = read.u32(at)
        if read.wide:
            p_off, p_filesz = read.addr(at + 8), read.addr(at + 32)
        else:
            p_off, p_filesz = read.u32(at + 4), read.u32(at + 16)
        if p_type == PT_LOAD:
            loaded.append((p_off, p_off + p_filesz))
    entry["entry"] = read.addr(24)
    entry["load"] = [[at, stop] for at, stop in loaded]
    shstrndx = read.u16(fields["shstrndx"])
    strtab_off = 0
    if shstrndx < shnum:
        at = entry["shoff"] + shstrndx * shentsize
        strtab_off = read.addr(at + 24) if read.wide else read.u32(at + 16)
    for index in range(shnum):
        at = entry["shoff"] + index * shentsize
        name_off = read.u32(at)
        sh_type = read.u32(at + 4)
        sh_flags = read.addr(at + 8)
        if read.wide:
            sh_addr, sh_off, sh_size = read.addr(at + 16), read.addr(at + 24), read.addr(at + 32)
        else:
            sh_addr, sh_off, sh_size = read.u32(at + 12), read.u32(at + 16), read.u32(at + 20)
        name = cstr(raw, strtab_off + name_off)
        found.append(elf_section(name, sh_type, sh_flags, sh_addr, sh_off, sh_size))
    return [each for each in found if each], loaded, entry


def elf_section(name, sh_type, sh_flags, sh_addr, sh_off, sh_size):
    """A section's span, typed by what the file's own flags and type say about it."""
    if sh_type == SHT_NULL or sh_type == SHT_NOBITS or not sh_size:
        return None
    allocated = bool(sh_flags & SHF_ALLOC)
    note = "loaded at {:#x}".format(sh_addr) if allocated else "not loaded"
    if (not allocated or sh_type in META_TYPES
            or name.startswith((".debug", ".zdebug", ".comment", ".note", ".rel", ".symtab", ".strtab"))):
        return region(sh_off, sh_size, "meta", name or "?", note)
    if sh_flags & SHF_EXECINSTR or name.startswith((".text", ".plt")):
        return region(sh_off, sh_size, "code", name or "?", note)
    if sh_flags & SHF_WRITE:
        return region(sh_off, sh_size, "data", name or "?", note)
    return region(sh_off, sh_size, "rodata", name or "?", note)


def pe(raw):
    """PE32/PE32+: the header block, the section table, the certificate directory, then each section."""
    lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[lfanew:lfanew + 4] != bytes([0x50, 0x45, 0, 0]):
        raise SystemExit("an MZ file whose nt header signature is {!r}".format(raw[lfanew:lfanew + 4]))
    machine, nsec = struct.unpack_from("<HH", raw, lfanew + 4)
    symtab, nsyms = struct.unpack_from("<II", raw, lfanew + 12)
    optsz = struct.unpack_from("<H", raw, lfanew + 20)[0]
    opt = lfanew + 24
    magic = struct.unpack_from("<H", raw, opt)[0]
    plus = magic == 0x20B
    dirs_at = opt + (112 if plus else 96)
    ndirs_at = dirs_at - 4
    size_of_headers = struct.unpack_from("<I", raw, opt + 60)[0]
    # Every address the map prints is on the loader's basis, image base included: that is what
    # `objdump -h` shows in its VMA column, and it is what makes a string's address comparable with the
    # targets a disassembly names. The field is 8 bytes wide in PE32+ and 4 in PE32.
    image_base = struct.unpack_from("<Q" if plus else "<I", raw, opt + (24 if plus else 28))[0]
    entry = {
        "machine": MACHINE.get(machine, hex(machine)), "magic": hex(magic), "sections": nsec,
        "sizeofheaders": size_of_headers, "entry": struct.unpack_from("<I", raw, opt + 16)[0],
        "checksum": struct.unpack_from("<I", raw, opt + 64)[0],
        "characteristics": struct.unpack_from("<H", raw, lfanew + 22)[0],
        "directories": struct.unpack_from("<I", raw, ndirs_at)[0] if optsz >= ndirs_at - opt + 4 else 0,
        "filealignment": struct.unpack_from("<I", raw, opt + 36)[0],
    }
    found = [region(0, size_of_headers, "header", "ms-dos stub and nt headers")]
    table = lfanew + 24 + optsz
    found.append(region(table, nsec * 40, "tables", "section headers"))
    if symtab and nsyms:
        found.append(region(symtab, nsyms * 18, "meta", "coff symbols", "not loaded"))
    sections = []
    for index in range(nsec):
        at = table + index * 40
        raw_name = raw[at:at + 8]
        name = raw_name.rstrip(b"\0").decode("utf8", "replace")
        if name.startswith("/") and len(raw_name) >= 5:
            # A long name lives in the string table the COFF header points at, as a decimal offset.
            digits = name[1:]
            where = symtab + nsyms * 18 + int(digits) if digits.isdigit() and symtab else -1
            name = "@{}/{}".format(digits, cstr(raw, where) if where >= 0 else "?")
        vsize = struct.unpack_from("<I", raw, at + 8)[0]
        vaddr = struct.unpack_from("<I", raw, at + 12)[0]
        rawsize = struct.unpack_from("<I", raw, at + 16)[0]
        roff = struct.unpack_from("<I", raw, at + 20)[0]
        chars = struct.unpack_from("<I", raw, at + 36)[0]
        entry.setdefault("section_names", []).append(name)
        if rawsize:
            used = rawsize if not vsize else min(rawsize, vsize)
            found.append(region(roff, used, pe_kind(name, chars), name,
                                "vaddr {:#x}, raw {:#x} in file".format(image_base + vaddr, rawsize)))
        sections.append({"name": name, "roff": roff, "rawsize": rawsize, "chars": chars})
    cert_at = dirs_at + 4 * 8
    if entry["directories"] > 4:
        rva, size = struct.unpack_from("<II", raw, cert_at)
        if size:
            found.append(region(rva, size, "cert", "authenticode", "a file offset, not an rva"))
            entry["cert"] = [rva, size]
    if entry["directories"] > 6:
        entry["debug"] = list(struct.unpack_from("<II", raw, dirs_at + 6 * 8))
    return [each for each in found if each], [], entry


def pe_kind(name, chars):
    if name.startswith((".debug", ".reloc", ".pdata", ".xdata")) and not chars & SCN_CNT_CODE:
        return "meta"
    if chars & SCN_MEM_EXECUTE:
        return "code"
    if chars & SCN_MEM_WRITE:
        return "data"
    if chars & SCN_CNT_CODE and not chars & SCN_CNT_INIT_DATA:
        return "code"
    if name in (".rdata", ".rodata") or chars & SCN_CNT_INIT_DATA:
        return "rodata"
    return "meta"


def shadow(raw):
    if raw[:4] == b"\x7fELF":
        return elf(raw)
    if raw[:2] == b"MZ":
        return pe(raw)
    return None, [], {}


MIN_RUN = 4


def printable_runs(raw, start, stop):
    """Maximal runs of printable ASCII at least MIN_RUN long - binutils' rule, and its default length.

    High bytes break a run here as they do there, so a UTF-8 string is not half-listed: it is not listed,
    and that is the same answer `strings` gives.
    """
    at, found = start, []
    while at < stop:
        if not 0x20 <= raw[at] <= 0x7E:
            at += 1
            continue
        end = at
        while end < stop and 0x20 <= raw[end] <= 0x7E:
            end += 1
        if end - at >= MIN_RUN:
            found.append((at, end - at, raw[at:end].decode("ascii")))
        at = end
    return found


def string_rows(raw, merged):
    """The string list, over the ranges the map itself calls loaded data.

    Scanning only `data` and `rodata` is what separates a string list from a dump of the file: the
    executable bytes, the headers and the symbol tables all contain printable accidents, and IDA's
    Strings window is about data. The address column is the section's own virtual base plus the offset
    into it, which is the basis the region rows already carry in their note.
    """
    rows, scanned, ranges = [], 0, 0
    for each in merged:
        if each["kind"] not in ("data", "rodata"):
            continue
        ranges += 1
        scanned += each["length"]
        found = re.search(r"0x[0-9a-f]+", each["note"])
        vaddr = int(found.group(0), 16) if found else 0
        for at, length, text in printable_runs(raw, each["start"], each["start"] + each["length"]):
            rows.append("string\t{:#x}\t{}\t{}\t{}\t{}".format(
                vaddr + (at - each["start"]), at, length, text, each["name"]))
    return rows, scanned, ranges


def rows_for(raw):
    """The rows the reader prints: every claim in file order, with what falls between them named."""
    claims, loaded, entry = shadow(raw)
    if claims is None:
        raise SystemExit("not an ELF or PE file")
    claims.sort(key=lambda each: (each["start"], 0 if each["kind"] != GAP else 1, each["name"]))
    merged, cursor, free, mapped_free = [], 0, 0, 0
    for each in claims:
        start, length = each["start"], each["length"]
        if start < cursor:
            drop = cursor - start
            if drop >= length:
                continue
            start, length = cursor, length - drop
            each = dict(each, note=(each["note"] + " overlaps").strip())
        if start > cursor:
            gap = start - cursor
            inside = any(at <= cursor and start <= stop for at, stop in loaded)
            if inside:
                mapped_free += gap
            else:
                free += gap
            merged.append(region(cursor, gap, GAP, "alignment padding" if inside else "unreferenced",
                                 "loaded but unaddressed" if inside else "not loaded"))
        merged.append(dict(each, start=start, length=length))
        cursor = max(cursor, start + length)
    if cursor < len(raw):
        free += len(raw) - cursor
        merged.append(region(cursor, len(raw) - cursor, "overlay", "after the last table", "not loaded"))
    claimed = sum(each["length"] for each in merged if each["kind"] not in (GAP, "overlay"))
    rows = ["regions\t{}\tfile\t{}\tclaimed\t{}\tunloaded\t{}\tloaded-unaddressed\t{}".format(
        len(merged), len(raw), claimed, free, mapped_free)]
    found, scanned, ranges = string_rows(raw, merged)
    # Row order is the reader's: the two totals first, then the string list, then the map - so a page can
    # show either half without reading the other.
    rows = [rows[0], "strings\t{}\tmin\t{}\tscanned\t{}\tranges\t{}".format(
        len(found), MIN_RUN, scanned, ranges)] + found + rows[1:]
    rows += ["region\t{}\t{}\t{}\t{}\t{}".format(
        each["start"], each["length"], each["kind"], each["name"], each["note"] or "-")
        for each in merged]
    return rows, entry, merged


def check_strings(name, path, raw, merged):
    """Every run this scan reports must be one binutils reports, at the same offset and length."""
    out = run([tool("strings"), "-t", "x", "-a", "-n", str(MIN_RUN), path])
    listed = {}
    for line in out.splitlines():
        found = re.match(r"^\s*([0-9a-f]+) (.*)$", line)
        if found:
            listed.setdefault(int(found.group(1), 16), []).append(found.group(2))
    for entry in string_rows(raw, merged)[0]:
        _, addr, offset, length, text, _section = entry.split("\t")
        at, want = int(offset), int(length)
        if text not in listed.get(at, []):
            raise SystemExit("{}: strings does not list {!r} at {:#x}".format(name, text, at))
        if len(text) != want:
            raise SystemExit("{}: the run at {:#x} is {} here and {} for strings".format(
                name, at, want, len(text)))


def cross_check(name, path, entry, merged):
    """The parse must agree with binutils about every offset and size the map is built from."""
    if name.endswith(".elf"):
        text = run([tool("readelf"), "-h", "-l", "-S", path])
        for field, pattern in (("phoff", r"Start of program headers:\s+(\d+)"),
                               ("shoff", r"Start of section headers:\s+(\d+)")):
            found = re.search(pattern, text)
            if found and int(found.group(1)) != entry[field]:
                raise SystemExit("{}: readelf puts {} at {}, the parse at {}".format(
                    name, field, found.group(1), entry[field]))
        for found in re.finditer(r"^\s+\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                                 r"([0-9a-f]+)\s+", text, re.M):
            label, addr, off, size = found.groups()
            match = [one for one in merged if one["name"] == label and one["kind"] not in (GAP, "overlay")]
            if not match:
                continue
            if int(off, 16) != match[0]["start"] or int(size, 16) != match[0]["length"]:
                raise SystemExit("{}: readelf puts {} at {:#x}+{:#x}, the parse at {:x}+{:x}".format(
                    name, label, int(off, 16), int(size, 16), match[0]["start"], match[0]["length"]))
        for found in re.finditer(r"^\s+LOAD\s+(\w+) (\w+)", text, re.M):
            off, _rest = found.groups()
            span = [stop for at, stop in entry["load"] if at == int(off, 16)]
            if not span:
                raise SystemExit("{}: readelf's LOAD at {:#x} is not in the parsed segments".format(
                    name, int(off, 16)))
    else:
        text = run([tool("objdump"), "-h", path])
        for found in re.finditer(r"^\s+\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                                 r"([0-9a-f]+)", text, re.M):
            label, vsize, vma, _lma, foff = found.groups()
            match = [one for one in merged if one["name"] == label and one["kind"] not in (GAP, "overlay")]
            if not match:
                continue
            if int(foff, 16) != match[0]["start"]:
                raise SystemExit("{}: objdump puts {} at {:#x}, the parse at {:x}".format(
                    name, label, int(foff, 16), match[0]["start"]))
            # And the address the map carries has to be objdump's VMA - image base included. That is what
            # lets a string's address be compared with the target a disassembly names, which is the whole
            # use of a Strings window with an xref column.
            stated = re.search(r"0x[0-9a-f]+", match[0]["note"])
            if not stated or int(stated.group(0), 16) != int(vma, 16):
                raise SystemExit("{}: objdump gives {} vma {:#x}, the map says {!r}".format(
                    name, label, int(vma, 16), match[0]["note"]))
            # objdump prints the section's *virtual* size, which is the part of its raw span the file
            # claims to use - so the claim's length is that number, not SizeOfRawData.
            if int(vsize, 16) != match[0]["length"]:
                raise SystemExit("{}: objdump sizes {} at {:#x}, the parse claimed {}".format(
                    name, label, int(vsize, 16), match[0]["length"]))


def probe(name, path):
    raw = open(path, "rb").read()
    rows, entry, merged = rows_for(raw)
    cross_check(name, path, entry, merged)
    check_strings(name, path, raw, merged)
    print("== {} {} bytes, {} regions, {} kinds".format(
        name, len(raw), len(merged), len(set(each["kind"] for each in merged))))
    for row in rows:
        print("    ", repr(row))
    return {"bytes": len(raw), "rows": rows, "header": entry}


def main():
    probe_only = "--probe-only" in sys.argv
    names = ["lab.elf", "lab.exe"]
    if probe_only:
        for name in names:
            if not os.path.exists(os.path.join(OUT, name)):
                raise SystemExit("--probe-only needs the committed images; {} is missing".format(name))
        source = OUT
    else:
        build(WORK)
        source = WORK
    report = {}
    for name in names:
        report[name] = probe(name, os.path.join(source, name))
    with open(os.path.join(OUT, "images.probe.json"), "w", encoding="utf8", newline="\n") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print("wrote images.probe.json")
    if not probe_only:
        for name in names:
            shutil.copyfile(os.path.join(source, name), os.path.join(OUT, name))
            print("copied", name, os.path.getsize(os.path.join(OUT, name)), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
