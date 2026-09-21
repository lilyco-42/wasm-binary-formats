"""Produce and check the Mach-O fixtures.

A Mach-O file keeps everything behind one kind of record: the header says how many load commands
follow it, each command says how long it is, and the sections, the symbol table and the relocations
are all found by walking that chain. Two shapes matter to an analyser. An *object* has one segment
whose addresses start at zero and carries a relocation per instruction that names something; an
*image* has its segments placed at real addresses, has no relocations left, and ends in tables that
nothing in the file runs.

Four files, all written on this host by `clang` and by `ld.lld -flavor darwin` - neither needs an SDK
or a macOS box, which is why this lane could be measured at all:

    clang --target=x86_64-apple-macosx11.0 -c  ->  macho64.o   (5 sections, 8 relocations)
    clang --target=arm64-apple-macosx11.0 -c   ->  macho-arm.o (4 sections, ARM64_RELOC_* names)
    clang --target=i386-apple-macosx10.13 -c   ->  macho32.o   (the 32-bit record shapes)
    ld.lld -flavor darwin -e _main             ->  macho.mh    (__PAGEZERO, r-x, rw-, r--)

Five readings have to agree before the probe is written:

    this file's walk        ->  commands, sections, nlist entries, the relocation info word
    llvm-readobj --file-headers ->  Magic, CpuType, FileType, NumOfLoadCommands, SizeOfLoadCommands
    llvm-readobj --macho-segment ->  each segment's vmaddr, vmsize, fileoff, filesize, prot, nsects
    llvm-objdump -h / llvm-nm -m / llvm-objdump -r ->  sections, symbols, relocations
    llvm-readobj --relocs / --macho-dysymtab ->  the info word split four ways, and the symbol ranges

Two disagreements are the reason this file exists, and both are recorded in the probe rather than
smoothed over:

1. `n_sect` is **one-based**: a section symbol with `n_sect` 1 names the section the file's own
   section list calls index 0, and `llvm-nm -m` prints `(__TEXT,__text)` beside it, so the pairing is
   checkable symbol by symbol. A reader that hands `n_sect` to a zero-based section list is one place
   off for every symbol in the file - which is what the Rust `object` crate does here, so the row says
   both numbers and the test is forced to look. The zero in an undefined symbol is not a section.
2. A *non-extern* relocation's 24-bit field is an index into the local symbols as the file means it,
   while `llvm-objdump -r` and `llvm-readobj --relocs` print the section that number reaches: on
   `macho64.o` the field says `__text` where the local symbol at that index is `_lab_hidden`. So the
   rows give the number and `extern no`, and leave the name column `-` instead of choosing a reading.

The colour a section earns comes from its own attribute word, checked against the independent word
LLVM prints beside it: `S_ATTR_PURE_INSTRUCTIONS` (0x80000000) marks the bytes a processor runs, and
LLVM's `Type` column says TEXT for exactly those sections in all four files. `S_ATTR_DEBUG`
(0x02000000) marks `__compact_unwind`, which is why that section is called meta rather than data. A
section with no bytes in the file - `__bss` is `S_ZEROFILL` - cannot be coloured at all, and its row
says `disk no` so the reader's silence is expected rather than silently missed.

All four files come out byte-identical when the script is run twice, so a probe can be diffed against
the fixtures it describes; nothing here needed a timestamp pinned to make that true.
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
SCRATCH = os.path.join(ROOT, "temp", "macho-build")

MAX_LISTED = 64

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
SWAPPED = (0xCEFAEDFE, 0xCFFAEDFF)
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_SEGMENT_64 = 0x19
SECTION_TYPE = 0xFF
S_ZEROFILL = 0x1
S_THREAD_LOCAL_ZEROFILL = 0x12
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_DEBUG = 0x02000000
N_TYPE = 0x0E
N_SECT = 0xE
N_UNDF = 0x0
N_ABS = 0x2
N_EXT = 0x1

OBJECTS = {
    "macho64.o": "--target=x86_64-apple-macosx11.0",
    "macho-arm.o": "--target=arm64-apple-macosx11.0",
    "macho32.o": "--target=i386-apple-macosx10.13",
}
FIXTURES = list(OBJECTS) + ["macho.mh"]

LAB_SOURCE = """\
extern int lab_external(int);
const char lab_text[] = "mach-o laboratory";
int lab_count = 7;
int lab_static = 3;
static int lab_hidden(void) { return lab_static + 1; }
int lab_run(int seed) {
  lab_count += seed;
  return lab_external(lab_count) + lab_hidden();
}
"""

MAIN_SOURCE = """\
int lab_external(int x) { return x + 1; }
extern const char lab_text[];
extern int lab_run(int);
int main(void) { return lab_run(3) + lab_text[0] + lab_external(1); }
"""


def run(cmd, note):
    """Run one reader, and say what it was for if it fails."""
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        sys.exit("%s failed (%s):\n%s" % (note, " ".join(cmd), proc.stderr or proc.stdout))
    return proc.stdout


def tool(name):
    """The full path of a tool, because a Windows host needs the `.exe` and a Linux one must not add it."""
    found = shutil.which(name)
    if found is None:
        sys.exit("%s is not on PATH" % name)
    return found


def build():
    """Compile the three objects, link the image, and copy all four into the fixtures."""
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    lab = os.path.join(SCRATCH, "lab.c")
    for handle, text in ((open(lab, "w", newline="\n"), LAB_SOURCE),
                         (open(os.path.join(SCRATCH, "main.c"), "w", newline="\n"), MAIN_SOURCE)):
        with handle:
            handle.write(text)
    for name, target in OBJECTS.items():
        run([tool("clang"), target, "-c", lab, "-o", os.path.join(SCRATCH, name)],
            "clang -c " + name)
    main64 = os.path.join(SCRATCH, "main64.o")
    run([tool("clang"), OBJECTS["macho64.o"], "-c", os.path.join(SCRATCH, "main.c"), "-o", main64],
        "clang -c main.c")
    # `ld64.lld` is LLVM's Mach-O linker, and it takes the same arguments as Apple's `ld64` - which
    # means no SDK, no macOS box, and an image whose segments carry the protections a loader reads.
    run([tool("ld64.lld"), "-arch", "x86_64", "-platform_version", "macos", "11.0", "11.0",
         "-e", "_main", "-o", os.path.join(SCRATCH, "macho.mh"), main64,
         os.path.join(SCRATCH, "macho64.o")], "ld64.lld")
    for name in FIXTURES:
        one = os.path.join(SCRATCH, name)
        if not os.path.isfile(one) or os.path.getsize(one) == 0:
            sys.exit("%s was not produced" % name)
        shutil.copyfile(one, os.path.join(FIX, name))


# --------------------------------------------------------------------------------------- the walk


def sixteen(raw, at):
    return raw[at:at + 16].split(b"\x00")[0].decode("utf-8", "replace")


def walk(raw):
    """Every table a Mach-O file has, as the file itself spells it. None means it is not Mach-O."""
    if len(raw) < 32:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic in SWAPPED:
        # Readable in principle, and nothing here produces one, so the walk says no rather than
        # guess at a shape it has never seen a reader print.
        return None
    if magic == MH_MAGIC_64:
        wide = True
    elif magic == MH_MAGIC:
        wide = False
    else:
        return None
    head = 32 if wide else 28
    entry = 16 if wide else 12
    section_size = 80 if wide else 68
    segment_head = 72 if wide else 56
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds = struct.unpack_from("<6I", raw, 0)
    flags = struct.unpack_from("<I", raw, 24)[0]
    out = {
        "cputype": cputype, "cpusubtype": cpusubtype, "filetype": filetype, "cmds": ncmds,
        "cmdbytes": sizeofcmds, "flags": flags, "bits": 64 if wide else 32, "wide": wide,
        "segments": [], "sections": [], "symbols": [], "strings": (0, 0),
        "symtab": None, "dysymtab": None,
    }
    at = head
    for _ in range(ncmds):
        if at + 8 > len(raw):
            sys.exit("a load command runs off the end of the file")
        cmd, cmdsize = struct.unpack_from("<2I", raw, at)
        if cmdsize < 8 or at + cmdsize > len(raw):
            sys.exit("load command %08x at %d claims %d bytes" % (cmd, at, cmdsize))
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            # `segname` ends at 24 in both shapes, so the address fields start there and only grow
            # wider; the protection words sit behind them and `nsects` behind those.
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<4Q" if wide else "<4I", raw, at + 24)
            maxprot, initprot, nsects = struct.unpack_from("<3I", raw, at + (56 if wide else 40))
            out["segments"].append({
                "name": sixteen(raw, at + 8), "vmaddr": vmaddr, "vmsize": vmsize,
                "fileoff": fileoff, "filesize": filesize, "maxprot": maxprot,
                "initprot": initprot, "nsects": nsects,
            })
            for each in range(nsects):
                p = at + segment_head + each * section_size
                if p + section_size > len(raw):
                    sys.exit("a section record runs off the end")
                addr, size = struct.unpack_from("<2Q" if wide else "<2I", raw, p + 32)
                offset, align, reloff, nreloc, sectflags = struct.unpack_from(
                    "<5I", raw, p + (48 if wide else 40))
                out["sections"].append({
                    "sect": sixteen(raw, p), "seg": sixteen(raw, p + 16), "addr": addr,
                    "size": size, "offset": offset, "align": align, "reloff": reloff,
                    "nreloc": nreloc, "flags": sectflags,
                })
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", raw, at + 8)
            out["symtab"] = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
            out["strings"] = (stroff, strsize)
        elif cmd == LC_DYSYMTAB:
            keys = ["ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym",
                    "toccoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms",
                    "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff",
                    "nlocreloc"]
            out["dysymtab"] = dict(zip(keys, struct.unpack_from("<18I", raw, at + 8)))
        at += cmdsize
    if out["symtab"] is None:
        return out
    start, size = out["strings"]
    for each in range(out["symtab"]["nsyms"]):
        p = out["symtab"]["symoff"] + each * entry
        if p + entry > len(raw):
            sys.exit("an nlist entry runs off the end")
        strx, ntype, nsect, desc, value = struct.unpack_from("<IBBH" + ("Q" if wide else "I"), raw, p)
        stop = raw.find(b"\x00", start + strx)
        kind = ((ntype & N_TYPE) == N_SECT and "sect") or (
            (ntype & N_TYPE) == N_UNDF and "undef") or (
            (ntype & N_TYPE) == N_ABS and "abs") or "other"
        out["symbols"].append({
            "index": each, "name": raw[start + strx:stop].decode("utf-8", "replace"),
            "value": value, "type": ntype, "sect": nsect, "desc": desc, "kind": kind,
            "extern": bool(ntype & N_EXT),
        })
    return out


# --------------------------------------------------------------------------- the borrowed readings


def readobj_flags(text):
    """The header words, as llvm-readobj --file-headers spells them."""
    out = {}
    for key, pattern in (
        ("cputype", r"CpuType: (\S+) \(0x([0-9A-Fa-f]+)\)"),
        ("filetype", r"FileType: (\S+) \(0x([0-9A-Fa-f]+)\)"),
        ("ncmds", r"NumOfLoadCommands: (\d+)"),
        ("cmdbytes", r"SizeOfLoadCommands: (\d+)"),
    ):
        hit = re.search(pattern, text)
        if hit:
            out[key] = hit.group(2) if hit.lastindex == 2 else hit.group(1)
    out["flag_names"] = re.findall(r"^\s+(MH_\S+) \(0x([0-9a-f]+)\)$", text, re.M)
    return out


def readobj_segments(text):
    """Every `Segment { ... }` block llvm-readobj --macho-segment prints."""
    out = []
    for block in re.findall(r"Segment \{(.*?)\n\}", text, re.S):
        one = {}
        for key, pattern in (
            ("name", r"Name: (\S*)"), ("vmaddr", r"vmaddr: (0x[0-9a-fA-F]+)"),
            ("vmsize", r"vmsize: (0x[0-9a-fA-F]+)"), ("fileoff", r"fileoff: (\d+)"),
            ("filesize", r"filesize: (\d+)"), ("nsects", r"nsects: (\d+)"),
            ("maxprot", r"maxprot: (\S+)"), ("initprot", r"initprot: (\S+)"),
        ):
            hit = re.search(pattern, block)
            one[key] = hit.group(1) if hit else None
        out.append(one)
    return out


def readobj_dysymtab(text):
    out = {}
    for key in ("ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym"):
        hit = re.search(r"%s: (\d+)" % key, text)
        if hit:
            out[key] = int(hit.group(1))
    return out


def objdump_sections(text):
    """`llvm-objdump -h`: Idx, Name, Size, VMA and the Type word LLVM chooses for itself."""
    out = []
    for line in text.splitlines():
        hit = re.match(r"^\s*(\d+) (\S+)\s+([0-9a-fA-F]{8}) ([0-9a-fA-F]{8,16}) (\S+)\s*$", line)
        if hit:
            out.append({
                "index": int(hit.group(1)), "name": hit.group(2), "size": int(hit.group(3), 16),
                "vma": int(hit.group(4), 16), "type": hit.group(5),
            })
    return out


def objdump_symbols(text):
    """`llvm-nm -m`: value, (SEG,sect) or (undefined), an optional marker, the scope word, the name.

    A linked image adds `[referenced dynamically]` before the scope for the header symbol the linker
    invents, and that column is not part of any claim made here, so the pattern lets it stand or go.
    """
    out = []
    for line in text.splitlines():
        hit = re.match(
            r"^([0-9a-fA-F]{8,16})?\s*\(([^)]*)\)\s*(?:\[[^]]*\]\s*)?(\S+)\s+(\S+)$", line)
        if not hit:
            continue
        value, place, scope, name = hit.groups()
        out.append({
            "value": int(value, 16) if value else 0, "place": place, "scope": scope, "name": name,
        })
    return out


def objdump_relocs(text):
    """`llvm-objdump -r`: which section a block belongs to, then offset, type name, value."""
    out = []
    current = None
    for line in text.splitlines():
        block = re.match(r"^RELOCATION RECORDS FOR \[([^]]*)\]:", line)
        if block:
            current = block.group(1)
            continue
        hit = re.match(r"^([0-9a-fA-F]{8,16}) (\S+)\s+(.*)$", line)
        if hit and current is not None:
            out.append({
                "section": current, "offset": int(hit.group(1), 16), "type": hit.group(2),
                "value": hit.group(3).strip(),
            })
    return out


def readobj_relocs(text):
    """`llvm-readobj --relocs`: `0x46 1 2 1 X86_64_RELOC_SIGNED 0 _lab_static` on one line.

    The three numbers after the address are the info word's own bits in the order the struct declares
    them - `r_pcrel`, `r_length`, `r_extern` - and the last column before the name is a field no row of
    this lane uses.
    """
    out = []
    current = None
    for line in text.splitlines():
        block = re.match(r"^\s*Section (\S+) \{", line)
        if block:
            current = block.group(1)
            continue
        hit = re.match(r"^\s*0x([0-9a-fA-F]+) (\d+) (\d+) (\d+) (\S+) (\d+) (\S+)\s*$", line)
        if hit and current is not None:
            out.append({
                "section": current, "offset": int(hit.group(1), 16), "pcrel": int(hit.group(2)),
                "length": int(hit.group(3)), "extern": int(hit.group(4)), "name": hit.group(5),
                "value": hit.group(7),
            })
    return out


# ---------------------------------------------------------------------------------- the agreement


def prot_text(bits):
    """The three protection letters, in the order llvm-readobj prints them."""
    return "%s%s%s" % ("r" if bits & 1 else "-", "w" if bits & 2 else "-", "x" if bits & 4 else "-")


def classify(section):
    """What the section's own attribute word says its bytes are, or why it cannot say."""
    flags = section["flags"]
    if section["size"] == 0:
        return None, "empty"
    if flags & SECTION_TYPE in (S_ZEROFILL, S_THREAD_LOCAL_ZEROFILL):
        return None, "no bytes in the file"
    if flags & S_ATTR_DEBUG:
        return "meta", "S_ATTR_DEBUG"
    if flags & S_ATTR_PURE_INSTRUCTIONS:
        return "code", "instructions"
    if section["seg"] == "__TEXT":
        return "rodata", "in __TEXT, not instructions"
    if section["seg"] == "__DATA":
        return "data", "in __DATA"
    return None, "unclassified"


def check(name, raw, model):
    """Ask the readers the questions the walk answered, and refuse to write the probe otherwise."""
    path = os.path.join(FIX, name)
    header = readobj_flags(run([tool("llvm-readobj"), "--file-headers", path], "readobj --file-headers"))
    segments = readobj_segments(run([tool("llvm-readobj"), "--macho-segment", path], "readobj segment"))
    listing = objdump_sections(run([tool("llvm-objdump"), "-h", path], "objdump -h"))
    printed = objdump_symbols(run([tool("llvm-nm"), "-m", path], "nm -m"))
    dumped = objdump_relocs(run([tool("llvm-objdump"), "-r", path], "objdump -r"))
    readed = readobj_relocs(run([tool("llvm-readobj"), "--relocs", path], "readobj --relocs"))
    dys = readobj_dysymtab(run([tool("llvm-readobj"), "--macho-dysymtab", path], "readobj dysymtab"))

    bad = []
    want = (model["cputype"], model["filetype"], model["cmds"], model["cmdbytes"])
    got = (int(header["cputype"], 16), int(header["filetype"], 16), int(header["ncmds"]),
           int(header["cmdbytes"]))
    if want != got:
        bad.append("header walk %s vs readobj %s" % (want, got))
    if len(segments) != len(model["segments"]):
        bad.append("%d segments walked, readobj printed %d" % (len(model["segments"]), len(segments)))
    for mine, theirs in zip(model["segments"], segments):
        pair = [
            (mine["name"], theirs["name"] or ""),
            (mine["vmaddr"], int(theirs["vmaddr"], 16)),
            (mine["vmsize"], int(theirs["vmsize"], 16)),
            (mine["fileoff"], int(theirs["fileoff"])),
            (mine["filesize"], int(theirs["filesize"])),
            (mine["nsects"], int(theirs["nsects"])),
            (prot_text(mine["maxprot"]), theirs["maxprot"]),
            (prot_text(mine["initprot"]), theirs["initprot"]),
        ]
        for one, two in pair:
            if one != two:
                bad.append("segment %s: walk %r, readobj %r" % (mine["name"], one, two))
    if len(listing) != len(model["sections"]):
        bad.append("%d sections walked, objdump listed %d" % (len(model["sections"]), len(listing)))
    kinds = []
    for mine, theirs in zip(model["sections"], listing):
        if [mine["sect"], mine["size"], mine["addr"]] != [theirs["name"], theirs["size"],
                                                          theirs["vma"]]:
            bad.append("section %s: walk %r, objdump %r" % (mine["sect"], mine, theirs))
        kind, why = classify(mine)
        # The rule earns its colour only where LLVM's own column for the same section agrees.
        if kind == "code" and theirs["type"] != "TEXT":
            bad.append("%s: PURE_INSTRUCTIONS, objdump calls it %s (%s)"
                       % (mine["sect"], theirs["type"], why))
        if kind != "code" and theirs["type"] == "TEXT":
            bad.append("%s: objdump calls it TEXT, its flags do not (%s)" % (mine["sect"], why))
        kinds.append((mine, kind, theirs["type"]))
    order = {one["sect"]: index for index, one in enumerate(model["sections"])}
    symbols = []
    for mine in model["symbols"]:
        named = [one for one in printed if one["name"] == mine["name"]]
        place = "-"
        if mine["kind"] == "sect" and mine["sect"] == 0:
            bad.append("%s: N_SECT with n_sect 0" % mine["name"])
        if mine["sect"]:
            hit = model["sections"][mine["sect"] - 1]
            place = "%s,%s" % (hit["seg"], hit["sect"])
        if not named:
            bad.append("llvm-nm never printed %s" % mine["name"])
        else:
            seen = named[0]
            if seen["value"] != mine["value"]:
                bad.append("%s: value %#x, nm %#x" % (mine["name"], mine["value"], seen["value"]))
            if place != "-" and seen["place"] not in (place, "undefined"):
                bad.append("%s: n_sect %d means (%s), nm says (%s)"
                           % (mine["name"], mine["sect"], place, seen["place"]))
            scope = "external" if mine["extern"] else "non-external"
            if seen["place"] != "undefined" and seen["scope"] != scope:
                bad.append("%s: n_type %02x says %s, nm says %s"
                           % (mine["name"], mine["type"], scope, seen["scope"]))
        symbols.append({
            "index": mine["index"], "name": mine["name"], "value": mine["value"],
            "sect": (mine["sect"] - 1) if mine["sect"] else None, "n_sect": mine["sect"],
            "extern": mine["extern"], "kind": mine["kind"],
        })
    if dys and model["dysymtab"]:
        for key in sorted(dys):
            if model["dysymtab"].get(key) != dys[key]:
                bad.append("dysymtab %s: walk %s, readobj %s"
                           % (key, model["dysymtab"].get(key), dys[key]))
        cover = dys["nlocalsym"] + dys["nextdefsym"] + dys["nundefsym"]
        if cover != model["symtab"]["nsyms"]:
            bad.append("the three symbol ranges cover %d of %d" % (cover, model["symtab"]["nsyms"]))
    fixes = []
    scattered = 0
    for section in model["sections"]:
        for each in range(section["nreloc"]):
            address, info = struct.unpack_from("<2I", raw, section["reloff"] + each * 8)
            if address >> 31:
                # A scattered record says so in bit 31 of its *address* and repacks the rest of the
                # word for a different job: four type bits and no symbol index at all. Nothing in this
                # lane names those, so the count is what the row carries.
                scattered += 1
                continue
            index = info & 0xFFFFFF
            pcrel = (info >> 24) & 1
            shift = (info >> 25) & 3
            extern = (info >> 27) & 1
            number = (info >> 28) & 7
            listed = [one for one in readed if one["section"] == section["sect"]
                      and one["offset"] == address]
            seen = [one for one in dumped if one["section"] == section["sect"]
                    and one["offset"] == address]
            if not listed or not seen:
                bad.append("no reader printed the relocation at %#x in %s"
                           % (address, section["sect"]))
                continue
            if (shift, extern, pcrel) != (listed[0]["length"], listed[0]["extern"],
                                          listed[0]["pcrel"]):
                bad.append("reloc %#x: the info word splits %d/%d/%d, readobj prints %s"
                           % (address, shift, extern, pcrel, listed[0]))
            if seen[0]["type"] != listed[0]["name"]:
                bad.append("reloc %#x: objdump says %s, readobj says %s"
                           % (address, seen[0]["type"], listed[0]["name"]))
            spelled = "-"
            if extern:
                if index >= len(symbols):
                    bad.append("reloc %#x names symbol %d of %d" % (address, index, len(symbols)))
                elif symbols[index]["name"] != listed[0]["value"]:
                    bad.append("reloc %#x: symbol %d is %s, readers print %s"
                               % (address, index, symbols[index]["name"], listed[0]["value"]))
                else:
                    spelled = listed[0]["value"]
            elif listed[0]["value"] != (symbols[index]["name"] if index < len(symbols) else "?"):
                # Both readings are on show in the fixtures: the number reaches a local symbol as the
                # file means it and a section as the readers print it. Neither becomes a name.
                if listed[0]["value"] not in order:
                    bad.append("reloc %#x: %r is neither a local symbol nor a section"
                               % (address, listed[0]["value"]))
            fixes.append({
                "section": section["sect"], "address": address, "number": number,
                "name": listed[0]["name"], "bytes": 1 << shift, "pcrel": bool(pcrel),
                "extern": bool(extern), "index": index, "spelled": spelled,
            })
    # A number earns its name only where the pairing is a function both ways: one number standing
    # for two names, or one name for two numbers, would mean the bits were taken from the wrong place.
    pairs = {}
    for one in fixes:
        pairs.setdefault(one["number"], set()).add(one["name"])
    for number, names in pairs.items():
        if len(names) != 1:
            bad.append("type %d is printed as %s" % (number, sorted(names)))
        for other, onames in pairs.items():
            if other != number and names & onames:
                bad.append("%d and %d share the name %s" % (number, other, sorted(names & onames)[0]))
    return bad, kinds, symbols, fixes, scattered, len(readed)


def probe_rows(model, kinds, symbols, fixes, scattered):
    """The probe's rows: what the map must show, and the relocation window as the reader emits it."""
    out = []
    for index, (section, kind, said) in enumerate(kinds):
        out.append("\t".join([
            "sect", str(index), "%s,%s" % (section["seg"], section["sect"]),
            "off", str(section["offset"]), "size", str(section["size"]),
            "disk", "yes" if kind else "no", "kind", kind or "-", "reader", said,
        ]))
    for mine in symbols:
        out.append("\t".join([
            "sym", str(mine["index"]), mine["name"], "addr", str(mine["value"]),
            "sect", "-" if mine["sect"] is None else str(mine["sect"]),
            "n_sect", str(mine["n_sect"]), "extern", "yes" if mine["extern"] else "no",
        ]))
    tables = []
    for one in fixes:
        if one["section"] not in tables:
            tables.append(one["section"])
    out.append("\t".join([
        "relocs", "kind", "sect", "tables", str(len(tables)), "entries", str(len(fixes)),
        "external", str(len([one for one in fixes if one["extern"]])),
        "scattered", str(scattered), "bits", str(model["bits"]),
    ]))
    for section in tables:
        listed = [one for one in fixes if one["section"] == section]
        out.append("\t".join(["table", section, "entries", str(len(listed)), "slot_bytes", "8",
                              "addend", "no"]))
    for one in fixes[:MAX_LISTED]:
        out.append("\t".join([
            "fixup", "0x%x" % one["address"], "type", str(one["number"]), "name", one["name"],
            "len", str(one["bytes"]), "pcrel", "yes" if one["pcrel"] else "no",
            "extern", "yes" if one["extern"] else "no",
            "sym", one["spelled"], "index", str(one["index"]), "section", one["section"],
        ]))
    if len(fixes) > MAX_LISTED:
        out.append("\t".join(["cut", "fixups", str(len(fixes)), "listed", str(MAX_LISTED)]))
    return out


def main():
    build()
    probe = {}
    problems = []
    for name in FIXTURES:
        with open(os.path.join(FIX, name), "rb") as handle:
            raw = handle.read()
        model = walk(raw)
        if model is None:
            problems.append("%s is not Mach-O to this walk" % name)
            continue
        bad, kinds, symbols, fixes, scattered, counted = check(name, raw, model)
        problems.extend("%s: %s" % (name, one) for one in bad)
        records = sum(one["nreloc"] for one in model["sections"])
        if len(fixes) + scattered != records:
            problems.append("%s: the sections claim %d records, the walk read %d"
                            % (name, records, len(fixes) + scattered))
        # `llvm-readobj --relocs` prints a scattered record's extern column as `n/a`, and
        # `llvm-objdump -r` folds each `GENERIC_RELOC_PAIR` into the SECTDIFF before it as an
        # expression, so the readers' line count reaches the non-scattered records only.
        if counted != len(fixes):
            problems.append("%s: %d named records, the readers printed %d"
                            % (name, len(fixes), counted))
        probe[name] = {"rows": probe_rows(model, kinds, symbols, fixes, scattered)}
    if problems:
        sys.stderr.write("\n".join(problems[:40]) + "\n")
        sys.exit("refusing to write the probe: %d disagreement(s)" % len(problems))
    with open(os.path.join(FIX, "macho.probe.json"), "w", newline="\n") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("wrote macho.probe.json with %d fixtures" % len(probe))
    for name in sorted(probe):
        print("  %-12s %3d rows" % (name, len(probe[name]["rows"])))


if __name__ == "__main__":
    main()
