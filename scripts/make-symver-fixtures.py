"""Produce and check the ELF symbol-versioning fixtures.

A shared object can carry one name under several versions and the loader chooses between them by version
index: `.gnu.version` says which index each dynamic symbol holds, `.gnu.version_d` lists the versions this
file defines, and `.gnu.version_r` lists the versions it needs from others. None of it is readable from a
symbol's plain name, so an analyser that skips these three tables cannot say which `lab_second` a call
reaches - and cannot tell the file that *defines* a versioned name from the one that only *asks* for it,
which is the whole difference between `libver.so` and `libuse.so` below.

Three files, cross-compiled for Linux, sharing one version script:

    LAB_1 { global: lab_first; local: *; };
    LAB_2 { global: lab_second; } LAB_1;

    clang --target=x86_64-unknown-linux-gnu -shared -nostdlib -fPIC v.c -o libver.so \
           -Wl,--version-script=v.map -Wl,-soname,libver.so
    clang --target=i386-unknown-linux-gnu   (same arguments)                    -o libver32.so
    clang ... use.c libver.so -o libuse.so -Wl,-soname,libuse.so

`-Wl,-soname` is not decoration: the BASE definition a version script creates is named after the file, so
without it the fixture would carry whatever name the link happened to be asked for. The 32-bit build is
here because `.gnu.version` is an array of `Elf_Half` in both classes while the tables around it are
reached through class-wide words - the only way to catch a reader that assumed one width is a file with
the other.

Three readers have to agree before the probe is written:

    this file's walk                 ->  the three tables, located by section header and again through
                                          DT_VERSYM / DT_VERDEF / DT_VERNEED, which must map onto the
                                          same bytes, and counted against DT_VERDEFNUM / DT_VERNEEDNUM
    readelf -VW                      ->  binutils' listing
    llvm-readobj --version-info      ->  LLVM's listing

What the two listings disagree about stays out of the rows. Indices 0 and 1 are reserved - binutils calls
them `*local*` and `*global*`, LLVM prints no version name at all for them - and LLVM spells a versioned
symbol `lab_second@LAB_2`, one at sign for a reference and two for the definition, which is its
formatting rather than a field. So a symbol row carries the raw halfword, the index with the high bit
taken off, whether that bit was set, and the name the index reaches *in this file*: its own definition
table first, then what it needs from elsewhere, then nothing. That is a lookup, not a claim. The flag
word keeps binutils' spelling, with LLVM's beside it in the README, because the pair is witnessed twice
and the word once.

The hashes are the interesting evidence. `readelf` prints none at all, LLVM prints them, and this script
computes them - the SysV ELF hash of the name, the function the format's own lookup uses - so every hash
in a row has a derivation and a listing behind it. It is also how a wrong record layout reports itself:
shift a `Verneed`'s fields by four bytes and its hash stops matching its name.
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
SCRATCH = os.path.join(ROOT, "temp", "symver-build")

PT_LOAD = 1
PT_DYNAMIC = 2
DT_STRTAB = 5
DT_STRSZ = 10
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
MAX_LISTED = 64

SCRIPT = ("LAB_1 { global: lab_first; local: *; };\n"
          "LAB_2 { global: lab_second; } LAB_1;\n")
PRODUCER = ("long lab_first(long a) { return a + 1; }\n"
            "long lab_second(long a) { return a * lab_first(a); }\n")
CONSUMER = ("extern long lab_second(long);\n"
            "long go(long v) { return lab_second(v); }\n")


def run(cmd, note):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=SCRATCH, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:600]))
    return made


def write(name, text):
    with open(os.path.join(SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build():
    os.makedirs(SCRATCH, exist_ok=True)
    write("v.map", SCRIPT)
    write("v.c", PRODUCER)
    write("use.c", CONSUMER)
    shared = ["clang", "-shared", "-nostdlib", "-fPIC"]
    run(shared + ["--target=x86_64-unknown-linux-gnu", "v.c", "-o", "libver.so",
                  "-Wl,--version-script=v.map", "-Wl,-soname,libver.so"], "libver.so")
    run(shared + ["--target=i386-unknown-linux-gnu", "v.c", "-o", "libver32.so",
                  "-Wl,--version-script=v.map", "-Wl,-soname,libver.so"], "libver32.so")
    run(shared + ["--target=x86_64-unknown-linux-gnu", "use.c", "libver.so", "-o", "libuse.so",
                  "-Wl,-soname,libuse.so"], "libuse.so")


# ------------------------------------------------------------------------------ the file's own words
def elf_hash(text):
    """The SysV ELF hash of a name, which is what a version table's own hash field holds."""
    total = 0
    for one in text.encode():
        total = (total << 4) + one
        high = total & 0xF000_0000
        if high:
            total ^= high >> 24
        total &= (~high) & 0xFFFF_FFFF
    return total


def cstring(raw, at):
    end = raw.find(b"\x00", at)
    return raw[at:end].decode("utf-8", "replace") if end >= 0 else ""


def shape(raw):
    """(is64, little): the class decides the widths, the sixth byte of `e_ident` decides the order."""
    if raw[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    return raw[4] == 2, raw[5] == 1


def word(raw, at, wide, little=True):
    size = 8 if wide else 4
    return int.from_bytes(raw[at:at + size], "little" if little else "big")


def load_map(raw):
    """[(type, file offset, virtual address, file size)] straight out of the program header table."""
    is64, little = shape(raw)
    phoff = word(raw, 32 if is64 else 28, is64, little)
    phentsize, phnum = struct.unpack_from("<HH", raw, 54 if is64 else 42)
    out = []
    for index in range(phnum):
        at = phoff + index * phentsize
        kind = struct.unpack_from("<I", raw, at)[0]
        if is64:
            out.append((kind, word(raw, at + 8, True), word(raw, at + 16, True), word(raw, at + 32, True)))
        else:
            out.append((kind, word(raw, at + 4, False), word(raw, at + 8, False), word(raw, at + 16, False)))
    return out


def to_offset(loads, address):
    for kind, offset, vaddr, filesz in loads:
        if kind == PT_LOAD and vaddr <= address < vaddr + filesz:
            return offset + (address - vaddr)
    return None


class Elf:
    """One ELF file: its section table, its dynamic entries, and the string table both of them index."""

    def __init__(self, raw):
        self.raw = raw
        self.is64, self.little = shape(raw)
        wide = self.is64
        # e_shoff is the eighth u64 of an ELF64 header and the ninth u32 of an ELF32 one; reading the
        # programme-header pointer instead gives a section table that starts inside the headers.
        shoff = word(raw, 40 if wide else 32, wide, self.little)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", raw, 58 if wide else 46)
        rows = []
        for index in range(shnum):
            at = shoff + index * shentsize
            name_at, kind = struct.unpack_from("<II", raw, at)
            rows.append({"name_at": name_at, "type": kind,
                         "offset": word(raw, at + 24 if wide else at + 16, wide, self.little),
                         "size": word(raw, at + 32 if wide else at + 20, wide, self.little),
                         "link": struct.unpack_from("<I", raw, at + 40 if wide else at + 24)[0]})
        strings = rows[shstrndx]["offset"]
        self.sections = {}
        for one in rows:
            one["name"] = cstring(raw, strings + one["name_at"])
            self.sections.setdefault(one["name"], one)
        self.loads = load_map(raw)
        self.dyn = self.dynamic()
        self.strtab = to_offset(self.loads, self.dyn[DT_STRTAB]) if DT_STRTAB in self.dyn else None
        self.strsz = self.dyn.get(DT_STRSZ, 0)

    def dynamic(self):
        """PT_DYNAMIC as {tag: value}; a static executable has no such segment and so no entries."""
        found = next((one for one in self.loads if one[0] == PT_DYNAMIC), None)
        if found is None:
            return {}
        _kind, offset, _vaddr, filesz = found
        wide = self.is64
        step = 16 if wide else 8
        out, at = {}, offset
        while at + step <= offset + filesz:
            tag = word(self.raw, at, wide, self.little)
            value = word(self.raw, at + step // 2, wide, self.little)
            if tag == 0:
                break
            out[tag] = value
            at += step
        return out

    def string(self, at):
        """A string at an offset into the dynamic string table, bounded by that table's own length."""
        if self.strtab is None:
            return None
        start = self.strtab + at
        if start >= self.strtab + self.strsz:
            return None
        return cstring(self.raw, start)

    def table(self, section, tag):
        """(offset, size) for a version table. Where the section header and the dynamic entry both
        speak, they have to point at the same bytes - two routes to one place, and a file that
        contradicts itself between them is refused rather than half read."""
        entry = self.sections.get(section)
        from_header = None if entry is None else (entry["offset"], entry["size"])
        from_dynamic = to_offset(self.loads, self.dyn[tag]) if tag in self.dyn else None
        if from_dynamic is not None and from_header is not None and from_dynamic != from_header[0]:
            raise SystemExit("%s: the section header says %d, %#x maps to %d"
                             % (section, from_header[0], tag, from_dynamic))
        if from_header is not None:
            return from_header
        return None if from_dynamic is None else (from_dynamic, None)

    def versym(self):
        found = self.table(".gnu.version", DT_VERSYM)
        if found is None or not found[1]:
            return []
        at, size = found
        return list(struct.unpack_from(("<" if self.little else ">") + "%dH" % (size // 2), self.raw, at))

    def verdefs(self):
        found = self.table(".gnu.version_d", DT_VERDEF)
        if found is None or not found[1]:
            return []
        at, size = found
        stop, out = at + size, []
        while at + 20 <= stop:
            version, flags, index, count = struct.unpack_from("<HHHH", self.raw, at)
            hash_ = struct.unpack_from("<I", self.raw, at + 8)[0]
            aux_at = at + struct.unpack_from("<I", self.raw, at + 12)[0]
            names = []
            for _ in range(max(count, 1)):
                if aux_at + 8 > stop:
                    break
                name_at, next_at = struct.unpack_from("<II", self.raw, aux_at)
                names.append(self.string(name_at))
                if not next_at:
                    break
                aux_at += next_at
            out.append({"version": version, "flags": flags, "index": index, "count": count,
                        "hash": hash_, "name": names[0] if names else None, "aux": names})
            nxt = struct.unpack_from("<I", self.raw, at + 16)[0]
            if not nxt:
                break
            at += nxt
        claimed = self.dyn.get(DT_VERDEFNUM)
        if claimed is not None and claimed != len(out):
            raise SystemExit("DT_VERDEFNUM says %d, the walk reached %d" % (claimed, len(out)))
        return out

    def verneeds(self):
        found = self.table(".gnu.version_r", DT_VERNEED)
        if found is None or not found[1]:
            return []
        at, size = found
        stop, out, files = at + size, [], 0
        while at + 16 <= stop:
            version, count, file_at, aux_off = struct.unpack_from("<HHII", self.raw, at)
            owner = self.string(file_at)
            files += 1
            aux_at = at + aux_off
            for _ in range(count):
                if aux_at + 16 > stop:
                    break
                # The version index a need carries is `vna_other`, a u16 that has nothing to do with
                # the record's own position - read four bytes later and the loader's number is gone.
                hash_, flags, other, name_at, next_at = struct.unpack_from("<IHHII", self.raw, aux_at)
                out.append({"file": owner, "name": self.string(name_at), "hash": hash_, "flags": flags,
                            "index": other, "version": version, "count": count})
                if not next_at:
                    break
                aux_at += next_at
            nxt = struct.unpack_from("<I", self.raw, at + 12)[0]
            if not nxt:
                break
            at += nxt
        claimed = self.dyn.get(DT_VERNEEDNUM)
        if claimed is not None and claimed != files:
            raise SystemExit("DT_VERNEEDNUM says %d, the walk reached %d" % (claimed, files))
        return out

    def names(self):
        """What each version index reaches in this file: a definition, else a need, else nothing."""
        out = {}
        for one in self.verneeds():
            out.setdefault(one["index"], one["name"])
        for one in self.verdefs():
            out[one["index"]] = one["name"]
        return out


# ------------------------------------------------------------------------------- the two listings
def readelf(path):
    made = subprocess.run(["readelf", "-VW", path], capture_output=True, shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("readelf refused %s" % path)
    symbols, defs, needs = [], [], []
    section, owner = None, None
    for line in made.stdout.decode("utf-8", "replace").splitlines():
        text = line.strip()
        head = re.match(r"Version \w+ section '([^']+)'", text)
        if head:
            section = head.group(1)
            continue
        if section == ".gnu.version" and re.match(r"^[0-9a-fA-F]{3}:", text):
            for one in re.findall(r"(\d+) \(([^)]*)\)", text):
                symbols.append((int(one[0]), one[1]))
        elif section == ".gnu.version_d":
            found = re.search(r"Rev: (\d+) +Flags: (\S+) +Index: (\d+) +Cnt: (\d+) +Name: (\S+)", text)
            if found:
                defs.append((found.group(2), int(found.group(3)), int(found.group(4)), found.group(5)))
        elif section == ".gnu.version_r":
            one = re.match(r"^\S+: Version: (\d+) +File: (\S+) +Cnt: (\d+)", text)
            if one:
                owner = one.group(2)
                continue
            entry = re.match(r"^\S+: +Name: (\S+) +Flags: (\S+) +Version: (\d+)", text)
            if entry:
                needs.append((owner, entry.group(1), entry.group(2), int(entry.group(3))))
    return {"symbols": symbols, "defs": defs, "needs": needs}


def llvm(path):
    made = subprocess.run(["llvm-readobj", "--version-info", path], capture_output=True,
                          shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("llvm-readobj refused %s" % path)
    text = made.stdout.decode("utf-8", "replace")

    def block(name):
        found = re.search(r"%s \[(.*?)\n]" % name, text, re.S)
        return found.group(1) if found else ""

    symbols = [{"version": int(one.group(1)), "name": one.group(2).strip()} for one in
               re.finditer(r"Version: (\d+)\n\s*Name: (.*?)\n", block("VersionSymbols"))]
    defs = [{"flags": int(one.group(1), 16), "index": int(one.group(2)), "hash": int(one.group(3)),
             "name": one.group(4).strip()} for one in
            # The line reads `Flags [ (0x1)` - one closing parenthesis, not two - and a definition that
            # carries `Base` puts that word on the next line, so the gap to `Index:` is not fixed.
            re.finditer(r"Flags \[ \((0x[0-9a-fA-F]+)\).*?\n\s*Index: (\d+)\n\s*Hash: (\d+)\n"
                        r"\s*Name: (\S+)", block("VersionDefinitions"), re.S)]
    needs = [{"file": one.group(1), "hash": int(one.group(2)), "index": int(one.group(3)),
              "name": one.group(4).strip()} for one in
             re.finditer(r"FileName: (\S+)\n\s*Entries \[\n\s*Entry \{\n\s*Hash: (\d+)\n.*?\n"
                         r"\s*Index: (\d+)\n\s*Name: (\S+)", block("VersionRequirements"), re.S)]
    return {"symbols": symbols, "defs": defs, "needs": needs}


RESERVED = ("*local*", "*global*")


def check(name, elf, first, second):
    """The walk against both listings, field by field. A disagreement stops the probe being written."""
    symbols, defs, needs = elf.versym(), elf.verdefs(), elf.verneeds()
    for label, mine, one, two in (("symbol", symbols, first["symbols"], second["symbols"]),
                                  ("definition", defs, first["defs"], second["defs"]),
                                  ("need", needs, first["needs"], second["needs"])):
        if len(mine) != len(one) or len(mine) != len(two):
            raise SystemExit("%s: the walk lists %d %ss, readelf %d, llvm %d"
                             % (name, len(mine), label, len(one), len(two)))
    by_index = elf.names()
    for index, (mine, one, two) in enumerate(zip(symbols, first["symbols"], second["symbols"])):
        plain = mine & 0x7FFF
        if plain != one[0]:
            raise SystemExit("%s: symbol %d holds %#x, readelf prints index %d" % (name, index, mine, one[0]))
        if plain != two["version"]:
            raise SystemExit("%s: symbol %d holds %#x, llvm prints index %d"
                             % (name, index, mine, two["version"]))
        reached = by_index.get(plain)
        if one[1] and one[1] not in RESERVED and reached != one[1]:
            raise SystemExit("%s: readelf calls symbol %d's index %d %r, the tables here say %r"
                             % (name, index, plain, one[1], reached))
        tail = two["name"].rsplit("@", 1)[-1]
        if plain and reached is not None and tail and tail != reached:
            raise SystemExit("%s: llvm calls symbol %d %r, where index %d is %r"
                             % (name, index, two["name"], plain, reached))
    for mine, one, two in zip(defs, first["defs"], second["defs"]):
        if mine["index"] != one[1] or mine["index"] != two["index"]:
            raise SystemExit("%s: definition index %d, readelf %d, llvm %d"
                             % (name, mine["index"], one[1], two["index"]))
        if mine["count"] != one[2]:
            raise SystemExit("%s: definition %r carries %d names, readelf says %d"
                             % (name, mine["name"], mine["count"], one[2]))
        if mine["name"] != one[3] or mine["name"] != two["name"]:
            raise SystemExit("%s: definition %r, readelf %r, llvm %r" % (name, mine["name"], one[3], two["name"]))
        if mine["hash"] != elf_hash(mine["name"] or "") or mine["hash"] != two["hash"]:
            raise SystemExit("%s: %r carries hash %d, the ELF hash is %d, llvm prints %d"
                             % (name, mine["name"], mine["hash"], elf_hash(mine["name"] or ""), two["hash"]))
        base = mine["flags"] == 1
        if (one[0] == "BASE") != base or (((two["flags"] & 1) != 0) != base):
            raise SystemExit("%s: definition %r flags %#x, readelf %r, llvm %#x"
                             % (name, mine["name"], mine["flags"], one[0], two["flags"]))
    for mine, one, two in zip(needs, first["needs"], second["needs"]):
        if mine["file"] != one[0] or mine["file"] != two["file"]:
            raise SystemExit("%s: a need names the file %r, readelf %r, llvm %r"
                             % (name, mine["file"], one[0], two["file"]))
        if mine["name"] != one[1] or mine["name"] != two["name"]:
            raise SystemExit("%s: a need names %r, readelf %r, llvm %r"
                             % (name, mine["name"], one[1], two["name"]))
        if mine["index"] != one[3] or mine["index"] != two["index"]:
            raise SystemExit("%s: a need's index is %d, readelf %d, llvm %d"
                             % (name, mine["index"], one[3], two["index"]))
        if mine["hash"] != elf_hash(mine["name"] or "") or mine["hash"] != two["hash"]:
            raise SystemExit("%s: %r carries hash %d, the ELF hash is %d, llvm prints %d"
                             % (name, mine["name"], mine["hash"], elf_hash(mine["name"] or ""), two["hash"]))
    return symbols, defs, needs


def flag_word(value):
    """binutils writes `BASE` and `none` where LLVM prints a bracketed list; the row keeps binutils'."""
    return "BASE" if value == 1 else "none"


def need_flag_word(value):
    """A need's own flag bit means something else again - `VER_FLG_NODEFLIB` - and the only value these
    files carry is zero, which both readers write as none. Anything else is left unnamed."""
    return "none" if value == 0 else "-"


def rows(elf, symbols, defs, needs):
    def spot(section, tag):
        found = elf.table(section, tag)
        return -1 if found is None else found[0]

    reached = elf.names()
    said = lambda value: "-" if value is None else value
    out = ["\t".join(["symver",
                      "symbols\t%d" % len(symbols),
                      "defs\t%d" % len(defs),
                      "needs\t%d" % len(needs),
                      "versym\t%d" % spot(".gnu.version", DT_VERSYM),
                      "verdef\t%d" % spot(".gnu.version_d", DT_VERDEF),
                      "verneed\t%d" % spot(".gnu.version_r", DT_VERNEED),
                      "bits\t%d" % (64 if elf.is64 else 32)])]
    for index, one in enumerate(symbols[:MAX_LISTED]):
        plain = one & 0x7FFF
        out.append("\t".join(["symbol", str(index),
                              "value\t0x%x" % one,
                              "index\t%d" % plain,
                              "name\t%s" % said(reached.get(plain)),
                              "hidden\t%s" % ("yes" if one & 0x8000 else "no")]))
    for index, one in enumerate(defs[:MAX_LISTED]):
        out.append("\t".join(["def", str(index),
                              "index\t%d" % one["index"],
                              "hash\t%d" % one["hash"],
                              "flags\t%s" % flag_word(one["flags"]),
                              "name\t%s" % said(one["name"]),
                              "cnt\t%d" % one["count"],
                              "version\t%d" % one["version"]]))
    for index, one in enumerate(needs[:MAX_LISTED]):
        out.append("\t".join(["need", str(index),
                              "file\t%s" % said(one["file"]),
                              "name\t%s" % said(one["name"]),
                              "hash\t%d" % one["hash"],
                              "index\t%d" % one["index"],
                              "flags\t%s" % need_flag_word(one["flags"]),
                              "version\t%d" % one["version"]]))
    for label, length in (("symbols", len(symbols)), ("defs", len(defs)), ("needs", len(needs))):
        if length > MAX_LISTED:
            out.append("cut\t%s\t%d\tlisted\t%d" % (label, length, MAX_LISTED))
    return out


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    build()
    probe = {}
    for name in ("libver.so", "libver32.so", "libuse.so", "lab.so", "lab.elf", "liblab.so"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        path = os.path.join(SCRATCH, name)
        elf = Elf(open(path, "rb").read())
        first = readelf(path)
        second = llvm(path)
        found = check(name, elf, first, second)
        made = rows(elf, *found) if any(found) else []
        if made:
            print("%-12s %d symbols, %d definitions, %d needs" % (name, len(found[0]), len(found[1]),
                                                                  len(found[2])))
            for row in made:
                print("%-12s %s" % ("", row.replace("\t", " | ")))
        else:
            print("%-12s no version tables, and both readers agree" % name)
        probe[name] = {"symbols": len(found[0]), "defs": len(found[1]), "needs": len(found[2]), "rows": made}
    for name in ("libver.so", "libver32.so", "libuse.so"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "symver.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, readelf and llvm-readobj agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
