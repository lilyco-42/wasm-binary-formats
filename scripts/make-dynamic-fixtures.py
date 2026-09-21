"""Produce and check the ELF dynamic-section fixtures.

The four existing ELF files answer three shapes already: `lab.elf` has no dynamic section at all (a
static executable), `lab.so` and `labarm.so` carry 14 entries in 64-bit records with no library names
(`-nostdlib` leaves nothing to need), and `lab32.so` carries 14 entries in *8-byte* records. What none
of them has is the entries a loader acts on - `DT_NEEDED`, `DT_SONAME`, `DT_RUNPATH` - because those
need a real shared object to link against, and none of them is long enough to run into the row cap
the other windows have.

So three files are built here, cross-compiling for Linux the way the earlier ELF fixtures did:

    clang --target=x86_64-unknown-linux-gnu -shared -nostdlib -fPIC -Wl,-soname,liblab.so …
    clang … -Wl,-soname,libuser.so -Wl,-rpath,/opt/lab/lib -Wl,--hash-style=both … liblab.so
    clang … -Wl,-soname,many.so -Wl,--no-as-needed … libst0.so libst1.so … (70 of them)

`--no-as-needed` matters: a linker that is allowed to drop a library nothing references writes a file
whose dynamic section quietly has no `DT_NEEDED` in it at all, and the fixture would then prove
nothing about the list the loader reads.

All commands run through `subprocess`, never a shell: Git Bash rewrites a `/opt/lab/lib` argument into
`C:/Program Files/Git/opt/lab/lib` and the linker then stores the mangled path in the binary with
perfect fidelity - which happened to the first draft of this fixture, and is why the probe compares the
string the *file* holds rather than the one the command line asked for.

Three readers have to agree before a probe is written:

    this file's walk                ->  PT_DYNAMIC's entries, and the strings they index into DT_STRTAB
    readelf -dW                     ->  binutils' listing
    llvm-readobj --dynamic-table    ->  LLVM's listing

There is no tag-to-name table in this script on purpose. A hand-copied `DT_*` table is exactly the kind
of remembered constant that turns out to be off by one (0x1C is `FINI_ARRAYSZ`, not `RUNPATH`), so the
name a row carries is the name *both* readers gave that tag in *this* file, and a tag they do not agree
on gets no name at all. The same rule earns the `word` column: `DT_PLTREL` holds a tag, and both readers
spell that tag's number out as `RELA` rather than printing `7`, so the row may carry the word too.

    temp/venv/Scripts/python.exe scripts/make-dynamic-fixtures.py
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
SCRATCH = os.path.join(ROOT, "temp", "dynamic-build")

PT_LOAD = 1
PT_DYNAMIC = 2
DT_STRTAB = 5
DT_STRSZ = 10
# Which tags hold an offset into DT_STRTAB rather than an address or a count - and only the three this
# lab has witnesses for, because the rest are the kind of remembered constant that turns out to be
# wrong: `DT_INIT` and `DT_FINI` are the first drafts of this list, and their values are addresses of
# functions, not string offsets. `DT_RPATH` is a string and is left out too, since no file here carries
# one, so nothing has agreed what its row should say.
STRING_TAGS = {1, 0x0E, 0x1D}
MAX_LISTED = 64
STUBS = 70

FIRST_C = "long lab_first(long a) { return a + 1; }\n"
SECOND_C = ("extern long lab_first(long);\n"
            "long use_it(long v) { return lab_first(v) * 2; }\n")


def run(cmd, note, work=None):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=work or SCRATCH, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:600]))
    return made


def write(name, text, work=None):
    with open(os.path.join(work or SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build():
    write("first.c", FIRST_C)
    write("second.c", SECOND_C)
    common = ["clang", "--target=x86_64-unknown-linux-gnu", "-shared", "-nostdlib", "-fPIC"]
    run(common + ["-Wl,-soname,liblab.so", "first.c", "-o", "liblab.so"], "clang liblab")
    run(common + ["-Wl,-soname,libuser.so", "-Wl,-rpath,/opt/lab/lib", "-Wl,--hash-style=both",
                  "second.c", "liblab.so", "-o", "libuser.so"], "clang libuser")
    stubs = []
    for index in range(STUBS):
        name = "libst%d.so" % index
        write("st%d.c" % index, "void stub_%d(void) { }\n" % index)
        run(common + ["-Wl,-soname,%s" % name, "st%d.c" % index, "-o", name], "clang " + name)
        stubs.append(name)
    run(common + ["-Wl,-soname,many.so", "second.c", "-Wl,--no-as-needed"] + stubs
        + ["-o", "many.so"], "clang many")


# -------------------------------------------------------------------------------------- the walk
def segments(raw):
    """(is64, [(type, offset, vaddr, filesz)]) from the program header table."""
    if raw[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    is64 = raw[4] == 2
    phoff = struct.unpack_from("<Q" if is64 else "<I", raw, 32 if is64 else 28)[0]
    phentsize, phnum = struct.unpack_from("<HH", raw, 54 if is64 else 42)
    out = []
    for index in range(phnum):
        at = phoff + index * phentsize
        if is64:
            p_type, _flags, p_offset, p_vaddr, _p_paddr, p_filesz, _memsz, _align = \
                struct.unpack_from("<IIQQQQQQ", raw, at)
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _memsz, _flags, _align = \
                struct.unpack_from("<IIIIIIII", raw, at)
        out.append((p_type, p_offset, p_vaddr, p_filesz))
    return is64, out


def load_to_offset(table):
    def where(vaddr):
        for p_type, p_offset, p_vaddr, p_filesz in table:
            if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None
    return where


def dynamic(raw):
    """(items, width, segment, is64) where items runs up to and including the terminating NULL."""
    is64, table = segments(raw)
    width = 16 if is64 else 8
    found = next((one for one in table if one[0] == PT_DYNAMIC), None)
    if found is None:
        return None
    _type, offset, vaddr, filesz = found
    items = []
    at = offset
    while at + width <= offset + filesz:
        tag, value = struct.unpack_from("<qQ" if is64 else "<iI", raw, at)
        items.append((tag & 0xFFFFFFFFFFFFFFFF, value))
        at += width
        if tag == 0:
            break
    return items, width, (offset, vaddr, filesz), is64


def texts(raw, items, where):
    """The string each string-valued entry points at, through DT_STRTAB."""
    strtab = next((value for tag, value in items if tag == DT_STRTAB), None)
    strsz = next((value for tag, value in items if tag == DT_STRSZ), None)
    base = None if strtab is None else where(strtab)
    if base is None:
        return {}
    limit = base + (strsz or 0)
    out = {}
    for tag, value in items:
        if tag not in STRING_TAGS:
            continue
        start = base + value
        end = raw.find(b"\0", start, min(limit, len(raw)))
        out[tag, value] = None if end < 0 else raw[start:end].decode("utf-8", "replace")
    return out


# -------------------------------------------------------------------------------- the two listings
def listing(cmd, path):
    made = subprocess.run(cmd + [path], capture_output=True, shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("%s refused %s" % (" ".join(cmd), path))
    out = []
    for line in made.stdout.decode("utf-8", "replace").splitlines():
        found = re.match(r"\s+0x([0-9A-Fa-f]+)[ \(]+([A-Z0-9_]+)[\)]*\s*(.*)$", line)
        if found:
            out.append((int(found.group(1), 16), found.group(2), found.group(3).strip()))
    return out


def stated(text):
    """`168 (bytes)` -> 168, `0x398` -> 904, `Shared library: [liblab.so]` -> the name inside brackets."""
    inside = re.search(r"\[([^\]]*)\]", text)
    if inside:
        return inside.group(1)
    direct = re.fullmatch(r"0x([0-9a-fA-F]+)", text)
    if direct:
        return int(direct.group(1), 16)
    count = re.fullmatch(r"(\d+) \((?:bytes|entries|libs)\)", text)
    if count:
        return int(count.group(1))
    bare = re.fullmatch(r"(\d+)", text)
    if bare:
        return int(bare.group(1))
    return text


def bracket(text):
    """`Shared library: [liblab.so]` -> `liblab.so`, and None for a value no reader put in brackets."""
    inside = re.search(r"\[([^\]]*)\]", text)
    return None if inside is None else inside.group(1)


def spelled(binutils, llvm):
    """The word both readers give a value, or None.

    Some values are not addresses and the readers say so in words rather than numbers: `DT_PLTREL` holds
    a tag, which this binutils and LLVM both print as `RELA`, and a size like `DT_STRSZ` prints as
    `69 (bytes)`. Either shape is read, so a bare word and a word in parentheses after a number both
    count, and they are compared case-insensitively. A value one reader prints as a plain number -
    `DT_RELACOUNT` is just `1` - gets no word, and neither does a disagreement.
    """
    def word(text):
        """`RELA` or `7 (Rela)` -> `RELA`; a number, a bracketed path, nothing -> None."""
        inside = re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+) \(([A-Za-z_]+)\)", text)
        if inside is not None:
            return inside.group(1).upper()
        bare = re.fullmatch(r"[A-Za-z_]+", text)
        return None if bare is None else text.upper()

    one, two = word(binutils), word(llvm)
    if one is None or two is None:
        return None
    if one != two:
        raise SystemExit("a value readelf spells %r LLVM spells %r" % (binutils, llvm))
    return one


def rows(items, width, segment, found, names, words):
    """Row 0 of totals, then one line per entry, in the file's own order."""
    head = "\t".join(["dynamic",
                      "entries\t%d" % len(items),
                      "width\t%d" % width,
                      "vaddr\t0x%x" % segment[1],
                      "off\t%d" % segment[0],
                      "filesz\t%d" % segment[2],
                      "strtab\t0x%x" % (found.get("strtab") or 0),
                      "strlen\t%d" % (found.get("strsz") or 0),
                      "needed\t%d" % sum(1 for one in items if one[0] == 1),
                      "text\t%d" % sum(1 for one in items if found.get(one) is not None)])
    out = [head]
    listed = items if len(items) <= MAX_LISTED else items[:MAX_LISTED]
    for index, (tag, value) in enumerate(listed):
        one = ["entry", str(index), "tag\t0x%x" % tag, "name\t%s" % (names.get((tag, value)) or "-"),
               "value\t0x%x" % value]
        word = words.get((tag, value))
        if word is not None:
            one.append("word\t%s" % word)
        text = found.get((tag, value))
        if text is not None:
            one.append("text\t%s" % "".join(" " if ch == "\t" or ord(ch) < 32 else ch for ch in text))
        out.append("\t".join(one))
    if len(items) > MAX_LISTED:
        out.append("cut\tentries\t%d\tlisted\t%d" % (len(items), MAX_LISTED))
    return out


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    build()
    probe = {}
    for name in ("liblab.so", "libuser.so", "many.so", "lab.so", "lab32.so", "labarm.so", "lab.elf"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        path = os.path.join(SCRATCH, name)
        raw = open(path, "rb").read()
        found = dynamic(raw)
        first = listing(["readelf", "-dW"], path)
        second = listing(["llvm-readobj", "--dynamic-table"], path)
        if found is None:
            if first or second:
                raise SystemExit("%s: no PT_DYNAMIC, yet readelf lists %d and llvm %d"
                                 % (name, len(first), len(second)))
            probe[name] = {"entries": 0, "width": None, "rows": [], "names": {}}
            print("%-11s no dynamic section, and both readers agree" % name)
            continue
        items, width, segment, is64 = found
        where = load_to_offset(segments(raw)[1])
        strings = texts(raw, items, where)
        if len(items) != len(first) or len(items) != len(second):
            raise SystemExit("%s: walk %d, readelf %d, llvm %d" % (name, len(items), len(first), len(second)))
        names, words = {}, {}
        for mine, one, two in zip(items, first, second):
            if mine[0] != one[0] or mine[0] != two[0]:
                raise SystemExit("%s: entry order differs: walk %#x, readelf %#x, llvm %#x"
                                 % (name, mine[0], one[0], two[0]))
            if one[1] != two[1]:
                raise SystemExit("%s: tag %#x is %r to readelf and %r to llvm" % (name, mine[0], one[1], two[1]))
            names[mine] = one[1]
            word = spelled(one[2], two[2])
            if word is not None:
                words[mine] = word
            stated_value = stated(one[2])
            if isinstance(stated_value, int) and stated_value != mine[1]:
                raise SystemExit("%s: tag %#x holds %r, readelf prints %r" % (name, mine[0], mine[1], stated_value))
            quoted, other = bracket(one[2]), bracket(two[2])
            if quoted != other:
                raise SystemExit("%s: tag %#x quotes %r to readelf and %r to llvm"
                                 % (name, mine[0], quoted, other))
            if quoted is not None:
                stored = strings.get(mine)
                if mine[0] not in STRING_TAGS or stored != quoted:
                    raise SystemExit("%s: tag %#x quotes %r, the walk through DT_STRTAB gives %r"
                                     % (name, mine[0], quoted, stored))
        needed = sum(1 for one in items if one[0] == 1)
        if name == "many.so" and needed != STUBS:
            raise SystemExit("many.so needs %d libraries, the file lists %d" % (STUBS, needed))
        if name != "many.so" and needed > 1:
            raise SystemExit("%s lists %d libraries, which no fixture was meant to" % (name, needed))
        extra = dict(strings)
        extra["strtab"] = next((value for tag, value in items if tag == DT_STRTAB), 0)
        extra["strsz"] = next((value for tag, value in items if tag == DT_STRSZ), 0)
        made = rows(items, width, segment, extra, names, words)
        probe[name] = {"entries": len(items), "width": width, "rows": made,
                       "bits": 64 if is64 else 32,
                       "tags": [{"tag": "%#x" % tag, "name": names[(tag, value)],
                                 "value": "0x%x" % value, "word": words.get((tag, value)),
                                 "text": strings.get((tag, value))}
                                for tag, value in items]}
        for row in made[:4] + made[-2:]:
            print("%-11s %s" % (name, row.replace("\t", " | ")))

    for name in ("liblab.so", "libuser.so", "many.so"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "dynamic.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, readelf and llvm-readobj agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
