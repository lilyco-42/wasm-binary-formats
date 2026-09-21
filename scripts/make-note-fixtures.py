"""Produce and check the ELF note fixtures.

A note is three words and two payloads: `namesz`, `descsz`, `type`, then the owner's name and the
descriptor, each rounded up to a multiple of four. Everything an analyser can say about a note - that
this file wants a non-executable stack, that it was built with IBT and SHSTK, which build ID a debugger
matches it against - is inside that pair of payloads, and the padding between them is where a reader that
only knows the aligned form of the notes it has seen before goes wrong.

Four produced files, all from `clang` driving `ld.lld` for a Linux target, plus three borrowed negatives:

    -fcf-protection=full  + -Wl,--build-id=sha1  ->  note.elf      (two PT_NOTE segments)
    -fcf-protection=branch                      ->  note1.elf     (property only, no build ID)
    -fcf-protection=branch, not linked           ->  note.o       (no program headers at all)
    a .note written by hand in assembly          ->  notelab.elf  (two notes inside one section)
    lab.elf, res.dll, answer.obj                                  (nothing to read here)

The last of the four is the one that keeps the window honest. `llvm-readobj --notes` prints nothing for a
note whose owner it does not know, while `readelf -nW` prints it and a hex dump of its bytes - so the
readers do not agree, no word is claimed for such a note, and its descriptor is never quoted. What is
checked against `readelf` there is the three numbers per note and, because two of them have to tile a
section of a stated length, the rounding itself: read the name length wrong and the second note is not
where its owner says it is.

Three readings have to agree before a row is written:

    this file's walk   ->  every note in every PT_NOTE segment, or in the .note* sections when there
                           are no program headers to consult, which is what an object file gives
    readelf -nW        ->  owner, data size, the type word, the build ID, the property spelling
    llvm-readobj --notes ->  the same, section by section

The property note's descriptor is itself a chain - `prtype`, `prdatasz`, then `prdatasz` bytes, each
rounded to four - so the rows carry those numbers per entry and one aggregated word per note, which is
the only form either listing has: both spell `x86 feature: IBT, SHSTK` for the same bytes and neither
says anything per entry.
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
SCRATCH = os.path.join(ROOT, "temp", "note-build")

MAX_LISTED = 64
PT_NOTE = 4
GNU = b"GNU\0"
NT_GNU_BUILD_ID = 3
NT_GNU_PROPERTY_TYPE_0 = 5
PROPERTY_TYPE_0 = "NT_GNU_PROPERTY_TYPE_0"
BUILD_ID_TYPE = "NT_GNU_BUILD_ID"

SOURCE = "void _start (void) {}\n"

# Two notes in one section, written by hand because no toolchain here makes an owner whose length needs
# rounding: the first descriptor is five bytes, so the second note begins eight bytes past where it is
# declared rather than five. `readelf` names both owners and both sizes; `llvm-readobj` says nothing about
# either, which is the point of keeping them. The section is 44 bytes, which is also what 24 + 20 comes to
# - so a walk that rounded anything wrongly runs past it or stops short, and the length catches that.
LABORATORY = """__asm__(".section .note.lab,\\"a\\"\\n"
        ".p2align 2\\n"
        ".long 4\\n"
        ".long 5\\n"
        ".long 0x1234\\n"
        ".asciz \\"LAB\\"\\n"
        ".ascii \\"ABCDE\\"\\n"
        ".p2align 2\\n"
        ".long 2\\n"
        ".long 4\\n"
        ".long 0x7\\n"
        ".ascii \\"Q\\"\\n"
        ".p2align 2\\n"
        ".asciz \\"xyz\\"\\n");
""" + SOURCE

CLANG = ["clang", "--target=x86_64-unknown-linux-gnu"]


def run(cmd, note):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=SCRATCH, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:700]))
    return made


def build():
    write("s.c", SOURCE)
    write("lab.c", LABORATORY)
    run(CLANG + ["-fcf-protection=full", "-c", "s.c", "-o", "full.o"], "clang full.o")
    run(CLANG + ["-fcf-protection=branch", "-c", "s.c", "-o", "branch.o"], "clang branch.o")
    run(CLANG + ["-fcf-protection=branch", "-c", "lab.c", "-o", "lab.o"], "clang lab.o")
    run(CLANG + ["-nostdlib", "-Wl,--build-id=sha1", "full.o", "-o", "note.elf"], "lld note.elf")
    run(CLANG + ["-nostdlib", "branch.o", "-o", "note1.elf"], "lld note1.elf")
    run(CLANG + ["-nostdlib", "lab.o", "-o", "notelab.elf"], "lld notelab.elf")
    # The object keeps its note and gains no program header, which is the other half of the walk.
    shutil.copyfile(os.path.join(SCRATCH, "branch.o"), os.path.join(SCRATCH, "note.o"))


def write(name, text):
    with open(os.path.join(SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def rounded(length):
    return length + ((-length) % 4)


# ------------------------------------------------------------------------------------- the file's own walk
def notes_in(body, at, limit):
    """Every note in `body[at:at+limit]`, or [] the moment one stops making sense."""
    found = []
    where = at
    while where + 12 <= at + limit:
        namesz, descsz, kind = struct.unpack_from("<III", body, where)
        head = where + 12
        name_end = head + rounded(namesz)
        end = name_end + rounded(descsz)
        if end > at + limit:
            return found, "runs past the %d bytes it is given" % limit
        owner = body[head:head + namesz].split(b"\0")[0].decode("utf-8", "replace")
        found.append({"off": head - 12, "bytes": end - (head - 12), "namesz": namesz, "descsz": descsz,
                      "type": kind, "owner": owner, "desc": body[name_end:name_end + descsz]})
        where = end
    if where != at + limit:
        return found, "stops at %d of %d bytes" % (where - at, limit)
    return found, ""


def segments(body):
    """(bits, [(offset, size), ...]) for every PT_NOTE program header, [] when there are none."""
    if body[:4] != b"\x7fELF":
        return None
    bits = 32 if body[4] == 1 else 64
    little = body[5] == 1
    def word(at, width):
        raw = body[at:at + width]
        return int.from_bytes(raw, "little" if little else "big") if len(raw) == width else None
    if bits == 64:
        phoff, phentsize, phnum = word(32, 8), word(54, 2), word(56, 2)
    else:
        phoff, phentsize, phnum = word(28, 4), word(42, 2), word(44, 2)
    found = []
    for each in range(phnum or 0):
        base = phoff + each * phentsize
        if base + phentsize > len(body):
            break
        if word(base, 4) == PT_NOTE:
            # p_offset is at 8 in an ELF64 program header and p_filesz at 32; in ELF32 they sit at 4 and
            # 16. Reading the pair at the wrong offsets is the mistake this file exists to not make twice.
            span = (word(base + 8, 8), word(base + 32, 8)) if bits == 64 else (word(base + 4, 4), word(base + 16, 4))
            found.append(span)
    return bits, found


def sections(body):
    """[(name, offset, size)] for every section whose name says note, plus the file's own width."""
    if body[:4] != b"\x7fELF":
        return None
    bits = 32 if body[4] == 1 else 64
    little = body[5] == 1
    def word(at, width):
        raw = body[at:at + width]
        return int.from_bytes(raw, "little" if little else "big") if len(raw) == width else None
    if bits == 64:
        shoff, shentsize, shnum, shstrndx = word(40, 8), word(58, 2), word(60, 2), word(62, 2)
    else:
        shoff, shentsize, shnum, shstrndx = word(32, 4), word(46, 2), word(48, 2), word(50, 2)
    table = []
    for each in range(shnum or 0):
        base = shoff + each * shentsize
        if base + shentsize > len(body):
            break
        name_at, kind, off, size = word(base, 4), word(base + 4, 4), word(base + 24, bits // 8), word(base + 32, bits // 8)
        table.append((name_at, kind, off, size))
    strings_at = shoff + shstrndx * shentsize
    try:
        str_off = table[shstrndx][2]
    except IndexError:
        return bits, []
    strings = body[str_off:]
    found = []
    for name_at, _kind, off, size in table:
        raw = strings[name_at:strings.find(b"\0", name_at)]
        label = raw.decode("utf-8", "replace")
        if label.startswith(".note"):
            found.append((label, off, size))
    return bits, found


def walk(body):
    """(bits, where, rows-in-file-order) - segments when a file has them, sections when it has not."""
    wide = segments(body)
    if wide is None:
        return None
    bits, places = wide
    if places:
        entries, problems = [], []
        for offset, size in places:
            found, why = notes_in(body, offset, size)
            problems.append(why)
            for one in found:
                one["kind"], one["place"] = "segment", "PT_NOTE"
            entries += found
        return bits, "segment", entries, [one for one in problems if one]
    bits, table = sections(body)
    entries, problems = [], []
    for label, offset, size in table:
        found, why = notes_in(body, offset, size)
        problems.append(why)
        for one in found:
            one["kind"], one["place"] = "section", label
        entries += found
    return bits, "section", entries, [one for one in problems if one]


# ----------------------------------------------------------------------------------- the two listings
def shell(args):
    made = subprocess.run(args, capture_output=True, shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("%s refused: %s" % (args[0], (made.stdout + made.stderr).decode("utf-8", "replace")[:400]))
    return made.stdout.decode("utf-8", "replace")


def spelled(text):
    """One form for both printings of a decoded note. The two differ in how many spaces they put after a
    comma and in how they group a run of hex bytes, which is their formatting and not a statement about
    the bytes."""
    return re.sub(r"\s+", " ", text).strip()


def hexed(text):
    """A printer's run of hex bytes, as the bytes themselves."""
    return re.sub(r"[^0-9a-fA-F]", "", text).lower()


def readelf(path):
    """{(owner, descsz): type word, decoded text} as binutils lists it."""
    out = {}
    for line in shell(["readelf", "-nW", path]).splitlines():
        found = re.match(r"\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(.*?)\s*$", line)
        if not found or found.group(1) in ("Owner", "Displaying"):
            continue
        rest = found.group(3)
        kind = rest.split("\t")[0].split(" ")[0]
        words = re.findall(r"Build ID: ([0-9a-f]+)|(x86 feature: [A-Z, ]+)|(description data: ([0-9a-f ]+))", rest)
        text = next((one[0] or one[1] or one[3] for one in words if any(one)), "")
        out[(found.group(1), int(found.group(2), 16))] = {
            "type": kind, "text": hexed(text) if kind == "Unknown" else spelled(text)}
    return out


def llvm(path):
    """The same shape from LLVM's printer, so the two are compared rather than merged."""
    text = shell(["llvm-readobj", "--notes", path])
    out = {}
    for block in re.findall(r"\n      \{(.*?)\n      \}", text, re.S):
        owner = re.search(r"Owner: (\S+)", block)
        size = re.search(r"Data size: (0x[0-9a-fA-F]+)", block)
        kind = re.search(r"Type: (\S+)", block)
        build = re.search(r"Build ID: ([0-9a-f]+)", block)
        props = re.search(r"x86 feature: ([A-Z, ]+)", block)
        raw = re.findall(r"^\s*[0-9a-fA-F]{4}: ((?:[0-9a-fA-F]{1,8} ?)+)\s*\|", block, re.M)
        named = kind.group(1) if kind else "?"
        if build:
            body = build.group(1)
        elif props:
            body = "x86 feature: " + props.group(1)
        elif raw and named == "Unknown":
            # Only the hex columns of LLVM's dump - the line's own offset and its ASCII gutter are that
            # printer's layout, and reading them as data is how a byte string gains bytes it never had.
            body = "".join(raw)
        else:
            body = ""
        if owner and size:
            out[(owner.group(1), int(size.group(1), 16))] = {
                "type": named, "text": hexed(body) if named == "Unknown" else spelled(body)}
    return out


# --------------------------------------------------------------------------------------------- the rows
def property_entries(desc):
    out, where, limit = [], 0, len(desc)
    while where + 8 <= limit:
        kind, size = struct.unpack_from("<II", desc, where)
        body = desc[where + 8:where + 8 + size]
        out.append({"type": kind, "bytes": size, "value": int.from_bytes(body[:4], "little") if size == 4 else None})
        where += 8 + rounded(size)
    return out


def rows(name, found, listing):
    bits, where, entries, problems = found
    if not entries:
        return []
    out = []
    head = ["notes", "entries\t%d" % len(entries), "bits\t%d" % bits, "walked\t%s" % where]
    if problems:
        head.append("why\t%s" % "; ".join(problems))
    out.append("\t".join(head))
    for index, one in enumerate(entries[:MAX_LISTED]):
        seen = listing.get((one["owner"], one["descsz"]), {})
        word = seen.get("type", "-")
        text = seen.get("text", "")
        row = ["note", str(index), "kind\t%s" % one["kind"], "place\t%s" % one["place"],
               "namesz\t%d" % one["namesz"], "descsz\t%d" % one["descsz"],
               "type\t0x%x" % one["type"], "owner\t%s" % one["owner"]]
        if word and word != "-":
            row.append("word\t%s" % word)
        if text:
            row.append("text\t%s" % text)
        out.append("\t".join(row))
        if one["type"] == NT_GNU_PROPERTY_TYPE_0 and one["owner"] == "GNU":
            for each, prop in enumerate(property_entries(one["desc"])):
                out.append("\t".join(["prop", str(index), str(each),
                                      "type\t0x%x" % prop["type"], "bytes\t%d" % prop["bytes"],
                                      "value\t%s" % ("-" if prop["value"] is None else "0x%x" % prop["value"])]))
    if len(entries) > MAX_LISTED:
        out.append("cut\tnotes\t%d\tlisted\t%d" % (len(entries), MAX_LISTED))
    return out


# --------------------------------------------------------------------------------------- the agreements
def check(name, found, first, second):
    bits, where, entries, problems = found
    if not entries:
        if first or second:
            raise SystemExit("%s: the walk finds no note, readelf %r, llvm %r" % (name, list(first), list(second)))
        return
    if problems:
        raise SystemExit("%s: %s" % (name, "; ".join(problems)))
    for label, listing in ("readelf", first), ("llvm-readobj", second):
        if len(listing) != len(entries):
            raise SystemExit("%s: the walk counts %d notes, %s %d" % (name, len(entries), label, len(listing)))
    for one in entries:
        key = (one["owner"], one["descsz"])
        mine = first.get(key)
        if mine is None:
            raise SystemExit("%s: readelf says nothing about %s with a %d-byte descriptor"
                             % (name, one["owner"], one["descsz"]))
        other = second.get(key)
        if other is None:
            raise SystemExit("%s: llvm-readobj says nothing about %s with a %d-byte descriptor"
                             % (name, one["owner"], one["descsz"]))
        if other != mine:
            raise SystemExit("%s: %s reads as %r to binutils and %r to LLVM" % (name, key, mine, other))
        # The type word both print is the number in the file, so it has to be that number.
        stated = re.search(r"\(0x([0-9a-f]+)\)", mine["type"])
        if stated and int(stated.group(1), 16) != one["type"]:
            raise SystemExit("%s: %s prints a type word for %#x, the file says %#x"
                             % (name, key, int(stated.group(1), 16), one["type"]))


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    build()
    probe = {}
    for name in ("note.elf", "note1.elf", "notelab.elf", "note.o", "lab.elf", "res.dll", "answer.obj"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        path = os.path.join(SCRATCH, name)
        body = open(path, "rb").read()
        found = walk(body)
        if found is None:
            probe[name] = {"notes": False, "entries": 0, "rows": []}
            print("%-12s not an ELF file, so no notes to read" % name)
            continue
        listing = readelf(path)
        check(name, found, listing, llvm(path) if name != "answer.obj" else {})
        made = rows(name, found, listing)
        probe[name] = {"notes": bool(made), "entries": len(found[2]), "rows": made}
        print("%-12s %d notes, walked by %s" % (name, len(found[2]), found[1]))
        for row in made:
            print("%-12s %s" % ("", row.replace("\t", " | ")))
    for name in ("note.elf", "note1.elf", "notelab.elf", "note.o"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "note.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, readelf and llvm-readobj agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
