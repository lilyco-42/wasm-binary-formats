"""Produce and check the ELF relocation-record fixtures - the fixups a loader or `ld.so` applies.

The other half of `scripts/make-reloc-fixtures.py`: that script reads a PE's base-relocation directory,
this one reads an ELF's dynamic relocation records. Both are the same IDA question - which addresses does
the file say get rewritten - asked of a format whose answer lives in sections rather than in a directory.

Two classes, because the record is a different shape in each and the numbers mean different words:

    x86-64  .rela.dyn/.rela.plt   24-byte? no: 16-byte slots, info = sym<<32 | type, addend inline
    i386    .rel.dyn/.rel.plt      8-byte slots, info = sym<<8 | type, addend implicit

Both shared objects are written here with `clang --target=… -shared -nostdlib -fPIC`, and every row is
read back twice by readers that are not this repo's:

    readelf -rW   00000000000036b8  0000000500000001 R_X86_64_64  00000000000036b0 table + 4
    objdump -R    00000000000036b8 R_X86_64_64       table+0x0000000000000004

The script refuses to write a probe unless the two agree on every offset, type number, symbol and
addend, and unless each type number it names in a row was paired with that name by both of them in that
file. A number no fixture pairs - `R_X86_64_TPOFF64` and the rest of either table - stays a number.

    temp/venv/Scripts/python.exe scripts/make-elf-reloc-fixtures.py
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

SOURCE = """\
/* A shared object needs three kinds of fixup to be loadable at all: a pointer to something the loader
   may place anywhere (GLOB_DAT), a call that goes through the PLT (JUMP_SLOT), and a data word that
   holds an address computed out of another one (R_X86_64_64 / R_386_32 with an addend, and the
   symbol-less RELATIVE that says "write base plus this"). `pointer` and `offsets` exist to earn the
   last two, which a plain function-only object never emits. */

extern int data_at;
extern int call_me(int);
int local_static;
static int local_ro = 7;
int table[2] = { 1, 2 };
long *pointer = (long *)&table[1];
long offsets[2] = { (long)8, (long)&local_ro };

int use_data(void) {
    return data_at + local_static + local_ro + table[0] + (int)*pointer;
}

int forward(int n) {
    return call_me(n) + use_data() + (int)offsets[0];
}
"""

CASES = [
    ("lab.so", "x86_64-unknown-linux-gnu", 64, "x86_64", "X86-64"),
    ("lab32.so", "i686-unknown-linux-gnu", 32, "i386", "80386"),
    ("labarm.so", "aarch64-unknown-linux-gnu", 64, "aarch64", "AArch64"),
]


def run(cmd):
    out = subprocess.run(cmd, capture_output=True, shell=False, timeout=600, cwd=ROOT)
    if out.returncode != 0:
        raise SystemExit("%s failed: %s" % (" ".join(cmd), out.stderr.decode("utf-8", "replace")[:400]))
    return out.stdout.decode("utf-8", "replace")


def build(target, name, want):
    """Compile one shared object; the linker decides which fixups exist, this script only asks."""
    work = os.path.join(ROOT, "temp", "elflab")
    os.makedirs(work, exist_ok=True)
    src = os.path.join(work, "so.c")
    with open(src, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(SOURCE)
    out = os.path.join(work, name)
    run(["clang", "--target=" + target, "-shared", "-nostdlib", "-fPIC", "-o", out, src])
    header = run(["readelf", "-h", out])
    if want not in header:
        raise SystemExit("%s: readelf -h does not say %s, so the triple did not build what was asked" % (name, want))
    blob = open(out, "rb").read()
    with open(os.path.join(FIX, name), "wb") as handle:
        handle.write(blob)
    return blob


def sections(name):
    """(address, size, name) for every section header, as readelf -SW lists them.

    The bracket and its number split into two fields, which is why the line is matched rather than
    split: reading column three as the address names the *type* as an address and every lookup below
    then answers "unmapped" with a straight face.
    """
    found = []
    for line in run(["readelf", "-SW", os.path.join(FIX, name)]).splitlines():
        head = re.match(r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if not head or not head.group(1).startswith("."):
            continue
        found.append((int(head.group(2), 16), int(head.group(4), 16), head.group(1)))
    return found


def owner(table, where):
    """The tightest section whose address range holds `where`.

    `.relro_padding` is NOBITS and spans everything the dynamic linker may write, so it covers a `.got`
    slot too - taking the first section that matches would name the padding for all of them. The
    smallest covering range is the one the file itself uses to describe those bytes.
    """
    best = None
    for addr, size, label in table:
        if size == 0 or not (addr <= where < addr + size):
            continue
        if best is None or size < best[1]:
            best = (addr, size, label)
    return best[2] if best else "unmapped"


def from_readelf(name):
    """readelf -rW, parsed section by section: (table, offset, type number, type name, symbol, addend)."""
    rows = []
    table = None
    text = run(["readelf", "-rW", os.path.join(FIX, name)])
    for line in text.splitlines():
        head = re.match(r"^Relocation section '([^']+)' at offset 0x[0-9a-f]+ contains (\d+) entries", line)
        if head:
            table = head.group(1)
            continue
        cell = line.split()
        # A REL record for a symbol-less entry ends after the type name, so the row can be three cells
        # long; requiring a fourth is what readelf's own padding, not the format, decides.
        if not table or len(cell) < 3 or not re.fullmatch(r"[0-9a-f]{8,16}", cell[0]):
            continue
        where = int(cell[0], 16)
        info = int(cell[1], 16)
        kind = cell[2]
        rest = " ".join(cell[3:])
        if table.startswith(".rela"):
            # `Symbol's Value  Symbol's Name + Addend`. A symbol-less record drops the value and the `+`
            # and leaves the addend alone in the row, so the no-plus branch reads a number rather than
            # reporting an addend of zero - which is the difference between a RELATIVE and nothing.
            tail = re.search(r"\+\s*([0-9a-f]+)$", rest)
            body = rest[: tail.start()].split() if tail else rest.split()
            addend = int(tail.group(1), 16) if tail else (
                int(body[-1], 16) if body and re.fullmatch(r"[0-9a-f]+", body[-1]) else 0)
            named = [one for one in body if re.fullmatch(r"[A-Za-z_][\w.$]*", one)]
            sym = named[-1] if named else ""
        else:
            # A REL record states no addend at all; the last column is the name, which may be empty.
            addend = None
            body = rest.split()
            sym = body[-1] if body and re.fullmatch(r"[A-Za-z_.$][\w.$]*", body[-1]) else ""
        rows.append((table, where, kind, sym, addend, info))
    return rows


def from_objdump(name):
    """objdump -R: `OFFSET TYPE VALUE`, where VALUE is `sym`, `sym+0x4` or `*ABS*+0x36c0`."""
    rows = []
    for line in run(["objdump", "-R", os.path.join(FIX, name)]).splitlines():
        cell = line.split()
        if len(cell) < 2 or not re.fullmatch(r"[0-9a-f]{8,16}", cell[0]):
            continue
        where = int(cell[0], 16)
        kind = cell[1]
        value = " ".join(cell[2:])
        addend = None
        sym = value
        if "+" in value:
            sym, tail = value.rsplit("+", 1)
            addend = int(tail, 16)
        rows.append((where, kind, sym.strip() or "*ABS*", addend))
    return rows


def from_llvm(name):
    """`llvm-readobj --relocs`: `0x306E8 R_AARCH64_RELATIVE - 0x306D8`, grouped by section.

    LLVM's own reader is the second one that knows the AArch64 table, and it is what makes those type
    names claimable: binutils splits across two programs here, and `readelf` names them while `objdump`
    prints `UNKNOWN`. Two readers that spell a word the same way is the rule; which two is a fact about
    the toolchain, not something to widen the rule for.
    """
    rows = {}
    table = None
    for line in run(["llvm-readobj", "--relocs", os.path.join(FIX, name)]).splitlines():
        head = re.match(r"^\s+Section \(\d+\) (\S+) \{", line)
        if head:
            table = head.group(1)
            continue
        # A REL record ends after the symbol - LLVM has no addend to print for it either - so the fourth
        # column is optional and its absence is zero, not a missing field.
        one = re.match(r"^\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(?:\s+(0x[0-9a-fA-F]+))?\s*$", line)
        if not one or table is None:
            continue
        symbol = one.group(3)
        # LLVM writes `-` where a record names no symbol; the other two write nothing or `*ABS*`.
        if symbol == "-":
            symbol = "*ABS*"
        rows[int(one.group(1), 16)] = (table, one.group(2), symbol,
                                       int(one.group(4), 16) if one.group(4) else 0)
    return rows


def numbers(records, wide):
    """The symbol index and type number inside an `info` word, at the width this class uses."""
    return [(one[5] >> (32 if wide else 8), one[5] & (0xFFFFFFFF if wide else 0xFF)) for one in records]


def rows_for(name, bits, machine, table_map, paired, single):
    """Rows the Rust reader has to print, assembled from what the two readers said.

    readelf is the source of the printed values and objdump is the check on every one of them. A type
    number is *named* only where both wrote the same word beside it: binutils' `objdump -R` knows the
    x86 spellings and prints `UNKNOWN` for every AArch64 one, so an aarch64 file contributes offsets,
    symbols and addends that both readers agree on and no names at all - which is exactly what the rows
    below say, and the reason the name table is keyed on machine and number together.
    """
    wide = bits == 64
    records = from_readelf(name)
    other = {one[0]: one for one in from_objdump(name)}
    llvm = from_llvm(name)
    for label, found in (("objdump", other), ("llvm-readobj", llvm)):
        if len(records) != len(found):
            raise SystemExit("%s: readelf lists %d records, %s %d"
                             % (name, len(records), label, len(found)))
    tables = []
    fixes = []
    for table, where, kind, sym, addend, info in records:
        one = other.get(where)
        if one is None:
            raise SystemExit("%s: 0x%x is in readelf and not in objdump" % (name, where))
        spelled = sym or "*ABS*"
        if one[2] not in (spelled, "*ABS*"):
            raise SystemExit("%s: 0x%x names %s for one and %s for the other"
                             % (name, where, spelled, one[2]))
        if (addend or 0) != (one[3] or 0):
            raise SystemExit("%s: 0x%x has addend %s for one and %s for the other"
                             % (name, where, addend, one[3]))
        symbol = info >> (32 if wide else 8)
        number = info & (0xFFFFFFFF if wide else 0xFF)
        key = (machine, number)
        # `objdump -R` has no AArch64 table and prints UNKNOWN; readelf and llvm-readobj do. A number is
        # named only once two readers have spelled it identically, so the abstention is recorded and the
        # agreement is what earns the word.
        agree = [one[1], llvm[where][1]]
        if any(word != kind for word in agree if word != "UNKNOWN"):
            raise SystemExit("%s: 0x%x is %s to readelf, %s and %s to the others"
                             % (name, where, kind, agree[0], agree[1]))
        # Count readers, not distinct spellings: readelf is one, and each other program that wrote the
        # same word for the same record is another. Three is the same claim as two, and one is none.
        witnesses = 1 + len([word for word in agree if word == kind])
        if witnesses < 2:
            single[key] = kind
        elif key not in paired:
            paired[key] = kind
        elif paired[key] != kind:
            raise SystemExit("%s: type %d is named %s and %s in one file"
                             % (name, number, kind, paired[key]))
        if llvm[where][0] != table:
            raise SystemExit("%s: 0x%x sits in %s for one reader and %s for another"
                             % (name, where, table, llvm[where][0]))
        if llvm[where][3] != (addend or 0):
            raise SystemExit("%s: 0x%x addend is %s for readelf and %s for llvm-readobj"
                             % (name, where, addend, llvm[where][3]))
        if llvm[where][2] not in (spelled, "*ABS*"):
            raise SystemExit("%s: 0x%x names %s for llvm-readobj and %s for readelf"
                             % (name, where, llvm[where][2], spelled))
        if table not in tables:
            tables.append(table)
        fixes.append((table, where, number, symbol, spelled, addend))
    lines = []
    for table, where, number, symbol, spelled, addend in fixes:
        lines.append("fixup	0x%x	type	%d	name	%s	sym	%s	addend	%s	section	%s"
                     % (where, number, paired.get((machine, number), "-"),
                        "-" if symbol == 0 else spelled,
                        "-" if addend is None else addend, owner(table_map, where)))
    step = 8 if wide else 4
    listed = []
    for table in tables:
        addend = table.startswith(".rela")
        listed.append("table	%s	entries	%d	slot_bytes	%d	addend	%s"
                      % (table, len([one for one in fixes if one[0] == table]),
                         step * (3 if addend else 2), "yes" if addend else "no"))
    relative = len([one for one in lines if "	sym	-	" in one])
    header = ("relocs	kind	dyn	tables	%d	entries	%d	symbolic	%d	relative	%d	machine	%s	bits	%d"
              % (len(tables), len(fixes), len(fixes) - relative, relative, machine, bits))
    return [header] + listed + lines, fixes


def main():
    files = {}
    paired = {}
    single = {}
    for name, target, bits, machine, want in CASES:
        blob = build(target, name, want)
        table_map = sections(name)
        rows, records = rows_for(name, bits, machine, table_map, paired, single)
        files[name] = {"bytes": len(blob), "bits": bits, "records": len(records), "rows": rows}
        if len(records) < 7:
            raise SystemExit("%s: only %d records, so the table cases are thin" % (name, len(records)))
    for machine, numbers in (("x86_64", (1, 6, 7, 8)), ("i386", (1, 6, 7, 8))):
        for number in numbers:
            if (machine, number) not in paired:
                raise SystemExit("%s: type %d never appears, so its name is not earned"
                                 % (machine, number))
    for number in (257, 1025, 1026, 1027):
        if ("aarch64", number) not in paired:
            raise SystemExit("aarch64 type %d was not named by two readers, so it stays a number"
                             % number)
    for (machine, number), kind in sorted(paired.items()):
        print("paired   %-9s %4d %s" % (machine, number, kind))
    for (machine, number), kind in sorted(single.items()):
        print("unnamed  %-9s %4d %s" % (machine, number, kind))
    with open(os.path.join(FIX, "elfreloc.probe.json"), "w", encoding="utf-8") as handle:
        json.dump({"type_names": {"%s:%d" % key: value for key, value in sorted(paired.items())},
                   "readelf_only": {"%s:%d" % key: value for key, value in sorted(single.items())},
                   "files": files}, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print(json.dumps({one: len(two["rows"]) for one, two in files.items()}))


if __name__ == "__main__":
    sys.exit(main())
