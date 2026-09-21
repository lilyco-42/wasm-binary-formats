"""Produce and check the ELF symbol-hash fixtures.

A dynamic object finds a name without scanning `.dynsym`: it hashes the name, tests a bloom filter, walks
one bucket's chain, and compares the hash words it stored there. Two shapes do this job - the old SHT_HASH
and the `.gnu.hash` that became the default - and what an analyser can say about them is not decoration:
`.gnu.hash` deliberately leaves out the symbols before its `symoffset`, and a symbol it leaves out cannot
be found by name at all, which is the difference between "this file exports it" and "another file can ask
for it".

Four produced files, all from `clang` driving `ld.lld` for a Linux target, from one 90-function source so
the two shapes can be compared over an identical symbol set:

    -shared -nostdlib                      ->  hgnu.so     (.gnu.hash, 22 buckets, 32 mask words)
    -shared -nostdlib --hash-style=sysv    ->  hsys.so     (.hash, 92 buckets, 92 chains)
    -shared -nostdlib --hash-style=both    ->  hboth.so    (both tables in one file)
    the same for i386                      ->  hboth32.so  (and 64 mask words, because words are wider)

Six borrowed ones cover the rest: `lab.so`, whose `symoffset` is 3 and so has two named dynamic symbols
the hash cannot reach; `libuser.so`, the small both-tables case; `note.elf`, a position-independent
executable; and `lab.elf`, `res.dll`, `answer.obj` as three different reasons to answer with nothing.

Three readings have to agree before the probe is written:

    this file's walk               ->  the header words, both arrays, and what a chain walk reaches
    llvm-readobj --gnu-hash-table  ->  and --hash-table for the old shape; LLVM prints Buckets and Values,
                                       so the chain count is the length of its list rather than a word
    pyelftools                     ->  its own params, and - the part worth having - its `get_symbol(name)`,
                                       which performs the real lookup: hash, mask, bucket, chain, strcmp

The last one is behavioural rather than textual. Ask it for every named symbol and it resolves all of them
and nothing below `symoffset`, and it returns nothing at all for a name the file never had, which is the
control that says the successes mean something.

What the two shapes mean by the same column differs, and the rows keep it that way: a `.hash` bucket holds
an index into `.dynsym`, terminated by a zero chain word, while a `.gnu.hash` bucket holds an index into
its own chain array - every entry of that array carries the symbol's hash with bit 31 marking the last one
in its chain. The `kind` column is what tells the two apart; nothing is normalised between them.

`llvm-readobj --hash-symbols`, which sounds like the ideal witness, prints an empty listing for every file
here, so it is not used. And `pyelftools.gnu_hash(name)` is not treated as an oracle either: on `lab.so` it
disagrees in bit 0 with the word the file itself stores for three of six names while its own lookups still
succeed, so no row carries a per-symbol hash until two readers print the same one.
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
SCRATCH = os.path.join(ROOT, "temp", "hash-build")

MAX_LISTED = 64
GNU_SECTION = ".gnu.hash"
SYSV_SECTION = ".hash"

CLANG = ["clang"]
TARGETS = {"x86_64": "x86_64-unknown-linux-gnu", "i386": "i386-unknown-linux-gnu"}
SYMBOLS = 90


def source():
    """Ninety globals and two file-scope ints: the second group is not dynamic at all."""
    lines = ["int lab_sym_%03d(void) { return %d; }" % (one, one) for one in range(SYMBOLS)]
    lines.append("static int hidden_one; static int hidden_two;")
    lines.append("int *use_hidden (void) { return &hidden_one; }")
    return "\n".join(lines) + "\n"


def run(cmd, note):
    made = subprocess.run(cmd, capture_output=True, shell=False, cwd=SCRATCH, timeout=900)
    if made.returncode != 0:
        raise SystemExit("%s failed: %s" % (note, (made.stdout + made.stderr).decode("utf-8", "replace")[:700]))
    return made


def build():
    write("syms.c", source())
    for bits, name in (("x86_64", "s.o"), ("i386", "s32.o")):
        run(CLANG + ["--target=" + TARGETS[bits], "-fPIC", "-c", "syms.c", "-o", name], "clang " + name)
    shared = CLANG + ["--target=" + TARGETS["x86_64"], "-shared", "-nostdlib"]
    run(shared + ["s.o", "-o", "hgnu.so"], "ld hgnu.so")
    run(shared + ["-Wl,--hash-style=sysv", "s.o", "-o", "hsys.so"], "ld hsys.so")
    run(shared + ["-Wl,--hash-style=both", "s.o", "-o", "hboth.so"], "ld hboth.so")
    run(CLANG + ["--target=" + TARGETS["i386"], "-shared", "-nostdlib", "-Wl,--hash-style=both",
                 "s32.o", "-o", "hboth32.so"], "ld hboth32.so")


def write(name, text):
    with open(os.path.join(SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


# ------------------------------------------------------------------------------- the file's own walk
def elf(raw):
    """(bits, little, sections, string table) for an ELF file, or None."""
    if raw[:4] != b"\x7fELF":
        return None
    bits = 32 if raw[4] == 1 else 64
    little = raw[5] == 1
    wide = bits == 64

    def word(at, size):
        stop = at + size
        return None if stop > len(raw) else int.from_bytes(raw[at:stop], "little" if little else "big")

    header = word(0x28 if wide else 0x20, 8 if wide else 4)
    entsize = word(0x3a if wide else 0x2e, 2)
    count = word(0x3c if wide else 0x30, 2)
    link = word(0x3e if wide else 0x32, 2)
    if None in (header, entsize, count, link) or entsize < (64 if wide else 40):
        return None
    table = []
    for each in range(count):
        at = header + each * entsize
        name_at, kind = word(at, 4), word(at + 4, 4)
        off = word(at + (0x18 if wide else 0x10), 8 if wide else 4)
        size = word(at + (0x20 if wide else 0x14), 8 if wide else 4)
        info = word(at + (0x2c if wide else 0x1c), 4)
        if None in (name_at, kind, off, size):
            break
        table.append({"name_at": name_at, "kind": kind, "off": off, "size": size, "info": info or 0})
    strings = table[link]["off"] if link < len(table) else None
    if strings is None:
        return None
    for one in table:
        tail = raw[strings + one["name_at"]:]
        one["name"] = tail.split(b"\0")[0].decode("utf-8", "replace")
    return bits, little, table, strings


def words_at(raw, at, count, little, size=4):
    """`count` words of `size` bytes each, or None where the file does not have them.

    A hash table mixes widths: its header, buckets and chains are 32-bit in both classes, while the mask
    words of `.gnu.hash` are the file's own word size - 64 bits in an ELF64, which is why the same 22
    buckets need 32 mask words in one file and 64 in another.
    """
    stop = at + count * size
    if stop > len(raw):
        return None
    return [int.from_bytes(raw[at + each * size:at + each * size + size], "little" if little else "big")
            for each in range(count)]


def walk(raw, found):
    """Every hash table in the file, read the way a loader reads it."""
    bits, little, table, _strings = found
    wide = bits == 64
    out = []
    for section in table:
        kind = section["name"]
        if kind not in (GNU_SECTION, SYSV_SECTION):
            continue
        at, size = section["off"], section["size"]
        head = words_at(raw, at, 4, little)
        if head is None or size < 16:
            out.append({"section": kind, "broken": "no header"})
            continue
        if kind == GNU_SECTION:
            # The header is nbuckets, symoffset, bloom_size, bloom_shift - in that order, and the last of
            # them is derived from the word size rather than stored, so it is not read here at all.
            buckets, symoffset, masks = head[0], head[1], head[2]
            after = at + 16
            span = 8 if wide else 4
            bloom = words_at(raw, after, masks, little, span)
            if bloom is None:
                out.append({"section": kind, "broken": "no mask words"})
                continue
            after += masks * span
            words = words_at(raw, after, buckets, little)
            if words is None:
                out.append({"section": kind, "broken": "no buckets"})
                continue
            after += buckets * 4
            chains = (size - (after - at)) // 4
            tail = words_at(raw, after, chains, little)
            if tail is None:
                out.append({"section": kind, "broken": "chains run past the section"})
                continue
            out.append({"section": kind, "off": at, "bytes": size, "info": section["info"],
                        "buckets": words, "chains": tail, "bloom": bloom, "symoffset": symoffset,
                        "masks": masks,
                        "bits": bits, "little": little})
        else:
            buckets, chains = head[0], head[1]
            heads = words_at(raw, at + 8, buckets, little)
            tail = words_at(raw, at + 8 + buckets * 4, chains, little)
            if heads is None or tail is None:
                out.append({"section": kind, "broken": "arrays run past the section"})
                continue
            out.append({"section": kind, "off": at, "bytes": size, "info": section["info"],
                        "buckets": heads, "chains": tail, "symoffset": None, "masks": None,
                        "bits": bits, "little": little})
    return out


def gnu_hash(text):
    """The GNU hash, computed here so the stored chain words are checked against a derivation."""
    total = 5381
    for one in text.encode("utf-8", "replace"):
        total = (total * 33 + one) & 0xFFFF_FFFF
    return total


def elf_hash(text):
    """The old System V hash, same reason."""
    total = 0
    for one in text.encode("utf-8", "replace"):
        total = (total << 4) + one
        high = total & 0xF000_0000
        if high:
            total ^= high >> 24
        total &= ~high
    return total & 0xFFFF_FFFF


def swept(one, names):
    """The runs a bucket array implies, and whether every chain word agrees with the name it stands for.

    Both shapes store a symbol index in the bucket and 0 for an empty one, and they link differently:
    `.hash` chains hold the index of the next symbol, 0 ending the run, while `.gnu.hash` chains are
    addressed by `index - symoffset`, run in order, and end on the word whose bit 0 is set - the last
    entry of a run stores the hash with bit 0 raised and the others store it cleared.
    """
    gnu = one["section"] == GNU_SECTION
    chains, offset = one["chains"], one["symoffset"] or 0
    runs, reached, wrong, empty = [], [], 0, 0
    for position, head in enumerate(one["buckets"]):
        if not head:
            empty += 1
            runs.append((position, None, 0))
            continue
        at, steps = head, 0
        while True:
            slot = at - offset if gnu else at
            if steps > len(chains) or slot < 0 or slot >= len(chains) or at >= len(names):
                wrong += 1
                break
            text = names[at]
            word = chains[slot]
            if gnu:
                want = gnu_hash(text)
                agreed = word == (want | 1 if word & 1 else want & ~1)
                placed = want % len(one["buckets"]) == position
                reached.append(at)
                steps += 1
                if not agreed or not placed or word & 1:
                    wrong += (not agreed) + (not placed)
                    break
                at += 1
            else:
                placed = elf_hash(text) % len(one["buckets"]) == position
                reached.append(at)
                steps += 1
                if not placed:
                    wrong += 1
                    break
                at = word
                if not at:
                    break
        runs.append((position, head, steps))
    return runs, reached, wrong, empty


# ---------------------------------------------------------------------------- the other two readings
def shell(args):
    made = subprocess.run(args, capture_output=True, shell=False, cwd=SCRATCH, timeout=600)
    if made.returncode != 0:
        raise SystemExit("%s refused: %s" % (args[0], (made.stdout + made.stderr).decode("utf-8", "replace")[:400]))
    return made.stdout.decode("utf-8", "replace")


def llvm(path, gnu):
    """LLVM's listing of one table: its header words, its buckets, and the chain words beside them."""
    text = shell(["llvm-readobj", "--gnu-hash-table" if gnu else "--hash-table", path])
    block = re.search(r"(GnuHashTable|HashTable) \{(.*?)\n\}", text, re.S)
    if block is None:
        return None

    def numbers(label):
        found = re.search(label + r": \[(.*?)\]", block.group(2), re.S)
        if found is None:
            return None
        body = found.group(1).strip()
        return [] if not body else [int(one.strip(), 0) for one in body.split(",")]

    def word(label):
        found = re.search(label + r": (\d+)", block.group(2))
        return None if found is None else int(found.group(1))

    if gnu:
        return {"buckets": word("Num Buckets"), "symoffset": word("First Hashed Symbol Index"),
                "masks": word("Num Mask Words"),
                "bloom": numbers("Bloom Filter"), "heads": numbers("Buckets"),
                "chains": numbers("Values")}
    return {"buckets": word("Num Buckets"), "chains": word("Num Chains"),
            "heads": numbers("Buckets"), "words": numbers("Chains")}


def through_pyelftools(path):
    """pyelftools' own params, and what its hash lookup resolves - the behavioural reading."""
    from elftools.elf.elffile import ELFFile
    out, names, dynsym_count = {}, [], 0
    with open(path, "rb") as handle:
        elf_file = ELFFile(handle)
        sections = {one.name: one for one in elf_file.iter_sections()}
        table = sections.get(".dynsym")
        if table is not None:
            dynsym_count = table.num_symbols()
            names = [(index, one.name) for index, one in enumerate(table.iter_symbols()) if one.name]
        for section in (GNU_SECTION, SYSV_SECTION):
            here = sections.get(section)
            if here is None:
                continue
            params = dict(here.params)
            out[section] = {"params": params, "size": here["data_size"] if False else here.header.sh_size,
                            "info": here.header.sh_info, "off": here.header.sh_offset,
                            "resolved": {}, "control": None}
            for index, name in names:
                other = here.get_symbol(name)
                if other is None:
                    continue
                same = [each for each, sym in enumerate(table.iter_symbols())
                        if sym.name == name and sym.entry == other.entry]
                out[section]["resolved"][name] = same[0] if same else None
            out[section]["control"] = here.get_symbol("lab_symbol_that_is_not_here_" + section)
    return out, names, dynsym_count


# --------------------------------------------------------------------------------------- the agreements
def rows(walked, by_index, dynsym_count, bits):
    tables = [one for one in walked if "broken" not in one]
    if not tables and not [one for one in walked if "broken" in one]:
        # Nothing to say and no refusal to explain: the same answer a PE, an object file and a note-less
        # ELF give, so a panel does not show a table of zeroes for a file that has no table at all.
        return []
    head = ["hash", "tables	%d" % len(tables), "dynsym	%d" % dynsym_count, "bits	%d" % bits,
            "gnu	%d" % len([one for one in tables if one["section"] == GNU_SECTION]),
            "sysv	%d" % len([one for one in tables if one["section"] == SYSV_SECTION])]
    broken = [one["section"] + "	" + one["broken"] for one in walked if "broken" in one]
    if broken:
        head.append("broken	%s" % "; ".join(broken))
    out = ["	".join(head)]
    for index, one in enumerate(tables):
        gnu = one["section"] == GNU_SECTION
        runs, reached, _wrong, empty = swept(one, by_index)
        floor = one["symoffset"] if gnu else 1
        rows_out = ["table", str(index), "kind	gnu" if gnu else "kind	sysv",
                    "off	%d" % one["off"], "bytes	%d" % one["bytes"], "info	%d" % one["info"],
                    "buckets	%d" % len(one["buckets"]), "chains	%d" % len(one["chains"])]
        if gnu:
            rows_out += ["symoffset	%d" % one["symoffset"], "masks	%d" % one["masks"],
                         "wordsize	%d" % (8 if one["bits"] == 64 else 4)]
        rows_out += ["empty	%d" % empty, "reach	%d" % len(set(reached)), "floor	%d" % floor]
        out.append("	".join(rows_out))
        for position, head_at, steps in runs[:MAX_LISTED]:
            out.append("	".join(["bucket", str(index), str(position),
                                  "head	%s" % ("-" if head_at is None else head_at),
                                  "length	%d" % steps]))
        if len(runs) > MAX_LISTED:
            out.append("cut	buckets	%d	table	%d	listed	%d" % (len(runs), index, MAX_LISTED))
        # A symbol named below the floor is in the file and not in the table: it exists to the symbol
        # table and cannot be asked for by name. That is the row's whole claim, and the floor is a number
        # both listings state.
        hidden = [each for each in range(min(floor, len(by_index))) if by_index[each]]
        for each in hidden[:MAX_LISTED]:
            out.append("	".join(["unfound", str(index), str(each), "name	%s" % by_index[each]]))
        if len(hidden) > MAX_LISTED:
            out.append("cut	unfound	%d	table	%d	listed	%d" % (len(hidden), index, MAX_LISTED))
    return out


def check(name, walked, first, second, names, by_index):
    """Every reading has to say the same thing about the same table, or no probe is written."""
    tables = [one for one in walked if "broken" not in one]
    if len(tables) != len(first):
        raise SystemExit("%s: the walk finds %d tables, llvm %d" % (name, len(tables), len(first)))
    if len(tables) != len(second):
        raise SystemExit("%s: the walk finds %d tables, pyelftools %d" % (name, len(tables), len(second)))
    for one, listing in zip(tables, first):
        gnu = one["section"] == GNU_SECTION
        seen = second[one["section"]]
        params = seen["params"]
        if seen["size"] != one["bytes"] or seen["off"] != one["off"] or seen["info"] != one["info"]:
            raise SystemExit("%s: %s lies at %d/%d info %d, pyelftools %r"
                             % (name, one["section"], one["off"], one["bytes"], one["info"],
                                (seen["off"], seen["size"], seen["info"])))
        if params.get("nbuckets") != len(one["buckets"]):
            raise SystemExit("%s: %s has %d buckets here, pyelftools %r"
                             % (name, one["section"], len(one["buckets"]), params.get("nbuckets")))
        if gnu:
            if listing is None:
                raise SystemExit("%s: llvm prints no GNU hash table for a file that has one" % name)
            pairs = (("bucket count", params.get("nbuckets"), len(one["buckets"])),
                     ("symoffset", params.get("symoffset"), one["symoffset"]),
                     ("mask words", params.get("bloom_size"), one["masks"]),
                     ("bucket array", params.get("buckets"), one["buckets"]),
                     ("mask array", params.get("bloom"), one["bloom"]))
            for label, theirs, mine in pairs:
                if theirs != mine:
                    raise SystemExit("%s: %s %s is %r to the walk and %r to pyelftools"
                                     % (name, one["section"], label, mine, theirs))
            if listing["buckets"] != len(one["buckets"]) or listing["symoffset"] != one["symoffset"]:
                raise SystemExit("%s: %s reads %r to llvm, %d/%d to the walk"
                                 % (name, one["section"], listing, len(one["buckets"]), one["symoffset"]))
            if listing["masks"] != one["masks"] or listing["heads"] != one["buckets"]:
                raise SystemExit("%s: llvm's bucket array differs from the walk's for %s" % (name, one["section"]))
            if listing["bloom"] != one["bloom"]:
                raise SystemExit("%s: the mask words of %s differ from llvm's" % (name, one["section"]))
            if listing["chains"] is not None and len(listing["chains"]) != len(one["chains"]):
                raise SystemExit("%s: %s has %d chain words, llvm lists %d"
                                 % (name, one["section"], len(one["chains"]), len(listing["chains"])))
            if listing["chains"] and listing["chains"] != one["chains"]:
                raise SystemExit("%s: the chain words of %s differ from llvm's at %r"
                                 % (name, one["section"], [(a, b) for a, b in zip(one["chains"], listing["chains"])
                                                           if a != b][:4]))
            floor = one["symoffset"]
        else:
            if listing is None:
                raise SystemExit("%s: llvm prints no .hash for a file that has one" % name)
            pairs = (("bucket count", params.get("nbuckets"), len(one["buckets"])),
                     ("chain count", params.get("nchains"), len(one["chains"])),
                     ("bucket array", params.get("buckets"), one["buckets"]),
                     ("chain array", params.get("chains"), one["chains"]))
            for label, theirs, mine in pairs:
                if theirs != mine:
                    raise SystemExit("%s: .hash %s is %r to the walk and %r to pyelftools"
                                     % (name, label, mine, theirs))
            if listing["buckets"] != len(one["buckets"]) or listing["chains"] != len(one["chains"]):
                raise SystemExit("%s: llvm's .hash counts differ: %r" % (name, listing))
            if listing["heads"] != one["buckets"] or listing["words"] != one["chains"]:
                raise SystemExit("%s: llvm's .hash arrays differ from the walk's" % name)
            floor = 1
        # pyelftools performs the lookup the table describes; every name it resolves has to be the symbol
        # the symbol table lists at that index, and nothing below the floor may resolve at all.
        for index, label in names:
            got = seen["resolved"].get(label)
            if index < floor and got is not None:
                raise SystemExit("%s: %s resolves %s at index %d, below the floor of %d"
                                 % (name, one["section"], label, index, floor))
            if index >= floor and got != index:
                raise SystemExit("%s: %s cannot resolve %s (index %d), which the symbol table names"
                                 % (name, one["section"], label, index))
        if seen["control"] is not None:
            raise SystemExit("%s: %s resolves a name the file never had" % (name, one["section"]))
        # And the walk's own account has to close: every chain word equal to the hash of the name it
        # stands for, every symbol in the bucket its hash selects, the runs never crossing, and the
        # symbols they reach being exactly the named ones at or above the floor.
        runs, reached, wrong, empty = swept(one, by_index)
        if wrong:
            raise SystemExit("%s: %s has %d chain words that disagree with the hash of their own name"
                             % (name, one["section"], wrong))
        named = [index for index, text in enumerate(by_index) if text and index >= floor]
        if len(reached) != len(set(reached)):
            raise SystemExit("%s: %s reaches %d entries over %d distinct symbols"
                             % (name, one["section"], len(reached), len(set(reached))))
        if set(reached) != set(named):
            raise SystemExit("%s: %s reaches %s, the symbol table names %s at or above %d"
                             % (name, one["section"], sorted(set(reached))[:6], sorted(set(named))[:6], floor))
        if empty != len([one2 for one2 in one["buckets"] if not one2]):
            raise SystemExit("%s: %s counts %d empty buckets twice over" % (name, one["section"], empty))


def main():
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    build()
    probe = {}
    for name in ("hgnu.so", "hsys.so", "hboth.so", "hboth32.so", "lab.so", "libuser.so", "note.elf",
                 "lab.elf", "res.dll", "answer.obj"):
        if not os.path.exists(os.path.join(SCRATCH, name)):
            shutil.copyfile(os.path.join(FIX, name), os.path.join(SCRATCH, name))
        path = os.path.join(SCRATCH, name)
        raw = open(path, "rb").read()
        found = elf(raw)
        if found is None:
            probe[name] = {"hash": False, "tables": 0, "rows": []}
            print("%-12s not an ELF file, so no hash table to read" % name)
            continue
        bits, _little, _table, _strings = found
        walked = walk(raw, found)
        tables = [one for one in walked if "broken" not in one]
        first = [llvm(path, one["section"] == GNU_SECTION) for one in tables]
        second, names, dynsym_count = through_pyelftools(path)
        by_index = [""] * dynsym_count
        for index, text in names:
            if index < dynsym_count:
                by_index[index] = text
        check(name, walked, first, second, names, by_index)
        made = rows(walked, by_index, dynsym_count, bits)
        probe[name] = {"hash": bool(made and len(made) > 1), "tables": len(tables), "rows": made}
        print("%-12s %d tables, dynsym %d%s" % (name, len(tables), dynsym_count,
                                                 "" if tables else " - nothing to read"))
        for row in made[:4]:
            print("%-12s %s" % ("", row.replace("\t", " | ")))
    for name in ("hgnu.so", "hsys.so", "hboth.so", "hboth32.so"):
        shutil.copyfile(os.path.join(SCRATCH, name), os.path.join(FIX, name))
    with open(os.path.join(FIX, "hash.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; the walk, llvm-readobj and pyelftools agree" % len(probe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
