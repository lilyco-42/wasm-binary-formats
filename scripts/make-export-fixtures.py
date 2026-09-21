"""Produce and check the PE export fixture - a DLL whose export table holds every branch.

The producer is `clang` plus `lld-link`, and the witnesses are two readers the lab does not control:
`llvm-readobj --coff-exports`, which lists one entry per ordinal including the empty slots, and
`objdump -x`, which lists the export address table *without* the empty slots, names the section the
table lives in, and prints the three table addresses and the directory's own size. The script walks the
bytes itself as well, and refuses to write `test/fixtures/exports.probe.json` unless all three agree -
so the rows the reader will print are the witnesses' facts, not a reading of the fixture by hand.

    temp/venv/Scripts/python.exe scripts/make-export-fixtures.py

Five branches are on purpose, because an export table has nothing else: two names for one address
(`alias` and `answer` both land on `answer`'s body), an ordinal pinned out of thin air (`shipped,@7`,
which is what moves the ordinal base), an entry with an RVA and no name (`hidden,@9,noname`, the shape
system DLLs use for half their surface), a slot that is empty (ordinal 8, which falls out of the two
pins by itself), and a forwarder (`forward=KERNEL32.GetVersion`, an RVA that points back *into* the
directory and holds text instead of an address).
"""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

SOURCE = """\
__declspec(dllexport) int __cdecl answer(void) { return 42; }
__declspec(dllexport) int __cdecl helper(int x) { return x + 1; }
int __cdecl hidden(void) { return 7; }
"""

EXPORTS = ["-export:alias=answer", "-export:shipped=answer,@7",
           "-export:forward=KERNEL32.GetVersion", "-export:hidden,@9,noname"]


def run(cmd, work):
    out = subprocess.run(cmd, capture_output=True, cwd=work, shell=False, timeout=600)
    text = out.stdout.decode("utf-8", "replace") + out.stderr.decode("utf-8", "replace")
    if out.returncode:
        raise SystemExit("%s failed: %s" % (cmd[0], text[-800:]))
    return text


def readobj(text):
    """llvm's list: one block per EAT slot, in ordinal order, empty slots included."""
    found = []
    for block in re.findall(r"Export \{(.*?)\}", text, re.S):
        number = int(re.search(r"Ordinal: (\d+)", block).group(1))
        name = re.search(r"Name: ?(.*)", block).group(1).strip()
        rva = re.search(r"RVA: 0x([0-9a-f]+)", block)
        forward = re.search(r"ForwardedTo: (.*)", block)
        found.append({
            "ordinal": number,
            "name": name or None,
            "rva": int(rva.group(1), 16) if rva else None,
            "forward": forward.group(1).strip() if forward else None,
        })
    return found


def objdump_tables(text):
    """bfd's view: the directory header, the three table addresses, and its two listings.

    `Export Address Table` is printed twice with a different base each time - a count under `Number in:`,
    an address under `Table Addresses` - so each is read from its own block rather than by a search that
    could land on either."""
    block = text.split("The Export Tables")[1].split("Export Address Table -- Ordinal Base")[0]
    counts, tables = block.split("Table Addresses")
    name = re.search(r"Name \t+0*([0-9a-f]+) (\S+)", counts)
    head = {
        "rva": int(re.search(r"Entry 0 0*([0-9a-f]+) 0*([0-9a-f]+) Export Directory", text).group(1), 16),
        "size": int(re.search(r"Entry 0 0*[0-9a-f]+ 0*([0-9a-f]+) Export Directory", text).group(1), 16),
        "section": re.search(r"There is an export table in (\S+) at", text).group(1),
        "name_rva": int(name.group(1), 16),
        "dll": name.group(2),
        "base": int(re.search(r"Ordinal Base \t+(\d+)", counts).group(1)),
        "functions": int(re.search(r"Export Address Table \t+(\d+)", counts).group(1)),
        "names": int(re.search(r"\[Name Pointer/Ordinal\] Table\t+(\d+)", counts).group(1)),
        "eat": int(re.search(r"Export Address Table \t+0*([0-9a-f]+)", tables).group(1), 16),
        "names_at": int(re.search(r"Name Pointer Table \t+0*([0-9a-f]+)", tables).group(1), 16),
        "ordinals_at": int(re.search(r"Ordinal Table \t+0*([0-9a-f]+)", tables).group(1), 16),
    }
    body = text.split("Export Address Table -- Ordinal Base")[1]
    eat_block, name_block = body.split("[Ordinal/Name Pointer] Table")
    listed = re.findall(r"\[\s*(\d+)\] \+base\[\s*(\d+)\] ([0-9a-f]{8}) (Export RVA|Forwarder RVA)(?: -- (.*))?",
                        eat_block)
    eat = [{"index": int(one), "ordinal": int(two), "rva": int(three, 16),
            "forward": (five or "").strip().lstrip("- ").strip() or None}
           for one, two, three, four, five in listed]
    named = re.findall(r"\[\s*(\d+)\] \+base\[\s*(\d+)\] +([0-9a-f]+) (\S+)",
                       name_block.split("The Function Table")[0])
    return head, eat, [{"index": int(one), "ordinal": int(two), "hint": int(three, 16), "name": four}
                       for one, two, three, four in named]


def word(raw, at):
    return struct.unpack_from("<I", raw, at)[0]


def half(raw, at):
    return struct.unpack_from("<H", raw, at)[0]


def walk(raw):
    """The reader's own walk, from the headers up: no fact is taken from a witness here, so the
    comparison afterwards is between two derivations of the same bytes."""
    lfanew = word(raw, 0x3c)
    optsz = half(raw, lfanew + 20)
    opt = lfanew + 24
    plus = half(raw, opt) == 0x20b
    dirs = opt + (112 if plus else 96)
    image_base = struct.unpack_from("<Q", raw, opt + 24)[0] if plus else word(raw, opt + 28)
    nsec = half(raw, lfanew + 6)
    table = opt + optsz
    sections = []
    for each in range(nsec):
        at = table + 40 * each
        name = raw[at:at + 8].split(b"\0")[0].decode("latin-1")
        sections.append({"name": name, "vsize": word(raw, at + 8), "vaddr": word(raw, at + 12),
                         "rawsize": word(raw, at + 16), "roff": word(raw, at + 20)})
    # Every table has to be listed by a real section, so the file offsets below mean something.
    if sum(1 for each in sections if each["name"] == ".rdata") != 1:
        raise SystemExit("the fixture has no single .rdata to hang the export directory on")
    def where(rva):
        for each in sections:
            stop = each["vaddr"] + max(each["vsize"], each["rawsize"])
            if each["vaddr"] <= rva < stop and each["rawsize"]:
                return each["name"], each["roff"] + (rva - each["vaddr"])
        raise SystemExit("rva %#x lies in no section" % rva)

    dir_rva, dir_size = word(raw, dirs), word(raw, dirs + 4)
    if dir_rva == 0 or dir_size == 0:
        raise SystemExit("the fixture carries no export directory at all")
    at = where(dir_rva)[1]
    # The directory's `Name` is an RVA of a C string, not the string: reading the four bytes where the
    # RVA lives yields `( ` where bfd prints the file's name, which is the mistake this line prevents.
    name_rva = word(raw, at + 12)
    header = {
        "characteristics": word(raw, at),
        "stamp": word(raw, at + 4),
        "name_rva": name_rva,
        "dll": raw[where(name_rva)[1]:].split(b"\0")[0].decode("latin-1"),
        "base": word(raw, at + 16),
        "functions": word(raw, at + 20),
        "names": word(raw, at + 24),
        "eat": word(raw, at + 28),
        "names_at": word(raw, at + 32),
        "ordinals_at": word(raw, at + 36),
        "rva": dir_rva,
        "size": dir_size,
        "section": where(dir_rva)[0],
        "offset": at,
        "image_base": image_base,
    }
    names = {}
    for index in range(header["names"]):
        rva = word(raw, where(header["names_at"])[1] + 4 * index)
        slot = half(raw, where(header["ordinals_at"])[1] + 2 * index)
        names[slot] = (index, raw[where(rva)[1]:].split(b"\0")[0].decode("latin-1"))
    slots = []
    for index in range(header["functions"]):
        rva = word(raw, where(header["eat"])[1] + 4 * index)
        ordinal = header["base"] + index
        hint, name = names.get(index, (None, None))
        if rva == 0:
            slots.append({"ordinal": ordinal, "name": name, "rva": None, "forward": None,
                          "hint": hint, "hole": True})
        elif header["rva"] <= rva < header["rva"] + header["size"]:
            target = raw[where(rva)[1]:].split(b"\0")[0].decode("latin-1")
            slots.append({"ordinal": ordinal, "name": name, "rva": rva, "forward": target,
                          "hint": hint, "hole": False})
        else:
            slots.append({"ordinal": ordinal, "name": name, "rva": rva, "forward": None,
                          "hint": hint, "hole": False})
    return header, slots, where


def rows_for(header, slots, where):
    """The rows, built from the walk *after* the walk has been checked against both witnesses."""
    out = ["exports\trva\t0x%x\tbytes\t%d\toff\t%d\tsection\t%s\tdll\t%s\tbase\t%d\tfunctions\t%d\tnames\t%d"
           % (header["rva"], header["size"], header["offset"], header["section"], header["dll"],
              header["base"], header["functions"], header["names"])]
    for each in slots:
        if each["hole"]:
            out.append("export\t%d\t-\thole" % each["ordinal"])
            continue
        if each["forward"]:
            out.append("export\t%d\t%s\tforward\t%s\thint\t%d"
                       % (each["ordinal"], each["name"] or "-", each["forward"], each["hint"]))
            continue
        section, offset = where(each["rva"])
        kind = "noname" if each["name"] is None else "hint\t%d" % each["hint"]
        out.append("export\t%d\t%s\trva\t0x%x\taddr\t%d\toff\t%d\tsection\t%s\t%s"
                   % (each["ordinal"], each["name"] or "-", each["rva"],
                      header["image_base"] + each["rva"], offset, section, kind))
    return out


def main():
    work = tempfile.mkdtemp(prefix="export")
    with open(os.path.join(work, "exp.c"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(SOURCE)
    run(["clang", "-O0", "-g0", "--target=x86_64-w64-windows-gnu", "-c", "exp.c", "-o", "exp.obj"], work)
    run(["lld-link", "-out:exp.dll", "-dll", "-subsystem:windows", "-noentry"] + EXPORTS + ["exp.obj"], work)
    path = os.path.join(work, "exp.dll")
    raw = open(path, "rb").read()
    home = os.path.expanduser("~").encode()
    if home in raw:
        raise SystemExit("the home path leaked into the fixture: %r" % home.decode())
    readobj_rows = readobj(run(["llvm-readobj", "--coff-exports", "exp.dll"], work))
    objdump_text = run(["objdump", "-x", "exp.dll"], work)
    head, listed, named = objdump_tables(objdump_text)
    header, slots, where = walk(raw)

    # Header: the two witnesses and the walk have to name the same table in the same section.
    checks = {
        "rva": (head["rva"], header["rva"]),
        "size": (head["size"], header["size"]),
        "dll": (head["dll"], header["dll"]),
        "name_rva": (head["name_rva"], header["name_rva"]),
        "base": (head["base"], header["base"]),
        "functions": (head["functions"], header["functions"]),
        "names": (head["names"], header["names"]),
        "eat": (head["eat"], header["eat"]),
        "names_at": (head["names_at"], header["names_at"]),
        "ordinals_at": (head["ordinals_at"], header["ordinals_at"]),
    }
    for key, (one, two) in checks.items():
        if one != two:
            raise SystemExit("llvm/bfd say %s is %r, the walk says %r" % (key, one, two))
    if head["section"] != header["section"]:
        raise SystemExit("bfd puts the table in %s, the walk in %s" % (head["section"], header["section"]))
    # llvm lists the holes; bfd leaves them out and calls its list everything else. Both have to be
    # the same set once the holes are dropped, and the forwarder has to read the same way in both.
    ours = {each["ordinal"]: each for each in slots}
    if len(readobj_rows) != len(slots):
        raise SystemExit("llvm listed %d slots, the walk %d" % (len(readobj_rows), len(slots)))
    for each in readobj_rows:
        mine = ours.get(each["ordinal"])
        if mine is None:
            raise SystemExit("llvm names ordinal %d, the walk does not" % each["ordinal"])
        if mine["name"] != each["name"]:
            raise SystemExit("ordinal %d: llvm %r, walk %r" % (each["ordinal"], each, mine))
        if each["rva"] == 0 and not mine["hole"]:
            raise SystemExit("llvm calls ordinal %d empty, the walk does not" % each["ordinal"])
        if each["forward"]:
            # llvm prints the target and drops the `RVA` line; the walk keeps both, because the
            # directory's own range is what makes an entry a forwarder rather than an address.
            if mine["forward"] != each["forward"] or mine["hole"]:
                raise SystemExit("ordinal %d forwarder: llvm %r, walk %r"
                                 % (each["ordinal"], each["forward"], mine["forward"]))
        elif (mine["rva"] or 0) != each["rva"]:
            raise SystemExit("ordinal %d: llvm %r, walk %r" % (each["ordinal"], each, mine))
    for each in listed:
        mine = ours[each["ordinal"]]
        if mine["hole"]:
            raise SystemExit("bfd listed the hole at ordinal %d" % each["ordinal"])
        if mine["rva"] != each["rva"] or mine["forward"] != each["forward"]:
            raise SystemExit("ordinal %d: bfd %r, walk %r" % (each["ordinal"], each, mine))
    if len(listed) != sum(1 for each in slots if not each["hole"]):
        raise SystemExit("bfd listed %d of %d non-hole slots" % (len(listed), sum(1 for each in slots if not each["hole"])))
    for each in named:
        mine = ours[each["ordinal"]]
        if mine["name"] != each["name"] or mine["hint"] != each["hint"]:
            raise SystemExit("name %s: bfd %r, walk %r" % (each["name"], each, mine))
    if len(named) != header["names"]:
        raise SystemExit("bfd listed %d names, the directory says %d" % (len(named), header["names"]))
    # The branches this fixture exists to hold, checked as facts rather than as counts: one address
    # reached by several names, an entry with an RVA and no name, an empty slot, a forwarder, and an
    # ordinal base that is not 1 because two ordinals were pinned by hand.
    bodies = [each["rva"] for each in slots if each["rva"] and not each["forward"]]
    if len(bodies) != len(set(bodies)) + 2:
        raise SystemExit("no aliased address in %r" % bodies)
    if not any(each["forward"] for each in slots):
        raise SystemExit("no forwarder in the table")
    if not any(each["hole"] for each in slots):
        raise SystemExit("no empty slot in the table")
    if not any(each["name"] is None and not each["hole"] for each in slots):
        raise SystemExit("no nameless export in the table")
    if header["base"] < 2:
        raise SystemExit("no pinned ordinal, the base is %d" % header["base"])
    rows = rows_for(header, slots, where)
    if len(rows) != 1 + header["functions"]:
        raise SystemExit("one row per slot was expected")
    probe = {
        "bytes": len(raw),
        "header": {key: (value if not isinstance(value, str) else value)
                   for key, value in header.items()},
        "slots": [{key: value for key, value in each.items()} for each in slots],
        "rows": rows,
    }
    shutil.copyfile(path, os.path.join(FIX, "exp.dll"))
    with open(os.path.join(FIX, "exports.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    for row in rows:
        print(row.replace("\t", " | "))
    print("exp.dll: %d bytes, %d slots, %d names, both witnesses agree"
          % (len(raw), header["functions"], header["names"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
