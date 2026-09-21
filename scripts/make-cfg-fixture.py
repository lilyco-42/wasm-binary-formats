#!/usr/bin/env python3
"""Write the control-flow fixture and print the block and edge lists a CFG pass has to reproduce.

`temp` has no disassembler of its own, so the facts here come from **objdump**: `clang -c` compiles the C
function below (checked in as the string `SOURCE`, so the object is reproducible), and `objdump -d` lists
every instruction with its address, mnemonic and - for branches - the target it resolved, spelled
`30 <classify+0x30>`. Those targets are what a second implementation says the edges are.

The *grouping* of instructions into blocks is this lab's rule, not objdump's, because objdump has no notion
of a basic block: a run starts at the entry or at a branch target, and closes at a `ret`, an unconditional
jump, a `call`, or the instruction before the next leader. The script applies that rule to objdump's own
listing, and the tests then assert the wasm module agrees on the same bytes. So an address or a target that
objdump did not print cannot appear in an expected row, while the block boundaries are a stated convention
rather than an independent observation - which is the honest split, and it is the same one the COFF
relocation round drew.

Two things about this particular function are worth pinning, and both are graph facts rather than
instruction facts:

  * the `nopl (%rax)` at 0x3d is alignment padding after an unconditional `jmp`. It closes no block of
    anything that reaches it, so it is a block with **zero predecessors** that is not the entry - the only
    interesting thing a linear listing gets wrong and a graph gets right.
  * the `call` at 0x40 has no relocation applied yet, so objdump resolves it to the next instruction
    (`45 <classify+0x45>`). The call edge therefore points at the fallthrough target; the report labels the
    edge `call` so nobody reads it as a within-function flow edge.

Usage: temp/venv/Scripts/python.exe scripts/make-cfg-fixture.py
"""
import json
import os
import re
import subprocess
import sys

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "cfg-work"))
SOURCE = """\
int helper(int);

int classify(int *values, int count, int limit) {
  int total = 0;
  if (values == 0 || count <= 0) {
    return -1;
  }
  for (int i = 0; i < count; i++) {
    int each = values[i];
    if (each > limit) {
      total += helper(each);
    } else if (each < 0) {
      total -= each;
    } else {
      total += 1;
    }
  }
  return total;
}
"""
# A branch is unconditional only on this list; every other jump has a fallthrough as well, which is the
# distinction the edge list exists to make. `b` alone is AArch64's unconditional branch, and Capstone
# spells a conditional one differently (`b.eq`), so a bare name is enough to tell them apart.
UNCONDITIONAL = {"jmp", "b", "br", "j"}
RETURNS = {"ret", "iret", "eret", "retn", "retf"}
LINE = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*([a-z0-9.]+)\s*(.*)$")
TARGET = re.compile(r"^\s*([0-9a-f]+)\s*<")


def run(command):
    made = subprocess.run(command, capture_output=True, shell=False)
    if made.returncode != 0:
        raise SystemExit("{} failed: {}".format(" ".join(command), made.stderr[:300]))
    return made.stdout.decode("latin1")


def build():
    os.makedirs(SCRATCH, exist_ok=True)
    source = os.path.join(SCRATCH, "flow.c")
    with open(source, "w", encoding="utf8", newline="\n") as handle:
        handle.write(SOURCE)
    obj = os.path.join(SCRATCH, "flow.obj")
    if os.path.exists(obj):
        os.remove(obj)
    run(["clang", "-c", "-O1", "-o", obj, source])
    listing = run(["objdump", "-d", "--section=.text", obj])
    sizes = run(["objdump", "-h", obj])
    return obj, listing, sizes


def section_span(sizes):
    """.text's size, straight out of objdump's own section table."""
    for line in sizes.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] == ".text":
            return int(parts[2], 16), int(parts[3], 16), int(parts[5], 16)
    raise SystemExit("objdump -h shows no .text")


def parse_listing(listing):
    """Instructions as objdump printed them: address, mnemonic, operand text, resolved target."""
    each = []
    for line in listing.splitlines():
        match = LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        operand = match.group(3).strip()
        target = None
        found = TARGET.match(operand)
        if found:
            target = int(found.group(1), 16)
        each.append({"address": address, "mnemonic": mnemonic, "operand": operand, "target": target})
    if not each:
        raise SystemExit("objdump -d printed no instructions")
    return each


def kind(instruction):
    """The same three terminator classes the module reports, and nothing finer."""
    mnemonic = instruction["mnemonic"]
    if mnemonic.startswith("j") or mnemonic.startswith("loop") or mnemonic in ("cbz", "cbnz", "tbz",
                                                                                "tbnz", "bl", "b.eq"):
        return "jump"
    if mnemonic == "call":
        return "call"
    if mnemonic in RETURNS:
        return "ret"
    return None


def unconditional(instruction):
    return instruction["mnemonic"] in UNCONDITIONAL


def blocks(instructions, entry, section_end):
    """This lab's rule, applied to objdump's listing - see the docstring."""
    targets = {entry}
    for each in instructions:
        if kind(each) in ("jump", "call") and each["target"] is not None:
            targets.add(each["target"])
    out = []
    start = 0
    for index, each in enumerate(instructions):
        closing = kind(each) is not None or index + 1 == len(instructions) or \
            instructions[index + 1]["address"] in targets
        if not closing:
            continue
        group = instructions[start:index + 1]
        if group:
            following = instructions[index + 1]["address"] if index + 1 < len(instructions) else section_end
            out.append({
                "start": group[0]["address"],
                # Exclusive, the way the module's own block rows state an end: the address the next block
                # begins at, which is also what a fallthrough edge points at.
                "end": following,
                "next": following,
                "insns": len(group),
                "term": kind(group[-1]) or "none",
                "always": unconditional(group[-1]),
                "target": group[-1]["target"] if kind(group[-1]) in ("jump", "call") else None,
            })
        start = index + 1
    return out, sorted(targets)


def edges(groups):
    found = []
    by_start = {each["start"]: index for index, each in enumerate(groups)}
    for index, each in enumerate(groups):
        term = each["term"]
        if term == "jump":
            if each["target"] in by_start:
                found.append((index, by_start[each["target"]], "taken"))
            # A conditional branch goes both ways: the taken edge above and the instruction after it.
            if not each["always"] and each["next"] in by_start:
                found.append((index, by_start[each["next"]], "fall"))
        elif term == "call":
            # The call edge is interprocedural, so it is labelled as one; the block still falls through.
            if each["target"] in by_start:
                found.append((index, by_start[each["target"]], "call"))
            if each["next"] in by_start:
                found.append((index, by_start[each["next"]], "fall"))
        elif term == "none":
            if each["next"] in by_start:
                found.append((index, by_start[each["next"]], "fall"))
    return found


def rows(groups, found, entry):
    """Edge rows, then one degree row per block, then the summary - the order the module emits."""
    preds = [0] * len(groups)
    succs = [0] * len(groups)
    for source, destination, _kind in found:
        preds[destination] += 1
        succs[source] += 1
    lines = []
    kinds = {"fall": 0, "taken": 0, "call": 0}
    back = 0
    for number, (source, destination, kind_name) in enumerate(found):
        loops = groups[destination]["start"] <= groups[source]["start"]
        kinds[kind_name] += 1
        back += 1 if loops else 0
        lines.append("edge\t{}\tfrom\t0x{:x}\tto\t0x{:x}\tkind\t{}\tback\t{}".format(
            number, groups[source]["start"], groups[destination]["start"], kind_name,
            "yes" if loops else "no"))
    for index, each in enumerate(groups):
        lines.append("degree\t{}\tpreds\t{}\tsuccs\t{}\tentry\t{}".format(
            index, preds[index], succs[index], "yes" if each["start"] == entry else "no"))
    unreached = sum(1 for index, each in enumerate(groups)
                    if preds[index] == 0 and each["start"] != entry)
    lines.append("cfg\tblocks\t{}\tedges\t{}\tfall\t{}\ttaken\t{}\tcall\t{}\tback\t{}\tunreached\t{}"
                 .format(len(groups), len(found), kinds["fall"], kinds["taken"], kinds["call"], back,
                         unreached))
    return lines, preds, back


def main():
    obj, listing, sizes = build()
    size, vma, offset = section_span(sizes)
    instructions = parse_listing(listing)
    entry = instructions[0]["address"]
    groups, targets = blocks(instructions, entry, vma + size)
    found = edges(groups)
    lines, preds, back = rows(groups, found, entry)
    raw = open(obj, "rb").read()
    text = raw[offset:offset + size]
    if len(text) != size:
        raise SystemExit(".text claims {} bytes, the file holds {}".format(size, len(text)))
    print("== flow.obj .text {} bytes at file offset {:#x}, {} instructions".format(size, offset, len(instructions)))
    for line in lines:
        print("   ", line.replace("\t", " | "))
    if back == 0:
        raise SystemExit("the loop was optimised away, so the fixture proves nothing about back edges")
    zero = [each["start"] for each, value in zip(groups, preds) if value == 0]
    if zero != [entry, 0x3D]:
        raise SystemExit("expected only the entry and the 0x3d padding block to have no predecessor, got "
                         "{}".format([hex(each) for each in zero]))
    leaving = sum(1 for source, _destination, _kind in found if source == 0)
    if leaving != 2:
        raise SystemExit("the guard's conditional branch has {} successors, not taken plus fallthrough"
                         .format(leaving))
    for target in targets:
        if target < entry or target > instructions[-1]["address"]:
            raise SystemExit("objdump resolved a branch to {:#x}, outside the section".format(target))
    with open(os.path.join(OUT, "flow.obj"), "wb") as handle:
        handle.write(raw)
    with open(os.path.join(OUT, "flow.probe.json"), "w", encoding="utf8") as handle:
        json.dump({
            "text_bytes": size, "text_offset": offset, "text_hex": text.hex(),
            "instructions": len(instructions), "leaders": ["0x{:x}".format(each) for each in targets],
            "edges": [each for each in lines if each.startswith("edge")],
            "degrees": [each for each in lines if each.startswith("degree")],
            "summary": lines[-1], "rows": lines,
            "objdump_listing": [
                {"address": "0x{:x}".format(each["address"]), "mnemonic": each["mnemonic"],
                 "operand": each["operand"],
                 "target": None if each["target"] is None else "0x{:x}".format(each["target"])}
                for each in instructions],
        }, handle, indent=1, sort_keys=True)
    print("wrote flow.obj and flow.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
