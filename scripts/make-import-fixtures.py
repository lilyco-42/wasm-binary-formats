"""Produce and check the PE import fixtures - what a binary asks the loader to hand it.

`lld-link` cannot write an import table on this host: there is no Windows import library anywhere on it,
no mingw sysroot and no SDK, so a reference to `kernel32` has nothing to resolve against. `csc.exe` does
produce one, because a .NET assembly always imports its runtime host - `mscoree.dll`, `_CorDllMain` - and
it writes a PE32, which is the other half of the optional-header branch the export fixture does not cover.

Two shapes csc cannot make are got by editing its bytes and asking both readers what they now say: an
import by ordinal (the high bit of the lookup-table entry set, the low sixteen bits the number) and a
descriptor with no import lookup table at all, where the names have to be read out of the address table
instead. `objdump -x` and `llvm-readobj --coff-imports` were run over those two files before either rule
was written down, and both print the same name or the same ordinal as the untouched fixture, so the
branches are witnessed rather than assumed.

    temp/venv/Scripts/python.exe scripts/make-import-fixtures.py [--refresh]

The committed `lab.dll` is reused unless `--refresh` is given: csc stamps a random module id into every
build, so regenerating it would move bytes the probe has nothing to say about.
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
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

SOURCE = """\
namespace lab { public static class Tag { public static int Value { get { return 42; } } } }
"""

DESCRIPTOR = 20
DESCRIPTOR_FIELDS = "<IIIII"


def run(cmd, work=None):
    out = subprocess.run(cmd, capture_output=True, shell=False, timeout=600, cwd=work)
    text = out.stdout.decode("utf-8", "replace") + out.stderr.decode("utf-8", "replace")
    if out.returncode:
        raise SystemExit("%s failed: %s" % (cmd[0], text[-800:]))
    return text


def build():
    """csc's own output, or the committed file if it is already here."""
    keep = os.path.join(FIX, "lab.dll")
    if os.path.exists(keep) and "--refresh" not in sys.argv:
        return open(keep, "rb").read()
    if not os.path.exists(CSC):
        raise SystemExit("no C# compiler at %s, so no import fixture can be produced here" % CSC)
    work = tempfile.mkdtemp(prefix="imports")
    with open(os.path.join(work, "lab.cs"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(SOURCE)
    run([CSC, "/nologo", "/target:library", "/out:lab.dll", "lab.cs"], work)
    return open(os.path.join(work, "lab.dll"), "rb").read()


def headers(raw):
    """The few header facts an import walk needs: where the directories are, how wide a thunk is, and
    which section owns which address."""
    lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    opt = lfanew + 24
    optsz = struct.unpack_from("<H", raw, lfanew + 20)[0]
    plus = struct.unpack_from("<H", raw, opt)[0] == 0x20B
    found = []
    for each in range(struct.unpack_from("<H", raw, lfanew + 6)[0]):
        at = opt + optsz + 40 * each
        name = raw[at:at + 8].split(b"\0")[0].decode("latin-1")
        vsize, vaddr, rawsize, roff = struct.unpack_from("<IIII", raw, at + 8)
        if rawsize:
            found.append((name, vaddr, max(vsize, rawsize), roff))
    return {
        "plus": plus,
        "wide": 8 if plus else 4,
        "code": "<Q" if plus else "<I",
        "flag": 1 << (63 if plus else 31),
        "dirs": opt + (112 if plus else 96),
        "image_base": struct.unpack_from("<Q", raw, opt + 24)[0] if plus
        else struct.unpack_from("<I", raw, opt + 28)[0],
        "sections": found,
    }


def locate(raw, pe, rva):
    """A section that covers the address, and where the byte lies in the file."""
    for name, vaddr, span, roff in pe["sections"]:
        if vaddr <= rva < vaddr + span:
            return roff + (rva - vaddr), name
    return None, None


def text_at(raw, pe, rva):
    at, _ = locate(raw, pe, rva)
    if at is None:
        raise SystemExit("rva %#x lies in no section" % rva)
    return raw[at:].split(b"\0")[0].decode("latin-1")


def walk(raw):
    """The reader's own walk: descriptors until an all-zero one, thunks until a zero one."""
    pe = headers(raw)
    imp_rva, imp_size = struct.unpack_from("<II", raw, pe["dirs"] + 8)
    if imp_rva == 0 or imp_size < DESCRIPTOR:
        raise SystemExit("no import directory to walk")
    at, section = locate(raw, pe, imp_rva)
    if at is None:
        raise SystemExit("the import directory points outside every section")
    found = {"rva": imp_rva, "size": imp_size, "offset": at, "section": section,
             "image_base": pe["image_base"], "wide": pe["wide"], "plus": pe["plus"], "dlls": []}
    for step in range(257):
        base = at + DESCRIPTOR * step
        ilt, stamp, chain, name_at, iat = struct.unpack_from(DESCRIPTOR_FIELDS, raw, base)
        if (ilt, stamp, chain, name_at, iat) == (0, 0, 0, 0, 0):
            break
        if step == 256:
            raise SystemExit("no terminating descriptor")
        # With no lookup table the address table is the only list of names there is - and the loader
        # overwrites that one in place, which is why the two are read apart in the first place.
        source = ilt or iat
        entries = []
        for slot in range(4096):
            where_, _ = locate(raw, pe, source + pe["wide"] * slot)
            value = struct.unpack_from(pe["code"], raw, where_)[0]
            if not value:
                break
            if slot == 4095:
                raise SystemExit("a thunk array that never ends is not a fixture")
            iat_slot = iat + pe["wide"] * slot
            if value & pe["flag"]:
                entries.append({"ordinal": value & 0xFFFF, "hint": None, "name": None,
                                "thunk": None, "slot": iat_slot})
            else:
                entry, _ = locate(raw, pe, value)
                hint = struct.unpack_from("<H", raw, entry)[0]
                entries.append({"ordinal": None, "hint": hint,
                                "name": raw[entry + 2:].split(b"\0")[0].decode("latin-1"),
                                "thunk": value, "slot": iat_slot})
        found["dlls"].append({"dll": text_at(raw, pe, name_at), "ilt": ilt, "iat": iat,
                              "stamp": stamp, "chain": chain,
                              "names_from": "ilt" if ilt else "iat", "thunks": entries})
    return found


def objdump_imports(text):
    """bfd's list, as `{dll: {ilt, iat, symbols: [{slot, ordinal, hint, name}]}}`. A column is `<none>`
    where it does not apply, and the members are read out of the address table, not the lookup table."""
    if "There is an import table" not in text:
        return {}
    found = {}
    dll = None
    # Each descriptor line comes *before* the `DLL Name` it belongs to, so the pair is carried across
    # the blank line in between instead of being read when it arrives.
    pending = None
    for line in text.split("There is an import table")[1].splitlines():
        named = re.match(r"\s+DLL Name: (\S+)", line)
        member = re.match(r"\s*([0-9a-fA-F]{4,8})\s+(<none>|\d+)\s+(<none>|[0-9a-fA-F]{4})\s+(\S+)", line)
        # bfd prints six columns per descriptor: its own vma, then hint table, time stamp, forwarder
        # chain, DLL name and first thunk - the last two are the lookup and address tables.
        head = re.match(r"\s*([0-9a-fA-F]{4,8})	([0-9a-fA-F]{4,8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
                        r"([0-9a-fA-F]{4,8}) ([0-9a-fA-F]{4,8})\s*$", line)
        if named:
            dll = named.group(1)
            found[dll] = {"ilt": pending[0] if pending else None,
                          "iat": pending[1] if pending else None, "symbols": []}
            pending = None
        elif head:
            pending = (int(head.group(2), 16), int(head.group(6), 16))
        elif member and dll:
            found[dll]["symbols"].append({
                "slot": int(member.group(1), 16),
                "ordinal": None if member.group(2) == "<none>" else int(member.group(2)),
                "hint": None if member.group(3) == "<none>" else int(member.group(3), 16),
                "name": None if member.group(4) == "<none>" else member.group(4),
            })
    return found


def readobj_imports(text):
    """llvm's list, in the same shape as bfd's.

    Blocks are read line by line rather than by a regex, because a file with delay imports prints
    `Import {` blocks nested inside a delay descriptor, and a non-greedy brace-to-brace match then
    stops at the first inner brace and loses the rest of the real list. Only a brace in column zero
    opens or closes a top-level block; the delay ones carry `ModuleHandle`, and this walk does not read
    that directory, so those are skipped rather than mixed in."""
    found = {}
    block = None
    for line in text.splitlines():
        if line.startswith("Import {"):
            block = []
            continue
        if block is not None and not line.startswith("}"):
            block.append(line)
            continue
        if line.startswith("}") and block is not None:
            body = chr(10).join(block)
            block = None
            # The delay descriptor is recognised by its *field*, colon and all: `GetModuleHandleW` and
            # `GetModuleHandleExA` are ordinary symbol names, and a bare substring for the word
            # "ModuleHandle" drops the whole block of the DLL that happens to import them.
            if "  ModuleHandle:" in body or "  ImportAddressTable:" in body:
                continue
            named = re.search(r"Name: (\S+)", body)
            table = re.search(r"ImportAddressTableRVA: 0x([0-9a-fA-F]+)", body)
            lookup = re.search(r"ImportLookupTableRVA: 0x([0-9a-fA-F]+)", body)
            if not named or not table:
                continue
            rows = found.setdefault(named.group(1), {
                "ilt": int(lookup.group(1), 16) if lookup else None,
                "iat": int(table.group(1), 16),
                "symbols": [],
            })
            for symbol in re.findall(r"Symbol: +(.*)", body):
                # llvm leaves the name out for an ordinal import, so the parenthesis can sit right
                # against the start of the field: `Symbol: _CorDllMain (0)` and `Symbol:  (12)`.
                hit = re.match(r"^(.*?) ?\((\d+)\)$", symbol.strip())
                name, number = (hit.group(1).strip(), int(hit.group(2))) if hit else (symbol.strip(), None)
                rows["symbols"].append({"slot": rows["iat"], "ordinal": None if name else number,
                                        "hint": number if name else None, "name": name or None})
    return found


def rows_for(found):
    out = ["imports\trva\t0x%x\tbytes\t%d\toff\t%d\tsection\t%s\tdlls\t%d\tthunks\t%d"
           % (found["rva"], found["size"], found["offset"], found["section"], len(found["dlls"]),
              sum(len(each["thunks"]) for each in found["dlls"]))]
    for each in found["dlls"]:
        out.append("import\t%s\tilt\t0x%x\tiat\t0x%x\tnames\t%s\tstamp\t%d\tforward\t%d"
                   % (each["dll"], each["ilt"], each["iat"], each["names_from"], each["stamp"],
                      each["chain"]))
        for thunk in each["thunks"]:
            if thunk["ordinal"] is not None:
                out.append("thunk\t%s\t-\tordinal\t%d\tslot\t0x%x"
                           % (each["dll"], thunk["ordinal"], thunk["slot"]))
                continue
            out.append("thunk\t%s\t%s\thint\t%d\tslot\t0x%x\tname\t0x%x"
                       % (each["dll"], thunk["name"], thunk["hint"], thunk["slot"], thunk["thunk"]))
    return out


def check(name, raw, work):
    """One file, three readings, and no probe row unless all three say the same thing."""
    home = os.path.expanduser("~").encode()
    if home in raw:
        raise SystemExit("%s: the home path leaked into the fixture" % name)
    found = walk(raw)
    # Both readers are pointed at the scratch copy, so the bytes they see are the bytes on disk.
    bfd = objdump_imports(run(["objdump", "-x", name], work))
    llvm = readobj_imports(run(["llvm-readobj", "--coff-imports", name], work))
    mine = {each["dll"]: each for each in found["dlls"]}
    if set(mine) != set(bfd) or set(mine) != set(llvm):
        raise SystemExit("%s: the DLL lists disagree: %r / %r / %r"
                         % (name, sorted(mine), sorted(bfd), sorted(llvm)))
    for dll, each in mine.items():
        for reader in (bfd[dll], llvm[dll]):
            if each["ilt"] and reader["ilt"] is not None and reader["ilt"] != each["ilt"]:
                raise SystemExit("%s %s: lookup table %#x, a reader says %#x"
                                 % (name, dll, each["ilt"], reader["ilt"]))
            if reader["iat"] != each["iat"]:
                raise SystemExit("%s %s: address table %#x, a reader says %#x"
                                 % (name, dll, each["iat"], reader["iat"]))
            if len(reader["symbols"]) != len(each["thunks"]):
                raise SystemExit("%s %s: %d thunks, a reader lists %d"
                                 % (name, dll, len(each["thunks"]), len(reader["symbols"])))
        for index, thunk in enumerate(each["thunks"]):
            for reader in (bfd[dll], llvm[dll]):
                seen = reader["symbols"][index]
                if reader is bfd and seen["slot"] != thunk["slot"]:
                    raise SystemExit("%s %s: slot %#x, bfd says %#x"
                                     % (name, dll, thunk["slot"], seen["slot"]))
                if thunk["ordinal"] is None:
                    if seen["name"] != thunk["name"] or seen["hint"] != thunk["hint"]:
                        raise SystemExit("%s %s: hint %r name %r, a reader says %r / %r"
                                         % (name, dll, thunk["hint"], thunk["name"],
                                            seen["hint"], seen["name"]))
                elif seen["ordinal"] != thunk["ordinal"] or seen["name"]:
                    raise SystemExit("%s %s: ordinal %r, a reader says %r named %r"
                                     % (name, dll, thunk["ordinal"], seen["ordinal"],
                                        seen["name"]))
    return found, rows_for(found)


def main():
    lab = bytearray(build())
    pe = headers(lab)
    imp_rva = struct.unpack_from("<I", lab, pe["dirs"] + 8)[0]
    at, _ = locate(lab, pe, imp_rva)
    # Two edits, and they are one byte apart in the file but a world apart in meaning: the first
    # descriptor's *pointer* to its lookup table, and the first *entry* behind that pointer. Zeroing the
    # pointer is the no-ILT shape; setting the high bit of the entry is an import by ordinal, and 12 is
    # not a real mscoree ordinal - it is the number this patch writes so the branch has a witness.
    ilt_rva = struct.unpack_from("<I", lab, at)[0]
    ilt_at, _ = locate(lab, pe, ilt_rva)
    ordinal = bytearray(lab)
    noilt = bytearray(lab)
    struct.pack_into("<I", ordinal, ilt_at, pe["flag"] | 12)
    struct.pack_into("<I", noilt, at, 0)
    files = {"lab.dll": bytes(lab), "ordinal.dll": bytes(ordinal), "noilt.dll": bytes(noilt)}
    work = tempfile.mkdtemp(prefix="importw")
    for name, raw in files.items():
        with open(os.path.join(work, name), "wb") as handle:
            handle.write(raw)
    probe = {}
    for name, raw in files.items():
        found, rows = check(name, raw, work)
        probe[name] = {"bytes": len(raw), "wide": found["wide"], "plus": found["plus"],
                       "dlls": found["dlls"], "rows": rows}
        for row in rows:
            print("%-12s %s" % (name, row.replace("\t", " | ")))
    for name, raw in files.items():
        with open(os.path.join(FIX, name), "wb") as handle:
            handle.write(raw)
    with open(os.path.join(FIX, "imports.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files, three readings each" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
