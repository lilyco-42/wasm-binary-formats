#!/usr/bin/env python3
"""Write Compound File Binary fixtures with three independent writers and print the rows to prove.

CFB is the container behind the whole legacy Office family: an 8-byte magic, a 512-byte header, and
three linked structures - the FAT (whose own sector list is the DIFAT), the directory of 128-byte
entries, and, for streams under 4096 bytes, a second FAT and a second stream carried inside the root
entry's data. A reader that walks those can say how a compound file is built without opening a
single record of the document inside it.

The fixtures are written by tools that are not this repository:

  * `word97.doc`  - LibreOffice, from a document python-docx wrote (Word 97 filter)
  * `excel97.xls` - xlwt, which owns its own compound-file writer
  * `wide97.xls`  - xlwt again, big enough to need two FAT sectors

and every one of them is re-read by olefile, whose numbers have to match the private walk below
before this script will emit the probe JSON. Two header details only that cross-check pins down:
offset 0x38 is `Mini Stream Size` (always 0x1000) and not a sector count, and the DIFAT starts at
0x4C - the only layout that leaves all 109 slots inside the 512-byte header.

Usage: temp/venv/Scripts/python.exe scripts/make-cfb-fixtures.py
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

import olefile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
OUT = os.path.join(ROOT, "test", "fixtures")
SOFFICE = os.environ.get(
    "SOFFICE",
    r"C:\Program Files\LibreOffice\program\soffice.exe",
)

ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
MAXREGSECT = 0xFFFFFFFA
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF
HEADER = 512
TYPES = {0: "free", 1: "storage", 2: "stream", 5: "root"}
# The names that say which document family is inside. Only names a fixture really carries go here.
HINTS = [
    (b"WordDocument", "word"),
    (b"Workbook", "excel"),
]
MAX_ENTRIES = 64


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def clean(text):
    return "".join(ch if 0x20 <= ord(ch) < 0x7F else "." for ch in text)


def name_of(raw, limit=64):
    """Directory names are UTF-16LE with a trailing length that counts the NUL."""
    length = u16(raw, 64)
    if length < 2 or length > 64:
        return ""
    return clean(raw[: length - 2].decode("utf-16-le", "replace"))


def read_header(data):
    if data[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
        raise ValueError("not a compound file")
    head = {
        "major": data[26],
        "minor": u16(data, 24),
        "order": u16(data, 28),
        "sector": 1 << u16(data, 30),
        "mini": 1 << u16(data, 32),
        "dir_sectors": u32(data, 40),
        "fat_sectors": u32(data, 44),
        "first_dir": u32(data, 48),
        "mini_stream_size": u32(data, 56),
        "first_mini_fat": u32(data, 60),
        "mini_fat_sectors": u32(data, 64),
        "first_difat": u32(data, 68),
        "difat_sectors": u32(data, 72),
    }
    head["cutoff"] = head["mini_stream_size"] if head["mini_stream_size"] else 4096
    return head


def chain(table, start, limit):
    """Follow a FAT chain the way a reader must: bounded, and a cycle has to be caught."""
    seen, at = [], start
    while True:
        if at in (ENDOFCHAIN, FREESECT):
            return seen, "end"
        if len(seen) >= limit or at >= len(table):
            return seen, "past"
        if table[at] is None or at in seen:
            return seen, "cycle"
        seen.append(at)
        at = table[at]


def read_fat(data, head, top, broken):
    """The FAT is indexed by sector number, so every DIFAT slot lands at its own position."""
    slots = [u32(data, 76 + 4 * i) for i in range(109)]
    at, hops = head["first_difat"], 0
    while at not in (ENDOFCHAIN, FREESECT) and hops < 1024:
        if at >= top:
            broken[0] += 1
            break
        base = HEADER + at * head["sector"]
        page = [u32(data, base + 4 * i) for i in range(head["sector"] // 4)]
        slots += page[:-1]
        at, hops = page[-1], hops + 1
    if at not in (ENDOFCHAIN, FREESECT):
        broken[0] += 1
    used = [s for s in slots if s != FREESECT]
    fat = [None] * (len(used) * (head["sector"] // 4) + 4)
    for pos, sector in enumerate(used):
        if sector >= top:
            broken[0] += 1
            continue
        base = HEADER + sector * head["sector"]
        for i in range(head["sector"] // 4):
            fat[pos * (head["sector"] // 4) + i] = u32(data, base + 4 * i)
    return fat, len(used)


def walk(data):
    head = read_header(data)
    ss, mss = head["sector"], head["mini"]
    top = (len(data) - HEADER) // ss
    broken = [0]
    fat, fat_sectors = read_fat(data, head, top, broken)

    dirs, why = chain(fat, head["first_dir"], 4096)
    if why != "end":
        broken[0] += 1
    dir_bytes = b"".join(data[HEADER + s * ss : HEADER + (s + 1) * ss] for s in dirs)

    mini_fat = [None] * 4
    mini_sectors = 0
    if head["first_mini_fat"] not in (ENDOFCHAIN, FREESECT):
        sectors, why = chain(fat, head["first_mini_fat"], 4096)
        if why != "end":
            broken[0] += 1
        mini_sectors = len(sectors)
        mini_fat = [None] * (len(sectors) * (ss // 4) + 4)
        for pos, sector in enumerate(sectors):
            base = HEADER + sector * ss
            for i in range(ss // 4):
                mini_fat[pos * (ss // 4) + i] = u32(data, base + 4 * i)

    count = min(len(dir_bytes) // 128, MAX_ENTRIES)
    entries = []
    for at in range(count):
        raw = dir_bytes[at * 128 : at * 128 + 128]
        entries.append(
            {
                "at": at,
                "name": name_of(raw),
                "type": raw[66],
                "child": u32(raw, 76),
                "clsid": raw[80:96],
                "start": u32(raw, 116),
                "size": struct.unpack_from("<Q", raw, 120)[0],
            }
        )
    root = entries[0] if entries and entries[0]["type"] == 5 else None

    # The one structural promise a compound file makes: no sector belongs to two owners. The chains
    # are linked lists, so sector numbers interleave freely but a repeat means the file lies.
    used = {}
    collisions = [0]

    def claim(list_, owner, space="reg"):
        # Mini sectors are a separate numbering, so keys carry which table they came from.
        for sector in list_:
            if (space, sector) in used:
                collisions[0] += 1
            used[(space, sector)] = owner

    streams = storages = free = 0
    total = 0
    hint = "-"
    chains = []
    root_row = None
    if root is not None:
        if root["size"]:
            sectors, why = chain(fat, root["start"], 8192)
            if why != "end":
                broken[0] += 1
            claim(sectors, "root")
        else:
            sectors, why = [], "empty"
        clsid = root["clsid"]
        root_row = (
            f"root\tstart\t{root['start']}\tsize\t{root['size']}\tsectors\t{len(sectors)}"
            f"\tholds\t{len(sectors) * ss}\tmini\t{root['size'] // mss}"
            f"\tclsid\t{clsid.hex().upper() if any(clsid) else '-'}"
        )
    for ent in entries[1:]:
        kind = ent["type"]
        if kind == 2:
            streams += 1
            total += ent["size"]
            bare = ent["name"].lstrip(".")
            if hint == "-":
                for needle, label in HINTS:
                    if bare == needle.decode():
                        hint = label
        elif kind == 1:
            storages += 1
            chains.append(f"storage\t{ent['at']}\t{ent['name']}\tchild\t{ent['child']}")
        elif kind == 0:
            free += 1
        else:
            broken[0] += 1
            continue
        if kind != 2 or not ent["size"]:
            continue
        if ent["size"] >= head["cutoff"]:
            sectors, why = chain(fat, ent["start"], 8192)
            size, where = ss, "regular"
            claim(sectors, ent["name"])
        else:
            sectors, why = chain(mini_fat, ent["start"], 8192)
            claim(sectors, ent["name"], "mini")
            size, where = mss, "mini"
        if why != "end":
            broken[0] += 1
        chains.append(
            f"stream\t{ent['at']}\t{ent['name']}\tsize\t{ent['size']}\tstart\t{ent['start']}"
            f"\twhere\t{where}\tsectors\t{len(sectors)}\tholds\t{len(sectors) * size}"
        )

    rows = [
        f"cfb\t{len(data)}\tbroken\t{broken[0]}\tversion\t{head['major']}.{head['minor']}"
        f"\tsector\t{ss}\tmini\t{mss}",
        f"layout\tfat\t{fat_sectors}\tdifat\t{head['difat_sectors']}\tdir\t{len(dirs)}"
        f"\tminifat\t{mini_sectors}\tsectors\t{top}",
    ]
    if root_row is not None:
        rows.append(root_row)
    rows += chains
    rows.append(
        f"inventory\tstreams\t{streams}\tstorages\t{storages}\tfree\t{free}"
        f"\tbytes\t{total}\tcollisions\t{collisions[0]}\thint\t{hint}"
    )
    broken[0] += collisions[0]
    rows[0] = f"cfb\t{len(data)}\tbroken\t{broken[0]}\tversion\t{head['major']}.{head['minor']}" \
        f"\tsector\t{ss}\tmini\t{mss}"
    rows.append("walked\tend" if broken[0] == 0 else f"stopped\tbroken\t{broken[0]}")
    return rows, head, entries


def cross_check(path, rows, head, entries):
    """olefile must see the same sectors, names and sizes the walk computed."""
    ole = olefile.OleFileIO(path)
    assert ole.sector_size == head["sector"], f"{path}: sector size"
    assert ole.mini_sector_size == head["mini"], f"{path}: mini sector size"
    assert ole.first_dir_sector == head["first_dir"], f"{path}: directory start"
    assert ole.num_fat_sectors == head["fat_sectors"], f"{path}: FAT sector count"
    seen = {}
    for stream in ole.listdir(streams=True, storages=True):
        # Stream names carry 0x01/0x05 prefixes; map them exactly like the walk does.
        name = clean("/".join(stream))
        seen[name] = ole.get_size(stream)
        got = ole.openstream(stream).read()
        assert len(got) == ole.get_size(stream), f"{name}: size vs bytes"
    by_name = {e["name"]: e["size"] for e in entries if e["type"] == 2}
    assert set(seen) == set(by_name), f"{path}: {sorted(seen)} vs {sorted(by_name)}"
    for name, size in seen.items():
        assert by_name[name] == size, f"{name}: {size} vs {by_name[name]}"
    ole.close()
    return len(seen)


def convert(source, outdir, target):
    env = dict(os.environ, HOME=tempfile.gettempdir())
    profile = "-env:UserInstallation=file:///" + os.path.join(
        tempfile.gettempdir(), "lo-cfb-profile"
    ).replace("\\", "/")
    subprocess.run(
        [SOFFICE, "--headless", "--norestore", "--invisible", profile,
         "--convert-to", target, "--outdir", outdir, source],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL,
    )
    made = os.path.join(outdir, os.path.splitext(os.path.basename(source))[0] + "." + target)
    assert os.path.exists(made), f"LibreOffice produced no {target} for {source}"
    return made


def write_sources(work):
    import docx
    import xlwt

    note = docx.Document()
    note.add_heading("Compound file probe", 0)
    note.add_paragraph("A reader of the container does not read this sentence.")
    for index in range(3):
        note.add_paragraph(f"Line {index} carries enough text to make the stream change shape.")
    docx_path = os.path.join(work, "note.docx")
    note.save(docx_path)

    # One small workbook and one that needs more than a single FAT sector: the second is what makes
    # the DIFAT-to-FAT mapping observable rather than assumed.
    book = xlwt.Workbook()
    sheet = book.add_sheet("Sheet1")
    for row in range(8):
        sheet.write(row, 0, row)
        sheet.write(row, 1, f"cell {row}")
    xls_path = os.path.join(work, "excel97.xls")
    book.save(xls_path)

    wide = xlwt.Workbook()
    for name in ("A", "B", "C"):
        sheet = wide.add_sheet(name)
        for row in range(120):
            sheet.write(row, 0, row)
            sheet.write(row, 1, f"{'cell ' * 40}{name}{row}")
    wide_path = os.path.join(work, "wide97.xls")
    wide.save(wide_path)
    return docx_path, xls_path, wide_path


def main():
    if not os.path.isdir(OUT):
        raise SystemExit(f"{OUT} missing")
    work = os.path.join(ROOT, "temp", "cfb-src")
    os.makedirs(work, exist_ok=True)
    docx_path, xls_path, wide_path = write_sources(work)

    if os.path.exists(SOFFICE):
        made = convert(docx_path, work, "doc")
        shutil.copy(made, os.path.join(OUT, "word97.doc"))
    else:
        print(f"note: {SOFFICE} not found, keeping the committed LibreOffice fixture")
    for source in (xls_path, wide_path):
        shutil.copy(source, os.path.join(OUT, os.path.basename(source)))

    probe = {}
    for label in ("word97.doc", "excel97.xls", "wide97.xls"):
        path = os.path.join(OUT, label)
        data = open(path, "rb").read()
        rows, head, entries = walk(data)
        streams = cross_check(path, rows, head, entries)
        probe[label] = {"bytes": len(data), "streams": streams, "rows": rows}
        print(f"== {label} {len(data)} bytes, {streams} streams, "
              f"{len(rows)} rows, {rows[0]}")
        for row in rows:
            print("   ", row.replace("\t", " | "))

    with open(os.path.join(OUT, "cfb.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
    print("wrote test/fixtures/cfb.probe.json for", ", ".join(sorted(probe)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
