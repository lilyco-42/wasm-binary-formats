"""Produce and check the MSF 7.00 (PDB) container fixtures.

`lld-link /DEBUG` writes a real PDB, and `llvm-pdbutil` reads one back: `--summary`
prints the superblock and the PDB stream's header fields, `--streams` prints the
stream table with each stream's blocks, and `--type-stats` counts the records in the
TPI stream. This script writes `test/fixtures/lab.pdb` from a compiled object, walks
the container with its own reading of the bytes, and refuses to write
`test/fixtures/pdb.probe.json` unless the two agree - in both directions, the same
rule `make-codeview-fixtures.py` uses for the records inside the TPI stream.

    temp/venv/Scripts/python.exe scripts/make-pdb-fixtures.py

Needs clang, lld-link and llvm-pdbutil on PATH. Compiled outside any profile: LLVM
records the linker's command line and the module's source path inside the PDB.
"""

import importlib.util
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

SOURCE = """\
/* A function whose signature and locals put types in the TPI stream, and nothing
 * else: the container's shape is what this fixture is for. `_fltused` is the symbol
 * a link without a C runtime has to supply itself once a double is in the code. */
int _fltused = 0;
struct point { int x; double y; };
enum colour { RED, GREEN };
int add(int a, int b) { struct point p; p.x = a + b; return p.x + (int) p.y; }
struct point shift(struct point p, enum colour c) { p.x += (int) c; return p; }
"""

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS" + bytes([0, 0, 0])
# The indices MSF reserves, and the label llvm-pdbutil prints for each. A stream is named by its
# position here, so the witness has to agree about the position - which is the check below.
KNOWN = {0: ("old-msf-directory", "Old MSF Directory"),
         1: ("pdb", "PDB Stream"),
         2: ("tpi", "TPI Stream"),
         3: ("dbi", "DBI Stream"),
         4: ("ipi", "IPI Stream")}
# llvm's --summary spells three of its "Has …" answers out of the streams the directory holds, so
# that is what the check below compares: a named feature *bit* of the header word would be an
# interpretation, and the first draft's guess at one failed against this witness.
PRESENT = [(1, "pdb"), (2, "tpi"), (3, "dbi"), (4, "ipi")]
SUMMARY_FLAG = {"tpi": "types", "dbi": "debug info", "ipi": "ids"}


def codeview():
    """The CodeView leaf reader from `make-codeview-fixtures.py`, so the TPI records of a PDB are
    decoded by exactly the walk whose layout was proved against an object stream."""
    spec = importlib.util.spec_from_file_location(
        "cv", os.path.join(HERE, "make-codeview-fixtures.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(cmd, cwd=None):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("%s failed: %s" % (cmd[0], proc.stderr.decode("utf-8", "replace")[:400]))
    return proc.stdout.decode("utf-8", "replace")


def u32(raw, at):
    return struct.unpack_from("<I", raw, at)[0]


def read(raw):
    """The container: superblock, the page list the superblock points at, the directory.

    What the fields hold is taken from the file agreeing with llvm-pdbutil rather than
    from a description: @44 is the directory's size in bytes, @48 and @56 hold the first
    two of its pages, and @52 names a page whose own contents list the rest - which is
    how an 18-block file puts its directory on the last page.
    """
    if raw[:len(MAGIC)] != MAGIC:
        raise SystemExit("not an MSF 7.00 file")
    out = {
        "magic": "msf 7.00",
        "page": u32(raw, 32),
        "free": u32(raw, 36),
        "blocks": u32(raw, 40),
        "dirBytes": u32(raw, 44),
        "inline": [u32(raw, 48), u32(raw, 56)],
        "listPage": u32(raw, 52),
    }
    page = out["page"]
    if page == 0 or page % 64 != 0 or page > len(raw):
        raise SystemExit("implausible page size %d" % page)
    want = (out["dirBytes"] + page - 1) // page
    listed = [each for each in out["inline"] if each]
    if len(listed) < want:
        # The superblock holds two directory page numbers itself; a directory that needs
        # more lists them at the page @52 names, starting with the first and with no count
        # field in front - which is what an 18-block file with one directory page shows.
        if not out["listPage"]:
            raise SystemExit("%d directory pages needed, %d named and no list page"
                             % (want, len(listed)))
        at = out["listPage"] * page
        listed += [u32(raw, at + 4 * n) for n in range(want - len(listed))]
    if len(listed) < want:
        raise SystemExit("the superblock names %d directory pages, %d are needed"
                         % (len(listed), want))
    out["dirPages"] = listed[:want]
    joined = b"".join(raw[p * page:(p + 1) * page] for p in out["dirPages"])[:out["dirBytes"]]
    count = u32(joined, 0)
    sizes = [u32(joined, 4 + 4 * n) for n in range(count)]
    cursor = 4 + 4 * count
    streams = []
    for index, size in enumerate(sizes):
        used = (size + page - 1) // page
        blocks = [u32(joined, cursor + 4 * n) for n in range(used)]
        cursor += 4 * used
        streams.append({"index": index, "size": size, "blocks": blocks,
                        "name": KNOWN.get(index, ("", ""))[0]})
    if cursor != len(joined):
        raise SystemExit("the directory has %d bytes left over" % (len(joined) - cursor))
    out["streams"] = streams
    out["dirTail"] = cursor
    return out


def gather(raw, container, index):
    """A stream's bytes, copied out of its blocks in order."""
    page = container["page"]
    stream = container["streams"][index]
    if not stream["blocks"] and stream["size"]:
        return b""
    out = bytearray()
    for block in stream["blocks"]:
        out += raw[block * page:(block + 1) * page]
    return bytes(out[:stream["size"]])


def pdb_header(raw, container):
    """The PDB stream: version, signature, age, the GUID as the bytes hold it, features."""
    body = gather(raw, container, 1)
    if len(body) < 32:
        raise SystemExit("the PDB stream is %d bytes" % len(body))
    version, signature, age = struct.unpack_from("<III", body, 0)
    # The GUID is the sixteen bytes after the age, and its first word repeats the signature:
    # that is how a PDB identifies the binary it belongs to, and llvm prints the same pairing.
    guid = body[12:28].hex()
    features = u32(body, 28) if len(body) >= 32 else 0
    rows = [
        "header\tpdb\tversion\t%d\tsignature\t%d\tage\t%d" % (version, signature, age),
        "guid\t%s" % guid,
        "features\t0x%x" % features,
    ]
    return rows, {"version": version, "signature": signature, "age": age,
                  "guid": guid, "features": features}


def present(container, index):
    """Whether the container's own directory holds a stream at this index with bytes in it."""
    return index < len(container["streams"]) and container["streams"][index]["size"] > 0


def tpi_header(raw, container):
    """The TPI stream's header, and the record count its own fields declare.

    llvm's --type-stats reports the same byte total, which is what ties `bytes` here to
    a witness rather than to an interpretation.
    """
    index = next((each["index"] for each in container["streams"] if each["index"] == 2), None)
    if index is None:
        return ["tpi\tabsent"], {}
    body = gather(raw, container, index)
    if len(body) < 20:
        return ["tpi\ttoo short"], {}
    version, header, first, last, total = struct.unpack_from("<IIIII", body, 0)
    rows = ["tpi\tversion\t%d\theader\t%d\ttypes\t0x%x..0x%x\tbytes\t%d"
            % (version, header, first, last, total)]
    records, walked = count_records(body[header:header + total])
    if header + total > len(body):
        rows.append("tpi\theader+records\t%d\texceeds\t%d" % (header + total, len(body)))
    else:
        rows.append("tpi\twalked\t%d\trecords\t%d" % (walked, records))
    return rows, {"version": version, "header": header, "first": first, "last": last,
                  "total": total, "records": records, "walked": walked}


def count_records(body):
    """How many records the TPI body holds and how many bytes they cover. The record count and the
    byte total are what llvm's --type-stats prints, so the header's own fields get checked against
    a witness rather than against a reading of the spec."""
    at = 0
    records = 0
    while at + 4 <= len(body):
        length = struct.unpack_from("<H", body, at)[0]
        total = length + 2
        if total < 6 or at + total > len(body):
            break
        records += 1
        at += total
    return records, at


def tpi_records(body, facts):
    """Every record of the TPI stream, decoded by the walk whose layout was proved against an object
    stream in `make-codeview-fixtures.py`: the index base and the record range come out of the TPI
    header, which is why the same reader answers both files."""
    cv = codeview()
    records = []
    at = facts["header"]
    stop = facts["header"] + facts["total"]
    index = facts["first"]
    while at + 4 <= stop:
        length, leaf = struct.unpack_from("<HH", body, at)
        if length < 4 or at + length + 2 > stop:
            break
        records.append(cv.decode(index, leaf, body[at + 4:at + 2 + length], at, length + 2))
        at += length + 2
        index += 1
    return records


def witness(work):
    text = run(["llvm-pdbutil", "dump", "--summary", "--streams", "--stream-blocks",
                "--type-stats", "--types", os.path.join(work, "lab.pdb")])
    summary = {
        "page": number(text, r"Block Size:\s*(\d+)"),
        "blocks": number(text, r"Number of blocks:\s*(\d+)"),
        "streams": number(text, r"Number of streams:\s*(\d+)"),
        "signature": number(text, r"Signature:\s*(\d+)"),
        "age": number(text, r"Age:\s*(\d+)"),
        "features": number(text, r"Features:\s*0x([0-9a-f]+)", 16),
        "types": number(text, r"Total:\s*(\d+) entries"),
        "typeBytes": number(text, r"Total:\s*\d+ entries \(\s*(\d+) bytes"),
    }
    listed = []
    for hit in re.finditer(r"Stream\s+(\d+) \(\s*(\d+) bytes\):\s*\[([^\]]*)\][\s\S]*?Blocks: \[([^\]]*)\]",
                           text):
        listed.append({
            "index": int(hit.group(1)),
            "size": int(hit.group(2)),
            "label": hit.group(3).strip(),
            "blocks": [int(each) for each in re.findall(r"\d+", hit.group(4))],
        })
    flags = dict((hit.group(1).strip().lower(), hit.group(2) == "true")
                 for hit in re.finditer(r"Has ([^:\n]+): (\w+)", text))
    return text, summary, listed, flags


def number(text, pattern, base=10):
    hit = re.search(pattern, text)
    return int(hit.group(1), base) if hit else None


def cross_check(container, rows, summary, listed, tpi):
    problems = []
    for field, mine in (("page", container["page"]), ("blocks", container["blocks"]),
                        ("streams", len(container["streams"]))):
        if summary[field] is not None and summary[field] != mine:
            problems.append("%s: ours %s, witness %s" % (field, mine, summary[field]))
    for each in container["streams"]:
        found = next((each2 for each2 in listed if each2["index"] == each["index"]), None)
        if found is None:
            problems.append("stream %d is not in the witness" % each["index"])
            continue
        if found["size"] != each["size"]:
            problems.append("stream %d: ours %d bytes, witness %d"
                            % (each["index"], each["size"], found["size"]))
        if found["blocks"] != each["blocks"]:
            problems.append("stream %d: ours blocks %s, witness %s"
                            % (each["index"], each["blocks"], found["blocks"]))
        named = KNOWN.get(each["index"], ("", ""))[1]
        if named and found["label"] != named:
            problems.append("stream %d: witness calls it %r, we call it %r"
                            % (each["index"], found["label"], named))
    for extra in listed:
        if not any(each["index"] == extra["index"] for each in container["streams"]):
            problems.append("the witness lists stream %d, we do not" % extra["index"])
    return problems


def build():
    work = tempfile_dir()
    with open(os.path.join(work, "lab.c"), "w", encoding="ascii", newline="\n") as handle:
        handle.write(SOURCE)
    run(["clang", "-gcodeview", "-c", "lab.c", "-o", "lab.obj"], cwd=work)
    run(["lld-link", "/DEBUG", "/OUT:lab.dll", "/DLL", "/NOENTRY", "/MACHINE:X64", "lab.obj"],
        cwd=work)
    source = os.path.join(work, "lab.pdb")
    raw = open(source, "rb").read()
    secret = os.path.expanduser("~").encode()
    if secret in raw:
        raise SystemExit("the PDB carries a local path; do not commit it")
    return raw, work


def tempfile_dir():
    import tempfile
    root = os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), os.sep, "tmp")
    os.makedirs(root, exist_ok=True)
    return tempfile.mkdtemp(prefix="pdbfix", dir=root)


def main():
    raw, work = build()
    container = read(raw)
    header, headerFacts = pdb_header(raw, container)
    tpis, tpiFacts = tpi_header(raw, container)
    text, summary, listed, flags = witness(work)
    problems = cross_check(container, header, summary, listed, headerFacts)
    rows = [
        "container\tpdb\t%s\tblock\t%d\tpages\t%d\tfree\t%d\tstreams\t%d\tdir\t%d@%s"
        % (container["magic"].split()[-1], container["page"], container["blocks"],
           container["free"], len(container["streams"]), container["dirBytes"],
           ",".join(str(each) for each in container["dirPages"])),
    ]
    for each in container["streams"]:
        rows.append("stream\t%d\tsize\t%d\tblocks\t%d%s"
                    % (each["index"], each["size"], len(each["blocks"]),
                       "\tname\t%s" % KNOWN[each["index"]][0] if each["index"] in KNOWN else ""))
    rows += header + tpis
    for index, name in PRESENT:
        rows.append("has\t%s\t%s" % (name, "yes" if present(container, index) else "no"))
    checks = {
        "page": container["page"], "blocks": container["blocks"],
        "streams": len(container["streams"]), "signature": headerFacts["signature"],
        "age": headerFacts["age"],
        "typeBytes": tpiFacts.get("total"), "types": tpiFacts.get("records"),
    }
    for field, mine in checks.items():
        if summary.get(field) is None or mine is None:
            continue
        if summary[field] != mine:
            problems.append("%s: ours %s, witness %s" % (field, mine, summary[field]))
    # llvm's "Has Types / Has IDs / Has Debug Info" answers are about streams, not about the
    # feature word, so compare them with the directory's own contents.
    for name, flag in SUMMARY_FLAG.items():
        if flag not in flags:
            continue
        index = [each[0] for each in PRESENT if each[1] == name][0]
        mine = present(container, index)
        if mine != flags[flag]:
            problems.append("has %s: ours %s, witness %s" % (name, mine, flags[flag]))
    # The records inside the TPI stream, decoded by the object-stream walk and checked against the
    # same witness: this is the row set the analysis module has to reproduce for a .pdb.
    cv = codeview()
    trecords = tpi_records(gather(raw, container, 2), tpiFacts)
    tprimitives = cv.primitives_from(text)
    typerows = cv.rows_for(trecords, tprimitives, tpiFacts["header"])
    problems += cv.cross_check(trecords, text.splitlines())
    if problems:
        raise SystemExit("our reading and llvm-pdbutil disagree:\n  " + "\n  ".join(problems[:8]))
    shutil.copyfile(os.path.join(work, "lab.pdb"), os.path.join(FIX, "lab.pdb"))
    probe = {
        "lab.pdb": {
            "bytes": os.path.getsize(os.path.join(FIX, "lab.pdb")),
            "rows": rows,
            "types": {"records": len(trecords), "primitives": dict(
                (("0x%x" % k), v) for k, v in sorted(tprimitives.items())),
                "rows": typerows},
            "witness": [line for line in text.splitlines() if line.strip()],
        }
    }
    with open(os.path.join(FIX, "pdb.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print("%s: %d bytes, %d streams, checks agree with llvm-pdbutil"
          % (os.path.join(FIX, "lab.pdb"), probe["lab.pdb"]["bytes"],
             len(container["streams"])))
    for row in rows:
        print(row.replace("\t", " | "))


if __name__ == "__main__":
    main()
