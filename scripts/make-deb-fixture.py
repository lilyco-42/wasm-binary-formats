#!/usr/bin/env python3
"""Build a .deb fixture for the package reader's tests, and record what went into it.

A Debian binary package is an `ar` archive with three mandated members - `debian-binary`,
`control.tar.*` and `data.tar.*` - so the fixture is assembled with Python's own `tarfile` and
`gzip` (both outside this repo, which is the point: the ar walk is checked against bytes another
implementation wrote) and a hand-written ar header, byte-exact to the classic format:

    name[16] mtime[12] uid[6] gid[6] mode[8] size[10] then the two bytes "`\\n"

Members are padded to an even offset with a single newline, the same rule `read_ar` applies.
The sizes and names that were written go next to the archive as `lab-fixture.deb.json`, so the
Rust test compares against what the generator recorded rather than against a number typed by hand.

    python scripts/make-deb-fixture.py [out_dir]      (default: test/fixtures)
"""

import glob
import gzip
import io
import json
import os
import sys
import tarfile

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)

CONTROL = (
    "Package: lab-fixture\n"
    "Version: 0.1\n"
    "Architecture: all\n"
    "Maintainer: lab <lab@example.invalid>\n"
    "Description: synthetic package for the ar and deb readers\n"
)
README = "installed by lab-fixture\n"


def tar_bytes(name: str, data: bytes, mode: int = 0o644) -> bytes:
    """One-member tar, written by Python's tarfile and then gzipped."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as book:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        info.mtime = 1_700_000_000
        info.type = tarfile.REGTYPE
        book.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), 9)


def ar_header(name: str, size: int) -> bytes:
    # The size and the numeric fields are octal text, as GNU ar writes them; decimal 221
    # in that field reads back as 0o221 = 145 and desyncs the whole archive.
    fields = (name.ljust(16).encode(), b"0".ljust(12), b"0".ljust(6), b"0".ljust(6),
              b"644".ljust(8), format(size, "o").ljust(10).encode())
    return b"".join(fields) + b"`\n"


members = [
    ("debian-binary", b"2.0\n"),
    ("control.tar.gz", tar_bytes("./control", CONTROL.encode())),
    ("data.tar.gz", tar_bytes("./usr/share/doc/lab-fixture/README", README.encode())),
]

archive = io.BytesIO()
archive.write(b"!<arch>\n")
recorded = []
for name, payload in members:
    archive.write(ar_header(name, len(payload)))
    archive.write(payload)
    if len(payload) % 2:
        archive.write(b"\n")
    recorded.append({"name": name, "size": len(payload), "padded": bool(len(payload) % 2)})
blob = archive.getvalue()

path = os.path.join(out, "lab-fixture.deb")
with open(path, "wb") as handle:
    handle.write(blob)

with open(os.path.join(out, "lab-fixture.deb.json"), "w", encoding="utf-8") as handle:
    json.dump({"bytes": len(blob), "members": recorded}, handle, indent=1, sort_keys=True)

# A plain archive with one member, so the test can prove a .deb-shaped check does not swallow
# every ar file it sees.
plain = io.BytesIO()
NL = bytes([10])
plain.write(b"!<arch>" + NL)
plain.write(ar_header("object.o", 6))
plain.write(b"hello" + NL)
with open(os.path.join(out, "plain.ar"), "wb") as handle:
    handle.write(plain.getvalue())
print("wrote plain.ar", plain.tell(), "B")

# Read the members back with the tools that wrote them: this is what the Rust test claims to see.
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(dict(members)["control.tar.gz"]))) as book:
    print("control.tar.gz holds", book.getnames())
print("wrote", path, len(blob), "B", [(r["name"], r["size"]) for r in recorded])

for stale in glob.glob(os.path.join(out, "stream.lzma")):
    print("note: leaving", stale, "(LZMA_Alone has no magika label, so nothing asserts it)")
