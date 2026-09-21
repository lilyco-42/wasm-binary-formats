#!/usr/bin/env python3
"""Write the 7z fixtures and print the rows a reader has to reproduce.

`sevenzip` is magika's label for `.7z`, it has no Kaitai spec, and py7zr 1.1.3 is installed here as both
producer and witness. Two archives are committed because the format has two shapes that a reader has to
tell apart before it can say anything at all:

  * `encoded.7z` - what 7-Zip and every tool on this host write. `py7zr` compresses the *header* with its
    own filter (`DEFAULT_FILTERS.ENCODED_HEADER_FILTER`, LZMA2 preset 7) no matter which filters the
    content uses, so the property tree is inside an LZMA2 stream and a reader without that decoder
    cannot reach it. The first header byte is 0x17 (kEncodedHeader).
  * `plain.7z` - `set_encoded_header_mode(False)`, which writes the property tree in the open, starting
    with 0x01 (kHeader). The names are readable in it, which is what the next round on this format is
    about; this round only establishes where the header is and whether it is the walkable kind.

What the reader *can* always do is check the format against itself, and that is what these rows carry:
the signature, the version pair, the start header's CRC over bytes 12..32, and the header block's own CRC
over the bytes `next_header_offset` points at - an offset that is **relative to the end of the 32-byte
start header**, which is how py7zr's own `SignatureHeader._read` and `self.afterheader` treat it. The
packed area between the start header and the header block is reported as a length, because that is all
the envelope states about it without descending into a stream that may be compressed. So `sevenzip` is
credited at **container level**, like `cab`, and a third case below shows the envelope refusing to
print a CRC for a header that the truncation removed.

The names are *not* in these rows. Reaching them in `plain.7z` means parsing `MainStreamsInfo` (pack
positions, folder/coder flags, unpack sizes) before `FilesInfo` is aligned, and in `encoded.7z` it means
an LZMA2 decoder first; neither is here, and the report says so rather than guessing at the tree.

Usage: temp/venv/Scripts/python.exe scripts/make-7z-fixtures.py
"""
import io
import json
import os
import struct
import sys
import zlib

import py7zr
from py7zr.archiveinfo import write_uint64

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "7z-work"))
MAGIC = b"7z\xbc\xaf\x27\x1c"
K_HEADER = 0x01
K_ENCODED_HEADER = 0x17
# The py7zr property table, read out of the library rather than recalled (py7zr/properties.py).
NAMES = {
    0x00: "End", 0x01: "Header", 0x02: "ArchiveProperties", 0x03: "AdditionalStreamsInfo",
    0x04: "MainStreamsInfo", 0x05: "FilesInfo", 0x06: "PackInfo", 0x07: "UnpackInfo",
    0x08: "SubStreamsInfo", 0x09: "Size", 0x0A: "CRC", 0x0B: "Folder", 0x0C: "CodersUnpackSize",
    0x0D: "NumUnpackStream", 0x0E: "EmptyStream", 0x0F: "EmptyFile", 0x10: "Anti", 0x11: "Name",
    0x12: "CTime", 0x13: "ATime", 0x14: "WTime", 0x15: "Attribs", 0x16: "Comments",
    0x17: "EncodedHeader", 0x18: "StartPos", 0x19: "Dummy",
}
# What the envelope cannot say, said out loud in the report instead of left for the reader to infer.
# Neither note names the codec inside an encoded header: the codec id lives *in* that stream, so the
# envelope cannot know it, even though py7zr's own default here happens to be LZMA2.
ENVELOPE_NOTE = {
    "plain": "note\tthe header is a property tree, and reaching its names needs the streams-info walk",
    "encoded": "note\tthe header is itself a compressed stream, so only the envelope is read",
}

TARGETS = [("encoded.7z", True), ("plain.7z", False)]
MEMBER = "answer.txt"
PAYLOAD = b"answer 42\n" * 8


def read_uint64(data, at):
    """The variable-length UINT64 of the 7z spec, exactly as py7zr's write_uint64 documents it."""
    first = data[at]
    if first == 0xFF:
        return int.from_bytes(data[at + 1 : at + 9], "little"), 9
    extra = 0
    mask = 0x80
    while first & mask:
        extra += 1
        mask >>= 1
        if extra > 7:
            return None, 1
    high = first & (mask - 1)
    if extra == 0:
        return high, 1
    low = int.from_bytes(data[at + 1 : at + 1 + extra], "little")
    return low + (high << (8 * extra)), 1 + extra


def check_codec():
    """Encode with py7zr and decode with the function above, over every magnitude the scheme has."""
    bad = []
    for value in (0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x20_0000, 0xFE_FFFF_FFFF, 0xFF_FFFF_FFFF,
                  0x1_00_00_00_00, 0xFFFF_FFFF_FFFF_FFFF):
        buf = io.BytesIO()
        write_uint64(buf, value)
        raw = buf.getvalue()
        got, size = read_uint64(raw, 0)
        if got != value or size != len(raw):
            bad.append((value, raw.hex(), got, size))
    if bad:
        raise SystemExit("UInt64 codec disagreement: {}".format(bad))
    return "ok"


def write_fixture(label, encoded_header):
    os.makedirs(SCRATCH, exist_ok=True)
    source = os.path.join(SCRATCH, MEMBER)
    with open(source, "wb") as handle:
        handle.write(PAYLOAD)
    target = os.path.join(SCRATCH, label)
    if os.path.exists(target):
        os.remove(target)
    archive = py7zr.SevenZipFile(target, "w", filters=[{"id": py7zr.FILTER_COPY}])
    archive.set_encoded_header_mode(encoded_header)
    archive.write(source, MEMBER)
    archive.close()
    data = open(target, "rb").read()
    listed = [(info.filename, info.uncompressed) for info in py7zr.SevenZipFile(target, "r").list()]
    py7zr.SevenZipFile(target, "r").close()
    return data, listed


def rows_for(label, data, listed):
    if data[:6] != MAGIC:
        raise SystemExit("{}: not a 7z signature".format(label))
    major, minor = data[6], data[7]
    start_crc = struct.unpack_from("<I", data, 8)[0]
    offset, size, header_crc = struct.unpack_from("<QQI", data, 12)
    computed_start = zlib.crc32(data[12:32]) & 0xFFFFFFFF
    start_ok = computed_start == start_crc
    if not start_ok:
        raise SystemExit(
            "{}: start header CRC is {:08x}, bytes 12..32 say {:08x}".format(
                label, start_crc, computed_start
            )
        )
    where = 32 + offset
    if where + size > len(data):
        raise SystemExit("{}: header {}+{} runs past {} bytes".format(label, where, size, len(data)))
    block = data[where : where + size]
    computed_header = zlib.crc32(block) & 0xFFFFFFFF
    header_ok = computed_header == header_crc
    if not header_ok:
        raise SystemExit(
            "{}: header CRC is {:08x}, its bytes say {:08x}".format(label, header_crc, computed_header)
        )
    kind = {K_HEADER: "plain", K_ENCODED_HEADER: "encoded"}.get(block[0], "unknown")
    if kind == "unknown":
        raise SystemExit("{}: header starts with {:#02x}".format(label, block[0]))
    rows = [
        "7z\t{}\tbroken\t0\tversion\t{}.{}\tpacked\t{}\theader\tat\t{}\tlen\t{}\tkind\t{}".format(
            len(data), major, minor, offset, where, size, kind
        ),
        "crc\tstart\t{:08x}\t{}\theader\t{:08x}\t{}".format(
            start_crc, "ok" if start_ok else "bad", header_crc, "ok" if header_ok else "bad"
        ),
        ENVELOPE_NOTE[kind],
        "walked\tend",
    ]
    return rows


def truncated_rows(data):
    """The same envelope read on a file whose declared header no longer fits: broken, and the reader
    has to say so rather than print a CRC over bytes it does not have."""
    major, minor = data[6], data[7]
    start_crc = struct.unpack_from("<I", data, 8)[0]
    offset, size, header_crc = struct.unpack_from("<QQI", data, 12)
    where = 32 + offset
    computed_start = zlib.crc32(data[12:32]) & 0xFFFFFFFF
    if computed_start != start_crc:
        raise SystemExit("truncated: the start header itself changed, so this is not a truncation")
    if where + size <= len(data):
        raise SystemExit("truncated: the header still fits, cut deeper")
    return [
        "7z\t{}\tbroken\t1\tversion\t{}.{}\tpacked\t{}\theader\tat\t{}\tlen\t{}\tkind\tunreadable".format(
            len(data), major, minor, offset, where, size
        ),
        "crc\tstart\t{:08x}\tok\theader\t{:08x}\tunreachable".format(start_crc, header_crc),
        "stopped\tbroken\t1",
    ]


def main():
    codec = check_codec()
    built = {"uint64_codec": codec, "property_names": {hex(int(k)): v for k, v in NAMES.items()}}
    for label, encoded in TARGETS:
        fixture = os.path.join(OUT, label)
        if os.path.exists(fixture):
            data = open(fixture, "rb").read()
            listed = [(info.filename, info.uncompressed) for info in py7zr.SevenZipFile(fixture, "r").list()]
        else:
            data, listed = write_fixture(label, encoded)
            with open(fixture, "wb") as handle:
                handle.write(data)
        rows = rows_for(label, data, listed)
        print("==", label, len(data), "bytes,", listed)
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {"bytes": len(data), "py7zr": listed, "rows": rows}
    cut = truncated_rows(open(os.path.join(OUT, "encoded.7z"), "rb").read()[:-24])
    print("== encoded.7z truncated by 24")
    for row in cut:
        print("   ", row.replace("\t", " | "))
    built["encoded-cut"] = {"rows": cut}
    with open(os.path.join(OUT, "7z.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote 7z.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
