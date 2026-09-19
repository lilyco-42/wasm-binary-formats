#!/usr/bin/env python3
"""Structure fixtures for the generated-reader assertions (test/kaitai_structures.test.mjs).

Two kinds of file are produced here, deliberately kept apart because they are not equally strong
evidence:

* From a tool this repo does not control - `javac` (OpenJDK) writes `tiny.class`, and `ffmpeg`
  muxes `tiny-id3v23.mp3` with `-id3v2_version 3` so the tag is version 2.3 rather than the 2.4 the
  mp3 muxer defaults to. Reading those back proves the reader agrees with a real writer.
* Written straight from the published layout with `struct`, in the same tier as the hand-built
  image fixtures. These assert structure - counts, identifiers, terminator bytes - and the script
  asserts the byte counts too, so a length field cannot quietly stop matching its payload.

    python scripts/make-structure-fixtures.py [out_dir]     (default: test/fixtures)
"""

import os
import shutil
import struct
import subprocess
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)


def write(name: str, payload: bytes) -> None:
    path = os.path.join(out, name)
    with open(path, "wb") as handle:
        handle.write(payload)
    print("made", name, len(payload), "B")


def cstring(value: str) -> bytes:
    return value.encode() + b"\x00"


# --- Standard MIDI file: one track, note on, note off, end of track ---------------------------
events = bytes(
    [0x00, 0x90, 0x3C, 0x64]        # delta 0, note on  ch0, middle C, velocity 100
    + [0x60, 0x80, 0x3C, 0x40]      # delta 96, note off
    + [0x00, 0xFF, 0x2F, 0x00]      # end of track meta event
)
track = b"MTrk" + struct.pack(">I", len(events)) + events
assert len(events) == 12
write("tiny.mid", b"MThd" + struct.pack(">IHHH", 6, 1, 1, 480) + track)

# --- pcap: global header plus one DLT_RAW record ------------------------------------------------
# The 24-byte magic/version/snaplen header is '<IHHIiii' by name but is written here as one pack
# call, and the payload has to be eight bytes to match what the test asserts - the first version of
# this line produced seven and the reader correctly reported seven.
payload = bytes([0x45, 0x00, 0x00, 0x18]) + b"\x11\x22\x33\x44"
header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
assert len(header) == 24
record = struct.pack("<IIII", 1_700_000_000, 123_456, len(payload), len(payload)) + payload
assert len(record) == 16 + 8, "the per-packet header is 16 bytes"
write("tiny.pcap", header + record)

# --- BSON: int32, utf8 string, int64, then the document terminator -----------------------------
# The element count in a string's int32 includes its own NUL, and the document length counts
# itself plus every element plus the terminator. Both were wrong the first time this was written,
# and the reader rejected the file - which is the point of generating it in a script.
elements = (
    b"\x10" + cstring("n") + struct.pack("<i", 7)
    + b"\x02" + cstring("s") + struct.pack("<i", len(b"ok\x00")) + b"ok\x00"
    + b"\x12" + cstring("big") + struct.pack("<q", 2 ** 40)
    + b"\x00"
)
body = struct.pack("<i", len(elements) + 4) + elements
assert len(body) == struct.unpack("<i", body[:4])[0]
write("tiny.bson", body)

# --- MessagePack: fixmap of three pairs --------------------------------------------------------
packed = (
    b"\x83"                          # fixmap, 3 pairs
    + b"\xa1n" + b"\x7f"             # "n" => positive fixint 127
    + b"\xa1s" + b"\xa3msg"          # "s" => fixstr "msg"
    + b"\xa1f" + b"\xe1"             # "f" => negative fixint -30
)
write("tiny.msgpack", packed)

# --- From other tools, when they are installed -------------------------------------------------
javac = shutil.which("javac")
if javac:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="fixture-javac-") as work:
        source = os.path.join(work, "Tiny.java")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write(
                "public class Tiny { public static void main(String[] a) { System.out.println(1); } }\n"
            )
        subprocess.run([javac, "-d", work, source], check=True)
        with open(os.path.join(work, "Tiny.class"), "rb") as handle:
            write("tiny.class", handle.read())
else:
    print("skipped: tiny.class (no javac on PATH)")

ffmpeg = shutil.which("ffmpeg")
if ffmpeg:
    subprocess.run(
        [
            ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
            "-f", "lavfi", "-i", "sine=frequency=440:duration=0.2",
            "-c:a", "libmp3lame", "-b:a", "32k",
            "-metadata", "title=Lab fixture", "-id3v2_version", "3",
            os.path.join(out, "tiny-id3v23.mp3"),
        ],
        check=True,
    )
    print("made tiny-id3v23.mp3")
else:
    print("skipped: tiny-id3v23.mp3 (no ffmpeg on PATH)")
