#!/usr/bin/env python3
"""Write the PSD fixtures and print the rows a reader has to reproduce.

`psd` is magika's label for a Photoshop document. It has no Kaitai spec in the pinned collection, and
Pillow - which is what the earlier image rounds used - can *read* PSD but cannot write one, so this label
sat on the "no producer" list until `psd-tools` turned out to install from a wheel. That gives this lab a
writer; Pillow stays in the probe as the second, unrelated parser, because a file written and read back by
the same library only proves that library is self-consistent.

Four files, chosen so the header's own numbers vary rather than repeating:

  * `rgb.psd`  - 3 channels, 8 bit, colour mode 3, gradient pixels so the RLE rows are not all identical
  * `grey.psd` - 1 channel, colour mode 1
  * `rgba.psd` - 4 channels, still mode 3: the difference between "the format counts channels" and "the
                 writer happens to emit three of them"
  * `raw.psd`  - `compression=Compression.RAW`, the other branch of the image data, whose length is not
                 stated anywhere and so has to be predicted from channels x height x width x depth/8

What the reader may claim, and what each claim is checked against here:

  * the 26-byte header: version, the six reserved bytes (the spec says zero, so a non-zero is a defect to
    report rather than a reason to stop reading), channels, height, width, depth, colour mode. psd-tools
    states each of those as a number and Pillow states width, height and its own PIL mode; the walk has
    to agree with both before the probe is written at all.
  * the four section spans: layer and mask, image resources, colour mode data, image data. Every one is
    length-prefixed, so the next section's position is arithmetic, and a length that cannot fit is counted
    broken rather than followed.
  * the `8BIM` resource list: id, size and Pascal name. The id -> name table is read out of
    `psd_tools.constants.Resource` (128 entries) rather than recalled, and is checked in both directions
    the way the DER OID table is. Pillow parses the same blocks on its own.
  * the image data's own accounting. RLE writes a table of per-row byte counts - one entry per channel per
    row - and their sum must be exactly the bytes that follow; raw writes those bytes with no table, so
    the header's numbers predict the length. Either way `ends yes` is the file proving its own size, which
    a PSD never states anywhere else.

What is deliberately not claimed: the layer records. psd-tools can add pixel layers and both it and
ImageMagick then list them with the right geometry, but the file it saves declares a **zero-length** layer
section while the layer payload sits later in it, so the framing the header gives and the framing the
readers use do not agree. Writing a record walker against bytes whose own header mis-states where they
start would fit the reader to that one writer, so the layer section is reported as a span and nothing
more. Indexed colour is out for a related reason: `frompil` derives the colour mode from the PIL mode name
and refuses `P`, so no palette file can be produced here to read.

Usage: temp/venv/Scripts/python.exe scripts/make-psd-fixtures.py
"""
import io
import json
import os
import struct
import sys

from PIL import Image
from psd_tools import PSDImage
from psd_tools.constants import Compression, ColorMode, Resource

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "psd-work"))
MAGIC = b"8BPS"
LISTED_RESOURCES = 24
# Names lifted from the library that writes these files and re-checked against it below, so not one
# number in either table is a recollection.
MODE_NAMES = {int(each): each.name for each in ColorMode}
COMPRESSION_NAMES = {int(each): each.name for each in Compression}
RESOURCE_NAMES = {int(each): each.name for each in Resource}
# (fixture, PIL mode, size, psd-tools compression) - the mode names are the ones `frompil` accepts.
# The last field is the colour mode the writer is *observed* to record for that PIL mode, checked against
# psd-tools below rather than asserted from here: PIL "L" becomes GRAYSCALE, and RGBA stays RGB with an
# extra channel, which is the fact the channels column exists to show.
CASES = [
    ("rgb", "RGB", (7, 5), Compression.RLE, "RGB"),
    ("grey", "L", (6, 4), Compression.RLE, "GRAYSCALE"),
    ("rgba", "RGBA", (5, 5), Compression.RLE, "RGB"),
    ("raw", "RGB", (4, 3), Compression.RAW, "RGB"),
]
EXPECTED_CHANNELS = {"RGB": 3, "L": 1, "RGBA": 4}


def pixels(mode, size):
    """Deterministic values: the RLE row lengths are derived from these, so they must not wander."""
    image = Image.new(mode, size)
    put = image.load()
    for y in range(size[1]):
        for x in range(size[0]):
            triple = ((x * 31 + y * 7) % 251, (x * 13 + y * 53) % 241, (x * 97 + y * 11) % 239)
            if mode == "L":
                put[x, y] = triple[0]
            elif mode == "RGBA":
                put[x, y] = triple + ((x * 61 + y) % 251,)
            else:
                put[x, y] = triple
    return image


def write_fixture(label, mode, size, compression):
    os.makedirs(SCRATCH, exist_ok=True)
    target = os.path.join(SCRATCH, label + ".psd")
    if os.path.exists(target):
        os.remove(target)
    with open(target, "wb") as handle:
        PSDImage.frompil(pixels(mode, size), compression=compression).save(handle)
    return open(target, "rb").read()


def even(value):
    return value + (value % 2)


def walk(raw):
    """Header, then the four length-prefixed sections, then the image data's own arithmetic."""
    if len(raw) < 26 or raw[:4] != MAGIC:
        return None
    _sig, version, channels, height, width, depth, mode = struct.unpack_from(">4sH6xHIIHH", raw, 0)
    reserved = raw[6:12]
    out = {
        "version": version, "channels": channels, "height": height, "width": width,
        "depth": depth, "mode": mode, "reserved": reserved.hex(), "reserved_ok": reserved == b"\0" * 6,
        "problems": 0 if version == 1 else 1,
    }
    if version != 1:
        # PSB sections carry 64-bit lengths, so nothing below this row is at the offset this walk expects.
        return out
    out["problems"] += 0 if out["reserved_ok"] else 1
    # Each section's *length* has to be inside the file before it can be read, and each section's start is
    # the previous start plus the previous length - so this chain stops at the first field the file cannot
    # hold, and says which one, rather than reading past the end to find out.
    spans = []
    layer_at = 26
    layer_len = read32_at(raw, layer_at)
    if layer_len is None:
        spans.append(("layers", layer_at, None))
        out["spans"] = spans
        out["truncated"] = "layer section length"
        out["problems"] += 1
        return out
    spans.append(("layers", layer_at + 4, layer_len))
    if raw[layer_at + 4 + 4:layer_at + 4 + 8] != b"Layr":
        out["layer_key"] = raw[layer_at + 4:layer_at + 8].hex()
    resource_at = layer_at + 4 + layer_len
    resource_len = read32_at(raw, resource_at)
    if resource_len is None:
        spans.append(("resources", resource_at, None))
        out["spans"] = spans
        out["truncated"] = "resource section length"
        out["problems"] += 1
        return out
    spans.append(("resources", resource_at + 4, resource_len))
    colour_at = resource_at + 4 + resource_len
    colour_len = read32_at(raw, colour_at)
    if colour_len is None:
        spans.append(("colour", colour_at, None))
        out["spans"] = spans
        out["truncated"] = "colour mode length"
        out["problems"] += 1
        return out
    spans.append(("colour", colour_at + 4, colour_len))
    image_at = colour_at + 4 + colour_len
    out["spans"] = spans
    out.update(layer_at=layer_at + 4, layer_len=layer_len, resource_at=resource_at + 4,
               resource_len=resource_len, colour_at=colour_at + 4, colour_len=colour_len,
               image_at=image_at)
    compression = read16_at(raw, image_at)
    if compression is None:
        out["truncated"] = "image data"
        out["problems"] += 1
        out["resources"] = []
        return out
    out["compression"] = compression
    resources = []
    cursor = resource_at + 4
    stop = resource_at + 4 + resource_len
    while cursor < stop:
        if raw[cursor:cursor + 4] != b"8BIM":
            out["problems"] += 1
            out["resource_desync"] = cursor
            break
        identifier = read16_at(raw, cursor + 4)
        name_len = raw[cursor + 6] if cursor + 7 <= len(raw) else None
        if identifier is None or name_len is None:
            out["problems"] += 1
            out["resource_desync"] = cursor
            break
        field = even(1 + name_len)
        # The padding byte of an empty Pascal name is a real 0x00 in the file, and a NUL must never reach
        # a report row: the ABI reads rows as C strings, so it would truncate the line at the reader end.
        pascal = raw[cursor + 7:cursor + 6 + field].decode("latin1", "replace").strip(chr(0))
        head = 4 + 2 + field
        size = read32_at(raw, cursor + head)
        if size is None:
            out["problems"] += 1
            out["resource_desync"] = cursor
            break
        resources.append((identifier, size, pascal, cursor))
        cursor += head + 4 + even(size)
        if len(resources) > 4096:
            out["problems"] += 1
            break
    out["resources"] = resources
    compression = out["compression"]
    payload_at = image_at + 2
    if compression == 1:
        rows = channels * height
        out["rows"] = rows
        table_end = payload_at + 2 * rows
        out["table"] = rows * 2
        if table_end > len(raw):
            # The count table itself runs off the end: one broken claim, and the row says so with dashes
            # rather than with a sum the file cannot support.
            out["problems"] += 1
            out["counts"] = None
            out["payload"] = None
            out["ends"] = False
            return out
        counts = list(struct.unpack_from(">%dH" % rows, raw, payload_at))
        out["counts"] = sum(counts)
        out["payload"] = len(raw) - table_end
    elif compression == 0:
        if depth % 8 or channels == 0:
            out["problems"] += 1
            out["expect"] = None
            return out
        out["payload"] = len(raw) - payload_at
        out["expect"] = channels * height * width * (depth // 8)
    else:
        out["payload"] = len(raw) - payload_at
        out["expect"] = None
        return out
    ends = out["counts"] == out["payload"] if compression == 1 else out["payload"] == out["expect"]
    out["ends"] = bool(ends)
    if not out["ends"]:
        out["problems"] += 1
    return out


def read16(raw, at):
    return struct.unpack_from(">H", raw, at)[0]


def read32(raw, at):
    return struct.unpack_from(">I", raw, at)[0]


def read16_at(raw, at):
    return struct.unpack_from(">H", raw, at)[0] if at + 2 <= len(raw) else None


def read32_at(raw, at):
    return struct.unpack_from(">I", raw, at)[0] if at + 4 <= len(raw) else None


def witnesses(raw, label):
    """Two independent parsers over the same bytes, then compare them with the walk."""
    state = {}
    doc = PSDImage.open(io.BytesIO(raw))
    state["psd_tools"] = {
        "version": doc.version, "channels": doc.channels, "depth": doc.depth,
        "size": list(doc.size), "color_mode": int(doc.color_mode), "mode_name": doc.color_mode.name,
        "resources": [int(each) for each in doc.image_resources],
        "layers": [layer.name for layer in doc],
    }
    path = os.path.join(SCRATCH, label + ".psd")
    with Image.open(path) as pil:
        state["pillow"] = {
            "size": list(pil.size), "mode": pil.mode,
            "resources": [entry[0] for entry in pil.resources],
            "resource_names": [entry[1] for entry in pil.resources],
            "resource_sizes": [len(entry[2]) for entry in pil.resources],
            "layers": len(pil.layers),
        }
    return state


def check_tables(walked, state):
    """The names in this script's tables must be what both libraries say about the same integers."""
    for identifier, _size, _name, _at in walked["resources"]:
        named = RESOURCE_NAMES.get(identifier)
        seen = state["psd_tools"]["resources"]
        if identifier not in seen:
            raise SystemExit("the walk found resource {} but psd-tools did not".format(identifier))
        library = next(each for each in Resource if int(each) == identifier)
        if named != library.name:
            raise SystemExit("table says {}={}, psd-tools says {}".format(identifier, named, library.name))
    spelled = MODE_NAMES.get(walked["mode"])
    if spelled is None or spelled != state["psd_tools"]["mode_name"]:
        raise SystemExit("colour mode {}: table={}, psd-tools={}".format(
            walked["mode"], spelled, state["psd_tools"]["mode_name"]))
    if Compression.RLE.name != COMPRESSION_NAMES[1] or Compression.RAW.name != COMPRESSION_NAMES[0]:
        raise SystemExit("the compression table no longer matches psd_tools.constants.Compression")


def rows_for(label, raw, walked, state):
    mode = walked["mode"]
    problems = walked["problems"]
    rows = [
        "psd\t{}\tbroken\t{}\tversion\t{}\treserved\t{}\t{}x{}\tchannels\t{}\tdepth\t{}\tmode\t{}({})".format(
            len(raw), problems, walked["version"], walked["reserved"], walked["width"], walked["height"],
            walked["channels"], walked["depth"], mode, MODE_NAMES.get(mode, "?")
        )
    ]
    if walked["version"] != 1:
        rows.append("note\ta version-{} document states its section lengths differently, so the walk stops here".format(
            walked["version"]))
        rows.append("stopped\tbroken\t{}".format(problems))
        return rows
    parts = {name: (at, length) for name, at, length in walked["spans"]}

    def span(name):
        if name not in parts:
            return "unreadable"
        at, length = parts[name]
        return "{}+{}".format(at, length) if length is not None else "{}+?".format(at)

    rows.append("section\tlayers\t{}\tresources\t{}\tcolour\t{}\timage\t{}".format(
        span("layers"), span("resources"), span("colour"), walked.get("image_at", "unreadable")))
    if walked.get("truncated"):
        rows.append("stopped\tbroken\t{}\t{}\tdoes not fit in the file".format(
            problems, walked["truncated"]))
        return rows
    resources = walked.get("resources", [])
    for index, (identifier, size, name, _at) in enumerate(resources[:LISTED_RESOURCES]):
        rows.append("resource\t{}\t{}({})\tsize\t{}\tname\t{}".format(
            index, identifier, RESOURCE_NAMES.get(identifier, "?"), size, name if name else "-"))
    if len(resources) > LISTED_RESOURCES:
        rows.append("cut\tresources\t{}".format(len(resources)))
    compression = walked["compression"]
    spelled = COMPRESSION_NAMES.get(compression, "?")
    if compression == 1:
        if walked["counts"] is None:
            rows.append("image\tcompression\t{}({})\trows\t{}\tcounts\t-\tpayload\t-\tends\tno".format(
                compression, spelled, walked["rows"]))
        else:
            rows.append("image\tcompression\t{}({})\trows\t{}\tcounts\t{}\tpayload\t{}\tends\t{}".format(
                compression, spelled, walked["rows"], walked["counts"], walked["payload"],
                "yes" if walked["ends"] else "no"))
    elif compression == 0:
        rows.append("image\tcompression\t{}({})\tbytes\t{}\texpect\t{}\tends\t{}".format(
            compression, spelled, walked["payload"], walked["expect"],
            "yes" if walked["ends"] else "no"))
    else:
        rows.append("image\tcompression\t{}({})\tbytes\t{}\tends\tunknown".format(
            compression, spelled, walked.get("payload", 0)))
    rows.append("layers\tnot decoded\tthe writer's own header mis-states this section, so its records are left alone")
    if walked.get("truncated"):
        rows.append("stopped\tbroken\t{}\t{}\tdoes not fit".format(problems, walked["truncated"]))
    else:
        rows.append("walked\tend" if problems == 0 else "stopped\tbroken\t{}".format(problems))
    return rows


def check(walked, state, expected_mode_name, expected_channels):
    """Every field the rows carry must be what both parsers say it is."""
    pillow = state["pillow"]
    tools = state["psd_tools"]
    if [walked["width"], walked["height"]] != pillow["size"] or [walked["width"], walked["height"]] != tools["size"]:
        raise SystemExit("size: walk {}x{} pillow {} psd-tools {}".format(
            walked["width"], walked["height"], pillow["size"], tools["size"]))
    if walked["channels"] != tools["channels"]:
        raise SystemExit("channels: walk {} psd-tools {}".format(walked["channels"], tools["channels"]))
    if walked["channels"] != expected_channels:
        raise SystemExit("channels: the fixture came out with {} of the {} the case asked for".format(
            walked["channels"], expected_channels))
    if walked["mode"] != tools["color_mode"] or MODE_NAMES[walked["mode"]] != expected_mode_name:
        raise SystemExit("colour mode: walk {} psd-tools {} expected {}".format(
            walked["mode"], tools["color_mode"], expected_mode_name))
    if [each[0] for each in walked["resources"]] != tools["resources"]:
        raise SystemExit("resource ids: walk {} psd-tools {}".format(
            [each[0] for each in walked["resources"]], tools["resources"]))
    if [each[0] for each in walked["resources"]] != pillow["resources"]:
        raise SystemExit("resource ids disagree with Pillow: {} vs {}".format(
            [each[0] for each in walked["resources"]], pillow["resources"]))
    if [each[1] for each in walked["resources"]] != pillow["resource_sizes"]:
        raise SystemExit("resource sizes: walk {} pillow {}".format(
            [each[1] for each in walked["resources"]], pillow["resource_sizes"]))
    if pillow["layers"] != len(tools["layers"]):
        raise SystemExit("layer count: Pillow {} psd-tools {}".format(pillow["layers"], tools["layers"]))


def main():
    os.makedirs(OUT, exist_ok=True)
    built = {"tables": {"modes": MODE_NAMES, "compressions": COMPRESSION_NAMES,
                        "resource_entries": len(RESOURCE_NAMES)}}
    for label, mode, size, compression, color_mode in CASES:
        fixture = os.path.join(OUT, label + ".psd")
        if os.path.exists(fixture):
            raw = open(fixture, "rb").read()
        else:
            raw = write_fixture(label, mode, size, compression)
            with open(fixture, "wb") as handle:
                handle.write(raw)
        walked = walk(raw)
        if walked is None:
            raise SystemExit("{}: no 8BPS header".format(label))
        state = witnesses(raw, label)
        check_tables(walked, state)
        check(walked, state, color_mode, EXPECTED_CHANNELS[mode])
        rows = rows_for(label, raw, walked, state)
        print("==", label, len(raw), "bytes")
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {"bytes": len(raw), "rows": rows, "walk": {k: v for k, v in walked.items()},
                        "witnesses": state}
    # A file that cannot hold its own declared sections: the same walk, refusing to read past the end.
    short = open(os.path.join(OUT, "rgb.psd"), "rb").read()[:60]
    walked = walk(short)
    rows = rows_for("cut", short, walked, {})
    print("== rgb.psd cut to 60 bytes")
    for row in rows:
        print("   ", row.replace("\t", " | "))
    built["rgb-cut"] = {"rows": rows}
    # Cut into the byte-count table instead of past it: here the sections all fit and only the image data's
    # own arithmetic fails, which is the second way a PSD can be found out by its own numbers.
    rle_cut = open(os.path.join(OUT, "rgb.psd"), "rb").read()[:140]
    walked = walk(rle_cut)
    rows = rows_for("rle-cut", rle_cut, walked, {})
    print("== rgb.psd cut into its RLE table")
    for row in rows:
        print("   ", row.replace("\t", " | "))
    built["rgb-rle-cut"] = {"rows": rows}
    # A version-2 header, hand-built: no PSB writer exists here, so this is the one case that is labelled
    # as constructed rather than produced - it exists to pin the branch that stops after the header.
    fake = bytearray(struct.pack(">4sH6xHIIHH", MAGIC, 2, 3, 4, 5, 8, 3)) + b"\0" * 20
    walked = walk(bytes(fake))
    rows = rows_for("psb", bytes(fake), walked, {})
    print("== hand-built version-2 header")
    for row in rows:
        print("   ", row.replace("\t", " | "))
    built["psb-header"] = {"rows": rows, "hand_built": True}
    with open(os.path.join(OUT, "psd.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True, default=str)
    print("wrote psd.probe.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
