#!/usr/bin/env python3
"""Mirror of `read_bplist` in engine/src/containers.rs, in python.

    python3 tools/plist-sim.py test/fixtures/tiny.bplist
    python3 tools/plist-sim.py test/fixtures/keyed.bplist --check

The Rust side is the shipped reader; this file exists so a wrong byte-count assumption is caught
here instead of in a CI log, for two reasons:

  * `read()` produces the same tab-separated report, branch for branch, including the caps and the
    `bad`/`marker` rows, so the rows hardcoded in engine/tests/plist.rs were measured off a decoder
    that could not inherit the Rust author's mistakes;
  * `--check` rebuilds the whole object graph through that same walk and compares it, type by type,
    against CPython's `plistlib` reading of the identical bytes. KeyedArchiver graphs are where a
    wrong keys/values split would show up.

Where the two readers can differ in spelling rather than in fact, it is said out loud: each language
formats a float with its own Display/repr, so a hostile file holding 1e20 prints differently in the
two reports. No fixture depends on that.
"""

import datetime
import plistlib
import struct
import sys
import unicodedata

MAGIC = b"bplist00"
PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"
OBJECTS = 4096
SLOTS = 4096
ROWS = 4096
DEPTH = 32
EPOCH_DAYS = 11323


class Uid:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"UID({self.value})"


def be(data, at, width):
    if width is None or width < 1 or width > 8 or at + width > len(data):
        return None
    return int.from_bytes(data[at : at + width], "big")


def printable(chars):
    return "".join(
        "?" if c == "\t" or unicodedata.category(c) == "Cc" or 0xD800 <= ord(c) <= 0xDFFF else c
        for c in chars
    )


def utf16_be(payload):
    units = [struct.unpack(">H", payload[i : i + 2])[0] for i in range(0, len(payload) - 1, 2)]
    out, index = [], 0
    while index < len(units):
        unit = units[index]
        low = units[index + 1] if index + 1 < len(units) else None
        if low is not None and 0xD800 <= unit < 0xDC00 and 0xDC00 <= low < 0xE000:
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
            index += 2
        else:
            out.append("?" if 0xD800 <= unit < 0xE000 else chr(unit))
            index += 1
    return "".join(out)


def count_of(data, at, low):
    """Length or element count: the low nibble, or 0xF followed by an inline integer object."""
    if low != 0xF:
        return low, at + 1
    int_marker = data[at + 1] if at + 1 < len(data) else None
    if int_marker is None or int_marker >> 4 != 1:
        return None, at + 1
    width = 1 << (int_marker & 0xF)
    return be(data, at + 2, width), at + 2 + width


def iso(seconds):
    total = int(seconds // 1)
    days, rest = divmod(total, 86_400)
    stamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(
        days=days + EPOCH_DAYS, seconds=rest
    )
    if not 1600 <= stamp.year <= 2400:
        return None
    return stamp.strftime("%Y-%m-%d"), stamp.strftime("%H:%M:%S")


def object_row(data, at, index, ref_size, num, body_end, table_len):
    """(rows, node) for one object, branch for branch like `bp_object` in the Rust reader."""
    row = f"obj\t{index}"
    marker = data[at]
    hi, lo = marker >> 4, marker & 0xF
    if hi == 0:
        single = {0x0: "null", 0x8: "bool\tfalse", 0x9: "bool\ttrue", 0xF: "filler"}
        body = single.get(lo, f"marker\t0x{marker:02x}")
        return [f"{row}\t{body}"], None
    if hi == 1:
        width = 1 << lo
        if width > 8:
            return [f"{row}\tbad\twidth"], None
        raw = be(data, at + 1, width)
        if raw is None:
            return [f"{row}\tbad\tshort"], None
        value = raw - (1 << 64) if width == 8 and raw >= 1 << 63 else raw
        return [f"{row}\tint\t{value}\t{width}"], None
    if hi in (2, 3):
        width = 1 << lo
        if width not in (4, 8):
            return [f"{row}\tbad\twidth"], None
        if at + 1 + width > len(data):
            return [f"{row}\tbad\tshort"], None
        value = struct.unpack(">f" if width == 4 else ">d", data[at + 1 : at + 1 + width])[0]
        if hi == 2:
            return [f"{row}\treal\t{value}"], None
        stamp = iso(value)
        if stamp is None:
            return [f"{row}\tdate\t{value}"], None
        return [f"{row}\tdate\t{stamp[0]}\t{stamp[1]}"], None
    if hi in (4, 5, 6):
        length, after = count_of(data, at, lo)
        if length is None:
            return [f"{row}\tbad\tcount"], None
        unit = 2 if hi == 6 else 1
        if after + length * unit > body_end:
            return [f"{row}\tbad\tshort"], None
        payload = data[after : after + length * unit]
        if hi == 4:
            hint = ("png" if payload.startswith(PNG)
                    else "jpeg" if payload.startswith(JPEG) else "bytes")
            return [f"{row}\tdata\t{length}\t{hint}"], None
        if hi == 5:
            return [f"{row}\tascii\t{length}\t{printable(payload.decode('latin-1'))}"], None
        return [f"{row}\tutf16\t{length}\t{printable(utf16_be(payload))}"], None
    if hi == 8:
        raw = be(data, at + 1, lo + 1)
        if raw is None:
            return [f"{row}\tbad\tshort"], None
        return [f"{row}\tuid\t{raw}"], None
    if hi in (0xA, 0xD):
        count, after = count_of(data, at, lo)
        if count is None:
            return [f"{row}\tbad\tcount"], None
        is_dict = hi == 0xD
        kind = "dict" if is_dict else "array"
        wide = "wide" if lo == 0xF else "narrow"
        rows = [f"{row}\t{kind}\t{count}\t{wide}"]
        slots = count * (2 if is_dict else 1)
        if slots > SLOTS or after > body_end:
            return rows, None
        refs, broken = [], 0
        for slot in range(slots):
            ref = be(data, after + slot * ref_size, ref_size)
            if ref is not None and ref < num and ref < table_len:
                refs.append((slot, ref))
            else:
                broken += 1
        if broken:
            rows.append(f"{row}\tbad\trefs\t{broken}")
        return rows, (is_dict, count, refs)
    return [f"{row}\tmarker\t0x{marker:02x}"], None


def trailer(data):
    """What the last 32 bytes claim, or None when they do not claim a readable file."""
    if len(data) < 40 or data[:8] != MAGIC:
        return None
    tail = data[-32:]
    offset_size, ref_size = tail[6], tail[7]
    if not 1 <= offset_size <= 8 or not 1 <= ref_size <= 8:
        return None
    num, top, table_at = struct.unpack(">QQQ", tail[8:32])
    table_end = table_at + num * offset_size
    return offset_size, ref_size, num, top, table_at, table_end, table_end + 32


def offsets_of(data, frame):
    offset_size, _, num, _, table_at, _, _ = frame
    body_end = len(data) - 32
    offsets, bad = [], 0
    for index in range(min(num, OBJECTS)):
        value = be(data, table_at + index * offset_size, offset_size)
        if value is None or value < 8 or value >= body_end:
            bad += 1
            offsets.append(None)
        else:
            offsets.append(value)
    return offsets, bad


def read(data):
    frame = trailer(data)
    if frame is None:
        return None
    offset_size, ref_size, num, top, table_at, table_end, declared = frame
    body_end = len(data) - 32
    rows = [
        f"bplist\t{declared}\t{len(data)}\t{num}\t{top}",
        f"trailer\t{offset_size}\t{ref_size}\t{table_at}\t{table_end}",
    ]
    offsets, bad_offsets = offsets_of(data, frame)
    pairs = [(a, b) for a, b in zip(offsets, offsets[1:]) if a is not None and b is not None]

    nodes, edges = [None] * len(offsets), []
    emitted, unresolved, stopped = 0, 0, False
    for index, at in enumerate(offsets):
        if len(rows) >= ROWS:
            stopped = True
            break
        if at is None:
            rows.append(f"obj\t{index}\tbad\toffset")
            continue
        found, node = object_row(data, at, index, ref_size, num, body_end, len(offsets))
        rows.extend(found)
        if node is None:
            continue
        is_dict, count, refs = node
        for slot, ref in refs:
            if len(edges) >= ROWS:
                stopped = True
                break
            if offsets[ref] is None:
                unresolved += 1
                continue
            role = "element" if not is_dict else ("key" if slot < count else "value")
            edges.append(f"child\t{index}\t{slot}\t{ref}\t{role}")
            emitted += 1
        nodes[index] = node
    rows.extend(edges)
    rows.append(f"edges\t{emitted}\tunresolved\t{unresolved}")

    # An object reached twice is sharing, which KeyedArchiver graphs do constantly; only a reference
    # back to something on the current path is a cycle.
    seen, path = set(), []
    depth_of, cycles = [0], [0]

    def branch(index, depth):
        if index in path:
            cycles[0] += 1
            return
        if depth > depth_of[0]:
            depth_of[0] = depth
        if index in seen:
            return
        seen.add(index)
        if depth >= DEPTH:
            return
        path.append(index)
        node = nodes[index]
        if node is not None:
            for _, ref in node[2]:
                branch(ref, depth + 1)
        path.pop()

    if top < len(offsets):
        branch(top, 1)
    rows.append(f"reach\t{len(seen)}\tdepth\t{depth_of[0]}\tcycles\t{cycles[0]}")
    rows.append(
        f"offsets\t{len(offsets) - bad_offsets}"
        f"\tstrictly_increasing\t{1 if all(b > a for a, b in pairs) else 0}"
    )
    rows.append(f"stopped\t{1 if stopped else 0}")
    if declared == len(data):
        rows.append("walked\tend")
    return rows


def decode(data):
    """The same table and markers turned back into python values, for `--check`."""
    frame = trailer(data)
    if frame is None:
        raise ValueError("not a bplist00 file this walk can take")
    _, ref_size, _, top, _, _, _ = frame
    offsets, _ = offsets_of(data, frame)

    def value(index):
        at = offsets[index]
        if at is None:
            raise ValueError(f"object {index} has no offset inside the file")
        marker = data[at]
        hi, lo = marker >> 4, marker & 0xF
        if hi == 0:
            return {0x0: None, 0x8: False, 0x9: True}.get(lo, ("filler", lo))
        if hi == 1:
            width = 1 << lo
            raw = be(data, at + 1, width)
            if raw is None:
                raise ValueError(f"object {index} integer does not fit")
            return raw - (1 << 64) if width == 8 and raw >= 1 << 63 else raw
        if hi == 2:
            width = 1 << lo
            return struct.unpack(">f" if width == 4 else ">d", data[at + 1 : at + 1 + width])[0]
        if hi == 3:
            seconds = struct.unpack(">d", data[at + 1 : at + 9])[0]
            days, rest = divmod(int(seconds // 1), 86_400)
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(
                days=days + EPOCH_DAYS, seconds=rest
            )
        if hi in (4, 5, 6):
            length, after = count_of(data, at, lo)
            unit = 2 if hi == 6 else 1
            payload = data[after : after + length * unit]
            if hi == 4:
                return payload
            return utf16_be(payload) if hi == 6 else payload.decode("latin-1")
        if hi == 8:
            return Uid(be(data, at + 1, lo + 1))
        if hi in (0xA, 0xD):
            count, after = count_of(data, at, lo)
            slots = count * (2 if hi == 0xD else 1)
            if slots > SLOTS:
                raise ValueError(f"object {index} claims {slots} slots")
            refs = [be(data, after + slot * ref_size, ref_size) for slot in range(slots)]
            if hi == 0xA:
                return [value(ref) for ref in refs]
            half = len(refs) // 2
            return {value(refs[slot]): value(refs[slot + half]) for slot in range(half)}
        return ("marker", marker)

    return value(top)


def norm(value):
    """Type-tagged, order-insensitive form, so the comparison cannot pass by coincidence."""
    if isinstance(value, Uid):
        return ("uid", value.value)
    if isinstance(value, plistlib.UID):
        return ("uid", int(value))
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, list):
        return ("list", [norm(item) for item in value])
    if isinstance(value, dict):
        return ("dict", sorted(norm(k) + norm(v) for k, v in value.items()))
    return (type(value).__name__, value)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    data = open(sys.argv[1], "rb").read()
    rows = read(data)
    if rows is None:
        print("not a bplist00 file this walk can take")
        return 1
    print("\n".join(rows))
    if "--check" in sys.argv[2:]:
        mine = norm(decode(data))
        theirs = norm(plistlib.loads(data))
        if mine != theirs:
            print(f"MISMATCH\n  walk:     {mine}\n  plistlib: {theirs}", file=sys.stderr)
            return 3
        print(f"walk and plistlib agree: {len(data)} bytes, {len(rows)} rows", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
