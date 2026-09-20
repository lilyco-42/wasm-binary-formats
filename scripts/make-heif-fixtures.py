#!/usr/bin/env python3
"""Write HEIF fixtures with pillow-heif (libheif) and print the report a reader has to reproduce.

HEIF is ISO base media: a box list, big-endian sizes, and a `meta` box full of item descriptions.
Two things make it worth its own reader rather than the existing BMFF walk:

  * `ftyp` carries a brand, not a meaning - `heic`/`mif1` for HEIF, and the same container carries
    AVIF - so the reader has to name the brand it saw rather than assume one;
  * the *coded* size and the *visible* size are different numbers. libheif codes in whole blocks, so
    the 23x17 image below is coded 64x64 in `ispe` and cropped to 23x17 by `clap`, whose values are
    unsigned/signed rationals. A reader that reports `ispe` prints a size the picture does not have.

Every field the report shows is checked against what pillow-heif's own reader reports for the same
bytes (`size`, `bit_depth`, `chroma`, the `nclx` colour primaries/transfer/matrix/range), so the
numbers are the writer's, not a reading of the specification.

Usage: temp/venv/Scripts/python.exe scripts/make-heif-fixtures.py
"""
import json
import os
import struct

import pillow_heif
from PIL import Image

pillow_heif.register_heif_opener()

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
CONTAINERS = {"meta": 4, "iprp": 0, "ipco": 0, "iinf": 6}
BRANDS_OK = (b"heic", b"heix", b"heim", b"heis", b"mif1", b"avif", b"avis", b"hevc", b"av01")


def be(data, start, stop):
    return int.from_bytes(data[start:stop], "big")


def walk(data, start, stop, out, depth=0):
    """Box list, with the fields this reader names. A bad size stops the walk and says so."""
    at = start
    broken = 0
    while at + 8 <= stop:
        size = be(data, at, at + 4)
        kind = data[at + 4 : at + 8]
        head = 8
        if size == 1:
            if at + 16 > stop:
                return broken + 1
            size = be(data, at + 8, at + 16)
            head = 16
        elif size == 0:
            size = stop - at
        if size < head or at + size > stop:
            return broken + 1
        body = data[at + head : at + size]
        text = kind.decode("latin-1")
        out.append({"kind": text, "at": at, "size": size, "head": head, "depth": depth})
        if text == "ftyp":
            out[-1]["major"] = body[:4].decode("latin-1")
            out[-1]["minor"] = be(data, at + head + 4, at + head + 8)
            out[-1]["compat"] = [body[i : i + 4].decode("latin-1", "replace") for i in range(8, len(body) - 3, 4)]
        elif text == "hdlr":
            out[-1]["handler"] = body[8:12].decode("latin-1", "replace")
        elif text == "ispe":
            out[-1]["w"] = be(data, at + head + 4, at + head + 8)
            out[-1]["h"] = be(data, at + head + 8, at + head + 12)
        elif text == "clap":
            fields = [struct.unpack_from(">i", body, 4 * (i % 2) + 4 * (i // 2) * 2)[0] for i in range(0)]
            nums = [struct.unpack_from(">i", body, 4 * i)[0] for i in range(min(8, len(body) // 4))]
            out[-1]["clap"] = nums
        elif text == "pixi":
            out[-1]["channels"] = body[4] if body else 0
            out[-1]["depths"] = list(body[5 : 5 + (body[4] if body else 0)])
        elif text == "colr":
            if body[:4] == b"nclx":
                out[-1]["colour"] = {
                    "primaries": struct.unpack_from(">H", body, 4)[0],
                    "transfer": struct.unpack_from(">H", body, 6)[0],
                    "matrix": struct.unpack_from(">H", body, 8)[0],
                    "range": body[10] >> 7,
                }
            else:
                out[-1]["colour_flavour"] = body[:4].decode("latin-1", "replace")
        elif text == "pitm":
            out[-1]["primary"] = struct.unpack_from(">H", body, 4)[0] if body[0] == 0 else struct.unpack_from(">I", body, 4)[0]
        elif text == "iinf":
            out[-1]["count"] = struct.unpack_from(">H", body, 4)[0] if body[0] == 0 else body[4]
        elif text == "infe":
            out[-1]["item_type"] = body[4:8].decode("latin-1", "replace") if len(body) > 7 else ""
        elif text == "mdat":
            out[-1]["payload"] = len(body)
        if text in CONTAINERS:
            broken += walk(data, at + head + CONTAINERS[text], at + size, out, depth + 1)
        at += size
    return broken + (0 if at == stop else 1)


def report(data):
    boxes = []
    broken = walk(data, 0, len(data), boxes)
    kinds = {b["kind"]: b for b in boxes if b.get("major") or b.get("handler") or b.get("w") or b.get("count") is not None or b.get("primary") is not None}
    ftyp = next((b for b in boxes if "major" in b), {})
    ispe = next((b for b in boxes if "w" in b), {})
    clap = next((b for b in boxes if "clap" in b), {})
    pixi = next((b for b in boxes if "depths" in b), {})
    colr = next((b for b in boxes if "colour" in b), {})
    iinf = next((b for b in boxes if "count" in b), {})
    pitm = next((b for b in boxes if "primary" in b), {})
    hdlr = next((b for b in boxes if "handler" in b), {})
    mdat = sum(b.get("payload", 0) for b in boxes if b["kind"] == "mdat")
    rows = [
        "heif\t{size}\tboxes\t{boxes}\tbroken\t{broken}\tbrand\t{brand}".format(
            size=len(data), boxes=len(boxes), broken=broken, brand=ftyp.get("major", "?")
        ),
        "compat\t{}".format(",".join(c for c in ftyp.get("compat", []) if c.strip("\x00") == c) or "-"),
        "handler\t{}".format(hdlr.get("handler", "?")),
        "items\t{}\tprimary\t{}\tdescs\t{}".format(
            iinf.get("count", 0), pitm.get("primary", 0), len([b for b in boxes if b["kind"] == "infe"])
        ),
        "coded\t{w}x{h}".format(w=ispe.get("w", 0), h=ispe.get("h", 0)),
    ]
    if "clap" in clap:
        nums = clap["clap"]
        rows.append(
            "visible\t{num}/{den}x{hn}/{hd}".format(
                num=nums[0], den=nums[1] if len(nums) > 1 else 1, hn=nums[2] if len(nums) > 2 else 1, hd=nums[3] if len(nums) > 3 else 1
            )
        )
    if "depths" in pixi:
        rows.append("depths\t{}\tchannels\t{}".format(",".join(str(d) for d in pixi["depths"]), pixi.get("channels", 0)))
    if "colour" in colr:
        c = colr["colour"]
        rows.append(
            "colour\t{p}\ttransfer\t{t}\tmatrix\t{m}\trange\t{r}".format(
                p=c["primaries"], t=c["transfer"], m=c["matrix"], r=c["range"]
            )
        )
    rows.append("data\t{payload}".format(payload=mdat))
    for i, b in enumerate(boxes):
        rows.append("box\t{i}\t{kind}\tat\t{at}\tsize\t{size}\tdepth\t{depth}".format(i=i, **b))
    rows.append("walked\tend" if broken == 0 else "stopped\tbroken\t{broken}".format(broken=broken))
    return rows, kinds


def witness(path):
    heif = pillow_heif.open_heif(path)
    info = dict(heif.info)
    nclx = info.get("nclx_profile") or {}
    return {
        "size": list(heif.size),
        "frames": len(heif),
        "bit_depth": info.get("bit_depth"),
        "chroma": info.get("chroma"),
        "primary": info.get("primary"),
        "mimetype": heif.mimetype,
        "colour": {
            "primaries": nclx.get("color_primaries"),
            "transfer": nclx.get("transfer_characteristics"),
            "matrix": nclx.get("matrix_coefficients"),
            "range": nclx.get("full_range_flag"),
        }
        if nclx
        else None,
    }


def check(name, data):
    """The box walk has to land on the writer's own numbers."""
    rows, _ = report(data)
    seen = witness(os.path.join(OUT, name))
    brand = data[8:12].decode("latin-1")
    assert data[4:8] == b"ftyp", f"{name}: no ftyp"
    assert brand.encode() in BRANDS_OK, f"{name}: brand {brand} outside the observed set"
    coded = next(r for r in rows if r.startswith("coded\t")).split("\t")[1]
    cw, ch = (int(v) for v in coded.split("x"))
    if (cw, ch) != tuple(seen["size"]):
        assert any(r.startswith("visible\t") for r in rows), (
            f"{name}: coded {coded} vs the writer's {seen['size']} and no clean-aperture box to explain it"
        )
    if any(r.startswith("visible\t") for r in rows):
        visible = next(r for r in rows if r.startswith("visible\t")).split("\t")[1]
        nums = [int(v.split("/")[0]) for v in visible.split("x")]
        assert list(seen["size"]) == [nums[0], nums[1]], f"{name}: clap {visible} vs {seen['size']}"
    depths = [int(v) for v in next(r for r in rows if r.startswith("depths\t")).split("\t")[1].split(",")]
    assert max(depths) == seen["bit_depth"], f"{name}: depths {depths} vs bit_depth {seen['bit_depth']}"
    assert len(depths) == 3, f"{name}: channel count"
    colour = next((r for r in rows if r.startswith("colour\t")), None)
    if seen["colour"]:
        assert colour is not None, f"{name}: the writer reports a nclx profile the walk did not find"
        found = dict(
            zip(("primaries", "transfer", "matrix", "range"), (int(colour.split("\t")[1]), int(colour.split("\t")[3]), int(colour.split("\t")[5]), int(colour.split("\t")[7])))
        )
        assert found == seen["colour"], f"{name}: colour {found} vs {seen['colour']}"
    frames = next(r for r in rows if r.startswith("items\t")).split("\t")[1]
    assert int(frames) >= seen["frames"], f"{name}: {frames} items for {seen['frames']} frames"
    return rows, seen


def save(name, images, **kwargs):
    path = os.path.join(OUT, name)
    first, *rest = images
    first.save(path, format="HEIF", **kwargs)
    if rest:
        first.save(path, format="HEIF", save_all=True, append_images=rest, **kwargs)
    data = open(path, "rb").read()
    assert data[4:8] == b"ftyp", name
    return data


def main():
    os.makedirs(OUT, exist_ok=True)
    # Small, deliberately: libheif codes in 8-pixel blocks, so an odd size has to be cropped and the
    # `clap` box becomes the only place the real picture size is written down.
    fixtures = {
        "photo.heic": save("photo.heic", [Image.new("RGB", (23, 17), (200, 30, 90))], quality=40),
        "block.heic": save("block.heic", [Image.new("RGB", (64, 64), (10, 20, 30))], quality=30),
        "seq.heic": save(
            "seq.heic",
            [
                Image.new("RGB", (32, 24), (250, 10, 10)),
                Image.new("RGB", (32, 24), (10, 250, 10)),
                Image.new("RGB", (32, 24), (10, 10, 250)),
            ],
            quality=35,
        ),
    }
    # A .heif file gets the container brand rather than `heic`, which is why the brand is reported.
    alt = os.path.join(OUT, "container.heif")
    Image.new("RGB", (18, 12), (5, 6, 7)).save(alt, format="HEIF", quality=45)
    fixtures["container.heif"] = open(alt, "rb").read()

    probes = {}
    for name, data in fixtures.items():
        rows, seen = check(name, data)
        probes[name] = {
            "bytes": len(data),
            "brand": data[8:12].decode("latin-1"),
            "rows": rows,
            "writer": seen,
        }
        print(f"== {name} {len(data)} bytes brand {data[8:12].decode()} writer {seen['size']} x{seen['frames']}")
        for row in rows:
            print('\t\t\t"' + row.replace("\t", "\\t") + '",')
    with open(os.path.join(OUT, "heif.probe.json"), "w", encoding="utf-8", newline="\n") as sink:
        json.dump(probes, sink, indent=1, sort_keys=True, ensure_ascii=False)
        sink.write("\n")
    print("wrote heif.probe.json")


main()
