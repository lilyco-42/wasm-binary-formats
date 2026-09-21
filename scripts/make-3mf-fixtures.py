"""Produce and check the 3MF fixtures - a model package written by someone else.

A .3mf is an OPC package (the same zip-and-XML framing OOXML uses) whose one required part is a mesh
document at `3D/3dmodel.model`. None of that is this repo's opinion, and four readings of each file are
made before a probe is written - two of them by code that was not written here:

    trimesh   export    ->  the bytes themselves, from a box mesh it built
    zipfile   namelist  ->  which parts exist, how each is stored, and the archive's size
    ElementTree         ->  the tree: objects, vertices, triangles, build items, metadata
    trimesh   load      ->  the mesh rebuilt from the file on disk, vertex and face counts

The rows are assembled here from ElementTree's tree and the archive's own name list, so the Rust reader
is checked against a second implementation of the same walk and not against a transcription of its own
output. `trimesh.load` is the independent witness for the two numbers a model is really about.

    temp/venv/Scripts/python.exe scripts/make-3mf-fixtures.py

`hand.3mf` is authored here and packaged by `zipfile` because trimesh cannot be made to leave the `unit`
attribute off a model, nor to cover the part by `Override` instead of `Default`, nor to spell a
relationship target without the leading slash - and those three shapes are claims the reader has to
survive. `loose.3mf` names a model part that is not in the archive, which is a refusal.
"""

import json
import os
import sys
import xml.etree.ElementTree as ET
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

MODEL = "3D/3dmodel.model"
RELS = "_rels/.rels"
TYPES = "[Content_Types].xml"
MODEL_REL_TYPE = "http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel"
MODEL_CONTENT_TYPE = "application/vnd.ms-package.3dmanufacturing-3dmodel+xml"

# The tree is walked under the local name, because the reader strips prefixes the same way:
# ElementTree hands back `{uri}vertex` where the file spells `<vertex>` or `<m:vertex>`.
def local(tag):
    return tag.rsplit("}", 1)[-1]


def children(node, name):
    return [kid for kid in node if local(kid.tag) == name]


def every(node, name):
    """Every element called `name` under `node`, at any depth - the mesh is two levels down."""
    found = [node] if local(node.tag) == name else []
    for kid in node:
        found.extend(every(kid, name))
    return found


def read_archive(path):
    with zipfile.ZipFile(path) as archive:
        names = list(archive.namelist())
        data = {name: archive.read(name) for name in names}
        stored = {name: info.compress_type for name, info in zip(names, archive.infolist())}
    return names, data, stored


def model_relationship(data):
    """The target as the package spells it, the part that resolves to, and the relationship's id.

    A leading `/` in an OPC target is absolute, so `/3D/3dmodel.model` and `3D/3dmodel.model` name the
    same part. Both spellings stay in the row so the join a reader makes is visible, not assumed.
    """
    if RELS not in data:
        return None, None, None
    root = ET.fromstring(data[RELS])
    for one in children(root, "Relationship"):
        if one.get("Type") == MODEL_REL_TYPE:
            spelled = one.get("Target", "")
            return spelled, spelled.lstrip("/"), one.get("Id", "")
    return None, None, None


def content_type(data, part):
    """How `[Content_Types].xml` covers the model part: an Override, a Default, or nothing."""
    empty = ["none", "-", "-", "-"]
    root = ET.fromstring(data[TYPES])
    for one in children(root, "Override"):
        if one.get("PartName", "").lstrip("/") == part:
            return ["Override", one.get("PartName", ""), "-", one.get("ContentType", "")]
    extension = part.rsplit(".", 1)[-1]
    for one in children(root, "Default"):
        if one.get("Extension", "").lower() == extension:
            return ["Default", "-", one.get("Extension", ""), one.get("ContentType", "")]
    return empty


def rows_of(names, data, blob, part, spelled, rel_id):
    """The rows a reader has to print, from ElementTree's tree and the archive's own name list."""
    model = ET.fromstring(data[part])
    if local(model.tag) != "model":
        raise SystemExit("the model part's root element is %s, not model" % model.tag)
    unit = model.get("unit") or "-"
    resources = children(model, "resources")
    objects = [one for group in resources for one in children(group, "object")]
    build = children(model, "build")
    items = [one for group in build for one in children(group, "item")]
    metadata = children(model, "metadata")
    totals = {
        "objects": len(objects),
        "vertices": len(every(model, "vertex")),
        "triangles": len(every(model, "triangle")),
        "build": len(items),
        "metadata": len(metadata),
    }
    kind, override, default, content = content_type(data, part)
    out = [
        "document\t3mf\t%d" % len(data[part]),
        "main_part\t%s" % part,
        "entries\t%d" % len(names),
        "archive_bytes\t%d" % len(blob),
        "has_manifest\t1",
        "rels\tspelled\t%s\tpart\t%s\tid\t%s" % (spelled or "-", part, rel_id or "-"),
        "manifest\tkind\t%s\tpartname\t%s\textension\t%s\ttype\t%s"
        % (kind, override, default, content),
        "model\tunit\t%s\tobjects\t%d\tvertices\t%d\ttriangles\t%d\tbuild\t%d\tmetadata\t%d"
        % (unit, totals["objects"], totals["vertices"], totals["triangles"], totals["build"],
           totals["metadata"]),
    ]
    listed = 0
    for one in objects:
        if listed < 8:
            listed += 1
            out.append("object\tid\t%s\tname\t%s\ttype\t%s\tvertices\t%d\ttriangles\t%d"
                       % (one.get("id") or "-", one.get("name") or "-", one.get("type") or "-",
                          len(every(one, "vertex")), len(every(one, "triangle"))))
    if totals["objects"] > listed:
        out.append("cut\tobjects\t%d\tlisted\t%d" % (totals["objects"], listed))
    return out, totals


def build_lab():
    """A real producer's file: trimesh's own export of a box, and the mesh it reads back from it."""
    import trimesh

    mesh = trimesh.creation.box(extents=(10.0, 20.0, 30.0))
    blob = mesh.export(file_type="3mf")
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    path = os.path.join(FIX, "lab.3mf")
    with open(path, "wb") as handle:
        handle.write(blob)
    back = trimesh.load(path, force="mesh")
    return len(back.vertices), len(back.faces)


HAND_MODEL = """<?xml version="1.0" encoding="UTF-8"?>
<model xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02">
  <resources>
    <object id="2" type="support">
      <mesh>
        <vertices><vertex x="0" y="0" z="0"/><vertex x="2" y="0" z="0"/></vertices>
        <triangles><triangle v1="0" v2="1" v3="0"/></triangles>
      </mesh>
    </object>
    <object id="3">
      <mesh>
        <vertices><vertex x="0" y="0" z="0"/><vertex x="0" y="3" z="0"/><vertex x="3" y="3" z="0"/></vertices>
        <triangles><triangle v1="0" v2="1" v3="2"/><triangle v1="2" v2="1" v3="0"/></triangles>
      </mesh>
    </object>
  </resources>
  <build><item objectid="3"/><item objectid="2"/></build>
  <metadata name="Title">Two parts, no unit</metadata>
</model>
"""

HAND_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/3D/3dmodel.model" ContentType="%s"/>
</Types>
""" % MODEL_CONTENT_TYPE

HAND_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rel0" Type="%s" Target="3D/3dmodel.model"/>
</Relationships>
""" % MODEL_REL_TYPE


def main():
    lab_verts, lab_faces = build_lab()
    _zip(os.path.join(FIX, "hand.3mf"),
         [(TYPES, HAND_TYPES), (RELS, HAND_RELS), (MODEL, HAND_MODEL)], zipfile.ZIP_STORED)
    _zip(os.path.join(FIX, "loose.3mf"),
         [(TYPES, HAND_TYPES.replace(MODEL, "3D/gone.model")),
          (RELS, HAND_RELS.replace('Target="3D/3dmodel.model"', 'Target="3D/gone.model"')),
          (MODEL, HAND_MODEL)], zipfile.ZIP_DEFLATED)

    files = {}
    for name in ("lab.3mf", "hand.3mf", "loose.3mf"):
        path = os.path.join(FIX, name)
        blob = open(path, "rb").read()
        names, data, stored = read_archive(path)
        spelled, part, rel_id = model_relationship(data)
        if part is None or part not in names:
            files[name] = {
                "bytes": len(blob),
                "names": names,
                "stored": stored,
                "refused": "the relationship names %s, which the archive does not hold" % (part or "-"),
                "rows": [],
            }
            continue
        rows, totals = rows_of(names, data, blob, part, spelled, rel_id)
        files[name] = {
            "bytes": len(blob),
            "names": names,
            "stored": stored,
            "model_bytes": len(data[part]),
            "tree": totals,
            "rows": rows,
        }

    hand, loose, lab = files["hand.3mf"], files["loose.3mf"], files["lab.3mf"]

    # The refusal has to be for the reason it is: the archive reads, the manifest is there, the part the
    # package points at is not.
    if loose["rows"] or MODEL not in loose["names"]:
        raise SystemExit("loose.3mf lost the parts that make its refusal mean something")

    # The three shapes trimesh cannot be made to produce are the reason hand.3mf exists at all.
    if not any(one.startswith("model\tunit\t-\t") for one in hand["rows"]):
        raise SystemExit("hand.3mf carries a unit, so the absent-unit answer is unwitnessed")
    if "object\tid\t3\tname\t-\ttype\t-\tvertices\t3\ttriangles\t2" not in hand["rows"]:
        raise SystemExit("hand.3mf lost the object with neither a name nor a type")
    if 'rels\tspelled\t3D/3dmodel.model' not in " ".join(hand["rows"]):
        raise SystemExit("hand.3mf's relationship target is no longer spelled without a leading slash")
    if not any(one.startswith("manifest\tkind\tOverride\tpartname\t/3D") for one in hand["rows"]):
        raise SystemExit("hand.3mf no longer covers the part by Override")
    parts = [one for one in hand["rows"] if one.startswith("object")]
    if sum(int(one.split("\t")[one.split("\t").index("vertices") + 1]) for one in parts) \
            != hand["tree"]["vertices"]:
        raise SystemExit("hand.3mf's per-object vertex counts do not add up to the model's")
    if hand["tree"]["metadata"] != 1 or hand["tree"]["build"] != 2 or hand["tree"]["objects"] != 2:
        raise SystemExit("hand.3mf lost its metadata, its two build items or its second object")

    # trimesh's own re-read is the witness for the two numbers that matter in a mesh.
    if (lab_verts, lab_faces) != (lab["tree"]["vertices"], lab["tree"]["triangles"]):
        raise SystemExit("trimesh re-read %s/%s from lab.3mf where ElementTree counts %s/%s"
                         % (lab_verts, lab_faces, lab["tree"]["vertices"], lab["tree"]["triangles"]))
    if lab["tree"]["objects"] != 1 or lab["tree"]["build"] != 1:
        raise SystemExit("lab.3mf is not the one-object, one-build-item package it was written as")
    if not any(one.startswith("rels\tspelled\t/3D") for one in lab["rows"]):
        raise SystemExit("lab.3mf no longer spells its target with a leading slash")
    if not any(one.startswith("manifest\tkind\tDefault\tpartname\t-\textension\tmodel")
               for one in lab["rows"]):
        raise SystemExit("lab.3mf's manifest no longer covers the part by extension")
    if not any(one.startswith("object\tid\t1\tname\tgeometry_0") for one in lab["rows"]):
        raise SystemExit("lab.3mf lost the name trimesh gives its object")

    # Both member encodings have to be in the set, or one of the two readings proves nothing about it.
    seen = set()
    for one in files.values():
        seen.update(one["stored"].values())
    for code in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        if code not in seen:
            raise SystemExit("no fixture stores a member with code %d, so that spelling is unwitnessed"
                             % code)
    for name, one in files.items():
        if not one["rows"]:
            continue
        for row in one["rows"]:
            if "\t" not in row:
                raise SystemExit("%s: a row with no tab is not a row: %r" % (name, row))

    out = {
        "model_rel_type": MODEL_REL_TYPE,
        "model_content_type": MODEL_CONTENT_TYPE,
        "trimesh_reload": {"vertices": lab_verts, "faces": lab_faces},
        "files": files,
    }
    with open(os.path.join(FIX, "3mf.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print(json.dumps({name: len(one["rows"]) for name, one in files.items()}))


def _zip(path, entries, how):
    with zipfile.ZipFile(path, "w", how) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)


if __name__ == "__main__":
    main()
