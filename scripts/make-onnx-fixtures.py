#!/usr/bin/env python3
"""Write ONNX fixtures with the onnx package and print the report a reader has to reproduce.

An .onnx file is one protobuf message - `ModelProto` - with no magic and no framing: a tag varint
carrying a field number and a wire type, then a value that is a varint, a fixed 32/64-bit slot, or a
length-delimited region. The wire does *not* say whether such a region is a nested message or a plain
string, so nothing can be walked generically: the reader has to know which fields are messages and read
this schema level by level, which is why the mirror below is a cursor plus one typed accessor per
message rather than a generic tree printer - and the Rust reader follows the same shape.

Two things are therefore pinned against a second implementation (`onnx.load` of the same bytes):
  * the field numbers, which are not what a recollection supplies - `producer_name` is 2 not 3, `graph`
    is 7 not 8, `opset_import` is 8 - and each one is kept only if the value it yields equals the
    attribute onnx parsed;
  * completeness: `ModelProto.ByteSize()` equals the file length for these files, so the top-level walk
    is asserted to consume every byte.

Shapes are the other trap. A dimension is `dim_value`, or a named `dim_param`, or *neither* (a `None`
axis writes an unset dimension), so the report keeps those three apart instead of printing zero for an
unknown.
"""
import json
import os

import numpy as np
import onnx
import onnx.helper as helper
from onnx import TensorProto

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
MAX_ITEMS = 128


def varint(b, at, stop):
    result = 0
    shift = 0
    while at < stop:
        byte = b[at]
        at += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, at
        shift += 7
        if shift > 63:
            return None, at
    return None, at


class Msg:
    """One protobuf message read from a byte range. Unknown wire types and overruns set `bad`."""

    def __init__(self, data, start=0, stop=None):
        self.data = data
        self.stop = len(data) if stop is None else stop
        self.values = {}
        self.bad = 0
        self.at = self._read(start)

    def _read(self, start):
        at = start
        while at < self.stop:
            tag, at = varint(self.data, at, self.stop)
            if tag is None:
                self.bad += 1
                return at
            field, wire = tag >> 3, tag & 0x07
            if field == 0:
                self.bad += 1
                return at
            slot = self.values.setdefault(field, [])
            if wire == 0:
                value, at = varint(self.data, at, self.stop)
                if value is None:
                    self.bad += 1
                    return at
                slot.append(value)
            elif wire == 2:
                size, at = varint(self.data, at, self.stop)
                if size is None or at + size > self.stop:
                    self.bad += 1
                    return at
                slot.append(self.data[at : at + size])
                at += size
            elif wire == 5:
                if at + 4 > self.stop:
                    self.bad += 1
                    return at
                slot.append(int.from_bytes(self.data[at : at + 4], "little"))
                at += 4
            elif wire == 1:
                if at + 8 > self.stop:
                    self.bad += 1
                    return at
                slot.append(int.from_bytes(self.data[at : at + 8], "little"))
                at += 8
            else:
                self.bad += 1
                return at
        return at

    def scalars(self, field):
        return [v for v in self.values.get(field, []) if isinstance(v, int)]

    def blobs(self, field):
        return [v for v in self.values.get(field, []) if isinstance(v, (bytes, bytearray))]

    def one(self, field):
        values = self.values.get(field)
        return values[0] if values else None

    def text(self, field):
        value = self.one(field)
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else ""

    def count(self, field):
        return len(self.values.get(field, []))

    def sub(self, field):
        children = self.subs(field)
        return children[0] if children else Msg(b"")

    def subs(self, field):
        return [Msg(blob) for blob in self.blobs(field)[:MAX_ITEMS]]

    def packed(self, field):
        """A packed repeated scalar: one or more regions of concatenated varints."""
        out = []
        for blob in self.blobs(field):
            at = 0
            while at < len(blob):
                value, at = varint(blob, at, len(blob))
                if value is None:
                    return out
                out.append(value)
        return out

    def repeated(self, field, width=None):
        """Every numeric element of a repeated field, whichever of the two legal encodings the writer
        used: unpacked carries one tag per value, packed puts them in one region - and a packed float
        or double region is fixed-width words, not varints."""
        out = []
        for value in self.scalars(field):
            out.append(value)
        for blob in self.blobs(field):
            if width in (4, 8):
                out.extend(
                    int.from_bytes(blob[i : i + width], "little")
                    for i in range(0, len(blob) - width + 1, width)
                )
            else:
                at = 0
                while at < len(blob):
                    value, at = varint(blob, at, len(blob))
                    if value is None:
                        return out
                    out.append(value)
        return out


# Field numbers as the fixtures actually write them. `initializer` is 5 and `input`/`output` are 11/12,
# which is not what a recollection of GraphProto gives (3, 5, 6) - the numbers below are each justified
# in check() by byte-for-byte equality against `onnx`'s own serialization of that sub-message.
MODEL = {"ir_version": 1, "producer_name": 2, "producer_version": 3, "domain": 4, "model_version": 5, "doc_string": 6, "graph": 7, "opset": 8}
OPSET = {"domain": 1, "version": 2}
GRAPH = {"node": 1, "name": 2, "initializer": 5, "input": 11, "output": 12}
NODE = {"input": 1, "output": 2, "name": 3, "op_type": 4}
# TensorProto's payload fields are where a recollection goes wrong: `float_data` is 4 (not 5),
# `int32_data` 5, `string_data` 6 (not 12, which is `doc_string`), `int64_data` 7. The numbers below
# are the ones onnx's own descriptor reports *and* the ones the byte walk has to agree with, which
# check() verifies per tensor.
TENSOR = {"dims": 1, "data_type": 2, "float_data": 4, "int32_data": 5, "string_data": 6, "int64_data": 7, "name": 8, "raw_data": 9, "double_data": 10, "uint64_data": 11, "data_location": 14}
VALUE_INFO = {"name": 1, "type": 2}
TYPE_PROTO = {"tensor": 1}
TENSOR_TYPE = {"elem_type": 1, "shape": 2}
SHAPE = {"dim": 1}
DIM = {"value": 1, "param": 2}

# Element types, collected from files the writer was told to make each type - never recalled.
ELEMENT_NAMES = {}


def element_name(ordinal):
    # Lower case, because that is the form the reader prints; the assert in main() checks this table
    # against the name onnx itself gives the type.
    return ELEMENT_NAMES.get(ordinal, "unnamed").lower()


def dims_of(shape):
    out = []
    for dim in shape.subs(SHAPE["dim"]):
        if dim.one(DIM["value"]) is not None:
            out.append("d{}".format(dim.one(DIM["value"])))
        elif dim.one(DIM["param"]) is not None:
            out.append("p{}".format(dim.text(DIM["param"])))
        else:
            out.append("u")
    return out


def type_of(info):
    """A graph input or output: its name, element type and dimensions."""
    tensor = info.sub(VALUE_INFO["type"]).sub(TYPE_PROTO["tensor"])
    kind = tensor.one(TENSOR_TYPE["elem_type"]) or 0
    return kind, dims_of(tensor.sub(TENSOR_TYPE["shape"]))


# The reader's element-type names, asserted against what onnx called the types it wrote.
RUST_ELEMENTS = {
    1: "float",
    2: "uint8",
    3: "int8",
    6: "int32",
    7: "int64",
    8: "string",
    9: "bool",
    10: "float16",
    11: "double",
}


def report(data):
    model = Msg(data)
    graph = model.sub(MODEL["graph"])
    rows = [
        "onnx\t{size}\tnodes\t{nodes}\ttensors\t{tensors}\topsets\t{opsets}\tbad\t{bad}".format(
            size=len(data),
            nodes=graph.count(GRAPH["node"]),
            tensors=graph.count(GRAPH["initializer"]),
            opsets=model.count(MODEL["opset"]),
            bad=model.bad,
        ),
        "ir\t{ir}\topset\t{domain}\tversion\t{version}".format(
            ir=model.one(MODEL["ir_version"]) or 0,
            domain=model.sub(MODEL["opset"]).text(OPSET["domain"]) or "-",
            version=model.sub(MODEL["opset"]).one(OPSET["version"]) or 0,
        ),
    ]
    line = "producer\t{name}".format(name=model.text(MODEL["producer_name"]) or "-")
    if MODEL["producer_version"] in model.values:
        line += "\tversion\t" + model.text(MODEL["producer_version"])
    if MODEL["domain"] in model.values:
        line += "\tdomain\t" + model.text(MODEL["domain"])
    if MODEL["model_version"] in model.values:
        line += "\tmodel_version\t{value}".format(value=model.one(MODEL["model_version"]))
    if MODEL["doc_string"] in model.values:
        line += "\tdoc\t" + model.text(MODEL["doc_string"])
    rows.append(line)
    for i, opset in enumerate(model.subs(MODEL["opset"])):
        rows.append(
            "opset\t{i}\tdomain\t{domain}\tversion\t{version}".format(
                i=i, domain=opset.text(OPSET["domain"]) or "-", version=opset.one(OPSET["version"]) or 0
            )
        )
    rows.append(
        "graph\t{name}\tnodes\t{n}\tinputs\t{i}\toutputs\t{o}\ttensors\t{t}".format(
            name=graph.text(GRAPH["name"]) or "-",
            n=graph.count(GRAPH["node"]),
            i=graph.count(GRAPH["input"]),
            o=graph.count(GRAPH["output"]),
            t=graph.count(GRAPH["initializer"]),
        )
    )
    for i, node in enumerate(graph.subs(GRAPH["node"])):
        rows.append(
            "node\t{i}\top\t{op}\tname\t{name}\tinputs\t{ins}\toutputs\t{outs}".format(
                i=i,
                op=node.text(NODE["op_type"]),
                name=node.text(NODE["name"]) or "-",
                ins=node.count(NODE["input"]),
                outs=node.count(NODE["output"]),
            )
        )
    for which in ("input", "output"):
        for i, info in enumerate(graph.subs(GRAPH[which])):
            kind, dims = type_of(info)
            rows.append(
                "{which}\t{i}\t{name}\ttype\t{kind}\ttype_name\t{label}\tdims\t{dims}".format(
                    which=which,
                    i=i,
                    name=info.text(VALUE_INFO["name"]) or "-",
                    kind=kind,
                    label=element_name(kind),
                    dims=",".join(dims) or "-",
                )
            )
    for i, tensor in enumerate(graph.subs(GRAPH["initializer"])):
        kind = tensor.one(TENSOR["data_type"]) or 0
        line = "tensor\t{i}\t{name}\ttype\t{kind}\ttype_name\t{label}\tdims\t{dims}".format(
            i=i,
            name=tensor.text(TENSOR["name"]) or "-",
            kind=kind,
            label=element_name(kind),
            dims="x".join(str(d) for d in tensor.repeated(TENSOR["dims"])) or "-",
        )
        for field, label, width in (
            (TENSOR["float_data"], "float", 4),
            (TENSOR["int32_data"], "int32", None),
            (TENSOR["int64_data"], "int64", None),
            (TENSOR["double_data"], "double", 8),
            (TENSOR["uint64_data"], "uint64", None),
        ):
            found = tensor.repeated(field, width)
            if found:
                line += "\t{label}\t{n}".format(label=label, n=len(found))
        if tensor.count(TENSOR["string_data"]):
            line += "\tbytes\t{n}".format(n=tensor.count(TENSOR["string_data"]))
        line += "\traw\t{n}".format(n=len(tensor.one(TENSOR["raw_data"]) or b""))
        location = tensor.one(TENSOR["data_location"])
        if location is not None:
            line += "\tlocation\t{value}".format(value=location)
        rows.append(line)
    rows.append("walked\tend" if model.bad == 0 and model.at == len(data) else "stopped\tbad\t{value}".format(value=model.bad))
    return rows, model


def path_of(name):
    return os.path.join(OUT, name)


def write(name, model):
    onnx.save_model(model, path_of(name))


def check(name, data):
    """Every field number the report uses has to equal what onnx parsed from the same bytes."""
    model = onnx.load(path_of(name))
    onnx.checker.check_model(model, full_check=True)
    sink = Msg(data)
    assert sink.bad == 0, f"{name}: walk failed"
    assert sink.at == len(data), f"{name}: walk stopped at {sink.at} of {len(data)}"
    assert model.ByteSize() == len(data), f"{name}: ByteSize {model.ByteSize()} vs {len(data)}"
    assert sink.one(MODEL["ir_version"]) == model.ir_version, f"{name}: ir_version"
    assert sink.text(MODEL["producer_name"]) == model.producer_name, f"{name}: producer_name"
    assert sink.text(MODEL["producer_version"]) == model.producer_version, f"{name}: producer_version"
    assert sink.text(MODEL["domain"]) == model.domain, f"{name}: domain"
    # An absent proto2 scalar reads as its default, which is a different fact in the bytes than in the
    # parsed object: `add.onnx` writes no model_version at all and onnx reports 0.
    assert (sink.one(MODEL["model_version"]) or 0) == model.model_version, f"{name}: model_version"
    assert sink.text(MODEL["doc_string"]) == model.doc_string, f"{name}: doc_string"
    graph = sink.sub(MODEL["graph"])
    assert graph.text(GRAPH["name"]) == model.graph.name, f"{name}: graph.name"
    # The strongest witness available: every region the reader treats as a node, tensor, input or
    # output has to be the exact bytes onnx serializes for that object. A wrong field number cannot
    # survive this, because it would land on a different message.
    for field, wanted in (
        (GRAPH["node"], model.graph.node),
        (GRAPH["initializer"], model.graph.initializer),
        (GRAPH["input"], model.graph.input),
        (GRAPH["output"], model.graph.output),
    ):
        regions = graph.blobs(field)
        assert len(regions) == len(wanted), f"{name}: graph field {field} count"
        assert [r for r in regions] == [item.SerializeToString() for item in wanted], (
            f"{name}: graph field {field} is not these messages"
        )
    assert graph.count(GRAPH["node"]) == len(model.graph.node), f"{name}: nodes"
    assert graph.count(GRAPH["initializer"]) == len(model.graph.initializer), f"{name}: tensors"
    assert len(sink.subs(MODEL["opset"])) == len(model.opset_import), f"{name}: opset imports"
    assert [o.one(OPSET["version"]) for o in sink.subs(MODEL["opset"])] == [
        o.version for o in model.opset_import
    ], f"{name}: opset versions"
    assert [o.text(OPSET["domain"]) for o in sink.subs(MODEL["opset"])] == [
        o.domain for o in model.opset_import
    ], f"{name}: opset domains"
    for i, node in enumerate(model.graph.node):
        own = graph.subs(GRAPH["node"])[i]
        assert own.text(NODE["op_type"]) == node.op_type, f"{name}: node {i} op_type"
        assert own.text(NODE["name"]) == node.name, f"{name}: node {i} name"
        assert own.count(NODE["input"]) == len(node.input), f"{name}: node {i} inputs"
        assert own.count(NODE["output"]) == len(node.output), f"{name}: node {i} outputs"
    for which in ("input", "output"):
        wanted = getattr(model.graph, which)
        assert graph.count(GRAPH[which]) == len(wanted), f"{name}: {which} count"
        for i, info in enumerate(wanted):
            kind, dims = type_of(graph.subs(GRAPH[which])[i])
            expect = [
                "d{}".format(d.dim_value)
                if d.HasField("dim_value")
                else ("p{}".format(d.dim_param) if d.HasField("dim_param") else "u")
                for d in info.type.tensor_type.shape.dim
            ]
            assert dims == expect, f"{name}: {which} {i} dims {dims} vs {expect}"
            assert kind == info.type.tensor_type.elem_type, f"{name}: {which} {i} elem type"
            note(name, kind)
    for i, tensor in enumerate(model.graph.initializer):
        own = graph.subs(GRAPH["initializer"])[i]
        assert own.one(TENSOR["data_type"]) == tensor.data_type, f"{name}: tensor {i} data_type"
        assert own.text(TENSOR["name"]) == tensor.name, f"{name}: tensor {i} name"
        assert own.repeated(TENSOR["dims"]) == list(tensor.dims), f"{name}: tensor {i} dims"
        assert len(own.one(TENSOR["raw_data"]) or b"") == len(tensor.raw_data), f"{name}: tensor {i} raw"
        assert (own.one(TENSOR["data_location"]) or 0) == tensor.data_location, f"{name}: tensor {i} location"
        for field, attr, width in (
            (TENSOR["float_data"], "float_data", 4),
            (TENSOR["int32_data"], "int32_data", None),
            (TENSOR["int64_data"], "int64_data", None),
            (TENSOR["double_data"], "double_data", 8),
            (TENSOR["uint64_data"], "uint64_data", None),
            (TENSOR["string_data"], "string_data", "blobs"),
        ):
            got = own.count(field) if width == "blobs" else len(own.repeated(field, width))
            assert got == len(getattr(tensor, attr)), f"{name}: tensor {i} {attr} {got} vs {len(getattr(tensor, attr))}"
        note(name, tensor.data_type)
    return sink


def note(name, ordinal):
    if not ordinal:
        return
    label = TensorProto.DataType.Name(ordinal)
    seen = ELEMENT_NAMES.get(ordinal)
    assert seen in (None, label), f"{name}: {ordinal} is both {seen} and {label}"
    ELEMENT_NAMES[ordinal] = label


def float_input(name, dims):
    return helper.make_tensor_value_info(name, TensorProto.FLOAT, dims)


def add_model():
    graph = helper.make_graph(
        [helper.make_node("Add", ["x", "b"], ["y"], name="add_0")],
        "add_graph",
        [float_input("x", [3])],
        [float_input("y", [3])],
        [helper.make_tensor("b", TensorProto.FLOAT, [3], [0.5, -0.5, 2.0])],
    )
    return helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], doc_string="adds a vector")


def symbolic_model():
    graph = helper.make_graph(
        [
            helper.make_node("Relu", ["x"], ["h"], name="relu_0"),
            helper.make_node("Neg", ["h"], ["y"], name="neg_0"),
        ],
        "symbolic_graph",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, ["N", 3, None])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, ["N", 3, None])],
    )
    model = helper.make_model(
        graph,
        producer_name="onnx-fixture-generator",
        producer_version="1.2.3",
        domain="lab.test",
        model_version=42,
        opset_imports=[helper.make_opsetid("", 17), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.doc_string = "batch axis is symbolic, one axis is unknown"
    return model


def types_model():
    tensors = [
        helper.make_tensor("f32", TensorProto.FLOAT, [2], [1.5, -2.5]),
        helper.make_tensor("i32", TensorProto.INT32, [3], [1, 2, 3]),
        helper.make_tensor("i64", TensorProto.INT64, [2], [7, 8]),
        helper.make_tensor("f64", TensorProto.DOUBLE, [2], [0.25, 1.0]),
        helper.make_tensor("flag", TensorProto.BOOL, [2], [1, 0]),
        helper.make_tensor("u8", TensorProto.UINT8, [3], [1, 2, 3]),
        helper.make_tensor("i8", TensorProto.INT8, [2], [-1, 2]),
        helper.make_tensor("h", TensorProto.FLOAT16, [2], [np.float16(1.5), np.float16(2.5)]),
        helper.make_tensor("words", TensorProto.STRING, [2], [b"ab", b"cde"]),
        helper.make_tensor("wide", TensorProto.FLOAT, [2, 3], np.arange(6, dtype=np.float32).tolist()),
        helper.make_tensor(
            "raw", TensorProto.FLOAT, [3], np.array([1.0, 2.0, 3.0], dtype=np.float32).tobytes(), raw=True
        ),
    ]
    graph = helper.make_graph(
        [helper.make_node("Identity", ["f32"], ["y"], name="id_0")],
        "types_graph",
        [float_input("f32", [2])],
        [float_input("y", [2])],
        tensors,
    )
    return helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])


def main():
    os.makedirs(OUT, exist_ok=True)
    write("add.onnx", add_model())
    write("symbolic.onnx", symbolic_model())
    write("types.onnx", types_model())

    probes = {}
    for name in ("add.onnx", "symbolic.onnx", "types.onnx"):
        data = open(path_of(name), "rb").read()
        check(name, data)
        rows, _ = report(data)
        probes[name] = {"bytes": len(data), "head": data[:12].hex(), "rows": rows}
        print(f"== {name} {len(data)} bytes")
        for row in rows:
            print('\t\t\t"' + row.replace("\t", "\\t") + '",')
    learned = {k: v.lower() for k, v in ELEMENT_NAMES.items()}
    assert learned == RUST_ELEMENTS, f"the reader's table {RUST_ELEMENTS} vs learned {learned}"
    probes["_observed"] = {
        "element_types": {str(k): v for k, v in sorted(ELEMENT_NAMES.items())},
        "note": "RUST_ELEMENTS is the reader's own naming table, asserted equal to what onnx named",
    }
    print("element types:", {k: v for k, v in sorted(ELEMENT_NAMES.items())})
    with open(os.path.join(OUT, "onnx.probe.json"), "w", encoding="utf-8", newline="\n") as sink:
        json.dump(probes, sink, indent=1, sort_keys=True, ensure_ascii=False)
        sink.write("\n")
    print("wrote onnx.probe.json")


main()
