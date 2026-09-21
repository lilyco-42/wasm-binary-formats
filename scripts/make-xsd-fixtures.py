"""Produce and check the XSD fixtures - a schema, read by three readers that are not this repo's.

An `.xsd` is an XML document whose root element is `schema` in the namespace
`http://www.w3.org/2001/XMLSchema`. Nothing else about it is a magic: the label is carried entirely by
that one binding, which is why the reader's acceptance rule is the binding and not the file name.
Three readings are made before a probe is written, and two of them compile the schema rather than
merely parse it:

    ElementTree            ->  the tree: components, references as spelled, per-kind counts
    xmlschema.XMLSchema    ->  a schema compiler: global maps, imports, includes, its own error list
    Xerces via the JDK     ->  a second, independent compiler: javax.xml.validation.SchemaFactory

The rows are assembled from ElementTree's tree, so the Rust reader is checked against another
implementation of the same walk. The two compilers witness a different claim: that `lab.xsd`,
`hand.xsd`, `part.xsd` and `many.xsd` are schemas real implementations accept, and that `broken.xsd` -
well-formed, right root, right namespace - is one they both refuse. The reader answers for all five,
and the probe records which two of them are invalid, because identification here is structural and
this README is not going to claim more than that.

Two findings from the first run, both kept because they are the format rather than a mistake:

  * `SchemaFactory.newSchema` reports a broken schema through its ErrorHandler and still returns a
    Schema, so `compiled=yes` says nothing; the gate counts the `error` and `fatal` lines instead.
  * An unprefixed type reference is not portable when the root carries `xmlns` set to the schema
    namespace itself. `type="Amount"` in that file was refused by Xerces ("'Amount' is in namespace
    http://www.w3.org/2001/XMLSchema, but components from this namespace are not referenceable") and
    by xmlschema ("unknown type 'Amount'"), which is why `hand.xsd` keeps the default-namespace
    spelling and reaches only the builtins by name.

    temp/venv/Scripts/python.exe scripts/make-xsd-fixtures.py

`xmlschema` is a pip dependency of this lab's venv and Xerces is the JDK on PATH, so neither witness
can be re-run by CI. The committed `xsd.probe.json` is the evidence, exactly as `jsonc.probe.json` is.
"""

import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import xmlschema

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")
SCRATCH = os.path.join(ROOT, "temp", "xsd-build")

XSD = "http://www.w3.org/2001/XMLSchema"

# The seven names a schema puts global declarations under, and the three that are not declarations.
KINDS = ("element", "attribute", "complexType", "simpleType", "group", "attributeGroup", "notation")
MODEL = ("element", "group", "choice", "sequence", "any")
DERIVES = ("extension", "restriction", "complexContent", "simpleContent")
MAPS = {"element": "elements", "attribute": "attributes", "simpleType": "simple_types",
        "complexType": "complex_types", "group": "groups", "attributeGroup": "attribute_groups",
        "notation": "notations"}

LAB = """<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:tns="http://lab.example.invalid/fixture"
           targetNamespace="http://lab.example.invalid/fixture"
           elementFormDefault="qualified" attributeFormDefault="unqualified">
  <xs:import namespace="http://www.w3.org/XML/1998/namespace"/>
  <xs:annotation>
    <xs:documentation>a fixture schema &amp; nothing else</xs:documentation>
  </xs:annotation>
  <xs:simpleType name="Code">
    <xs:restriction base="xs:token">
      <xs:pattern value="[A-Z]{2,4}"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:complexType name="Item">
    <xs:sequence>
      <xs:element name="code" type="tns:Code"/>
      <xs:element name="price" type="xs:decimal" minOccurs="0"/>
      <xs:element name="qty">
        <xs:simpleType>
          <xs:restriction base="xs:int">
            <xs:minInclusive value="0"/>
          </xs:restriction>
        </xs:simpleType>
      </xs:element>
    </xs:sequence>
    <xs:attribute name="id" type="xs:int" use="required"/>
  </xs:complexType>
  <xs:group name="Parts">
    <xs:sequence>
      <xs:element ref="tns:line"/>
    </xs:sequence>
  </xs:group>
  <xs:attributeGroup name="Common">
    <xs:attribute name="lang" type="xs:language"/>
  </xs:attributeGroup>
  <xs:attribute name="reviewed" type="xs:boolean"/>
  <xs:notation name="JPEG" public="image/jpeg" system="viewer"/>
  <xs:element name="line" type="tns:Item"/>
  <xs:element name="order">
    <xs:complexType>
      <xs:sequence>
        <xs:element ref="tns:line" maxOccurs="unbounded"/>
      </xs:sequence>
      <xs:attribute name="note" type="xs:string" use="optional"/>
      <xs:attributeGroup ref="tns:Common"/>
    </xs:complexType>
  </xs:element>
</xs:schema>
"""

# The default namespace is on the root, so an unprefixed *element* is a schema element; the builtin
# type references are still prefixed, because a QName in an attribute value is not affected by a
# default namespace - see the second finding in this file's header.
HAND = """<?xml version="1.0"?>
<schema xmlns="http://www.w3.org/2001/XMLSchema" xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <annotation><appinfo>no target namespace, and a default namespace on the root</appinfo></annotation>
  <include schemaLocation="part.xsd"/>
  <simpleType name="Amount">
    <restriction base="xs:decimal">
      <minInclusive value="0"/>
      <fractionDigits value="2"/>
    </restriction>
  </simpleType>
  <simpleType name="Tags">
    <list itemType="xs:string"/>
  </simpleType>
  <simpleType name="Kind">
    <union memberTypes="xs:NCName xs:Name"/>
  </simpleType>
  <complexType name="Money" mixed="true">
    <sequence>
      <element name="when" type="xs:dateTime" minOccurs="0"/>
    </sequence>
    <attribute name="unit" type="xs:string" use="prohibited"/>
  </complexType>
  <element name="amount" type="xs:decimal"/>
  <attribute name="stamp" type="xs:dateTime"/>
</schema>
"""

PART = """<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="who" type="xs:string"/>
  <xs:element name="where" type="xs:string"/>
</xs:schema>
"""

BROKEN = """<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="http://lab.example.invalid/broken"
           targetNamespace="http://lab.example.invalid/broken">
  <xs:element name="thing" type="t:Missing"/>
  <xs:complexType name="Other">
    <xs:complexContent>
      <xs:extension base="t:AlsoMissing">
        <xs:sequence>
          <xs:element name="x" type="xs:int"/>
        </xs:sequence>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
</xs:schema>
"""

# The cap on listed components needs a file past it, and nothing else here has that many globals.
MANY = 70


def many(count):
    body = "".join('  <xs:element name="c%02d" type="xs:string"/>\n' % n for n in range(count))
    return (
        '<?xml version="1.0"?>\n'
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n' + body + "</xs:schema>\n"
    )


# ------------------------------------------------------------- the JDK's own compiler, kept in sync
JAVA = r"""import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.XMLConstants;
import java.io.File;
import org.xml.sax.SAXParseException;

public class XsdProbe {
  public static void main(String[] a) throws Exception {
    SchemaFactory f = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    final int[] bad = {0, 0};
    final StringBuilder seen = new StringBuilder();
    f.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
      void rec(String level, SAXParseException e) {
        bad["warn".equals(level) ? 1 : 0] += 1;
        seen.append(level).append('\t').append(e.getMessage().replace('\n', ' ')).append('\n');
      }
      public void error(SAXParseException e) { rec("error", e); }
      public void fatalError(SAXParseException e) { rec("fatal", e); }
      public void warning(SAXParseException e) { rec("warn", e); }
    });
    Schema s = null;
    try {
      s = f.newSchema(new File(a[0]));
    } catch (Exception e) {
      System.out.println("threw\t" + e.getClass().getSimpleName());
    }
    System.out.println("returned\t" + (s != null ? "yes" : "no"));
    System.out.println("errors\t" + bad[0]);
    System.out.println("warnings\t" + bad[1]);
    System.out.print(seen);
  }
}
"""


def local(tag):
    """ElementTree hands back `{uri}name`; the reader strips prefixes the same way GPX does."""
    return tag.rsplit("}", 1)[-1]


def space(tag):
    return tag[1 : tag.find("}")] if tag.startswith("{") else None


def children(node, name):
    return [kid for kid in node if local(kid.tag) == name]


def own_text(node):
    """The text runs directly inside `node`, which is what the reader's `text` field holds.

    ElementTree splits those runs between `node.text` (before the first child) and each child's `tail`
    (after that child closes); the reader concatenates them into one string. Two spellings of the same
    bytes, and the join order is the document order either way.
    """
    parts = [node.text or ""]
    for kid in node:
        parts.append(kid.tail or "")
    return "".join(parts)


def held_text(node):
    """`node`'s own text plus every descendant's, each trimmed, blanks dropped, joined by a space."""
    found, queue = [], [node]
    while queue:
        one = queue.pop(0)
        piece = own_text(one).strip()
        if piece:
            found.append(piece)
        queue = list(one) + queue
    return " ".join(found)


def field(row, key, default="-"):
    parts = row.split("\t")
    for at, one in enumerate(parts[:-1]):
        if one == key:
            return parts[at + 1]
    return default


def detail(node, kind):
    """The kind-specific tail of a component row, counting direct children only."""
    if kind == "element":
        nested = next((local(kid.tag) for kid in node if local(kid.tag) in ("complexType", "simpleType")), "-")
        return ["ref\t%s" % field_attrs(node, "ref"), "type\t%s" % field_attrs(node, "type"),
                "nested\t%s" % nested]
    if kind == "attribute":
        return ["type\t%s" % field_attrs(node, "type"), "use\t%s" % field_attrs(node, "use")]
    if kind == "complexType":
        return ["mixed\t%s" % field_attrs(node, "mixed"),
                "derives\t%s" % next((local(kid.tag) for kid in node if local(kid.tag) in DERIVES), "-"),
                "particles\t%d" % sum(1 for kid in node if local(kid.tag) in MODEL),
                "attributes\t%d" % len(children(node, "attribute"))]
    if kind == "simpleType":
        face = next((kid for kid in node if local(kid.tag) in ("restriction", "list", "union")), None)
        base, facets = "-", 0
        if face is not None:
            base = field_attrs(face, "base", None) or field_attrs(face, "itemType", None) or "-"
            facets = len(list(face))
        return ["base\t%s" % base, "facets\t%d" % facets]
    if kind == "group":
        return ["particles\t%d" % sum(1 for kid in node if local(kid.tag) in MODEL)]
    if kind == "attributeGroup":
        return ["attributes\t%d" % len(children(node, "attribute"))]
    if kind == "notation":
        return ["public\t%s" % field_attrs(node, "public"), "system\t%s" % field_attrs(node, "system")]
    return []


def field_attrs(node, key, default="-"):
    return node.get(key, default if default != "-" else None) or default


def rows_for(root, size, cap=64):
    """Row 0 of totals, then one row per direct child of the root, in document order."""
    counts = dict((kind, 0) for kind in list(KINDS) + ["import", "include", "annotation"])
    counts["unknown"] = 0
    for kid in root:
        name = local(kid.tag)
        counts["unknown" if name not in counts else name] += 1
    head = [
        "schema",
        "pieces\t%d" % len(list(root)),
        "elements\t%d" % counts["element"],
        "attributes\t%d" % counts["attribute"],
        "complexTypes\t%d" % counts["complexType"],
        "simpleTypes\t%d" % counts["simpleType"],
        "groups\t%d" % counts["group"],
        "attributeGroups\t%d" % counts["attributeGroup"],
        "imports\t%d" % counts["import"],
        "includes\t%d" % counts["include"],
        "notations\t%d" % counts["notation"],
        "annotations\t%d" % counts["annotation"],
        "unknown\t%d" % counts["unknown"],
        "nodes\t%d" % sum(1 for _ in root.iter()),
        "target\t%s" % field_attrs(root, "targetNamespace"),
        "eform\t%s" % field_attrs(root, "elementFormDefault"),
        "aform\t%s" % field_attrs(root, "attributeFormDefault"),
        "bytes\t%d" % size,
    ]
    rows = ["\t".join(head)]
    for index, kid in enumerate(root):
        if index >= cap:
            continue
        name = local(kid.tag)
        if name == "annotation":
            text = held_text(kid)
            rows.append("\t".join(["doc", str(index), "chars\t%d" % len(text),
                                   "text\t%s" % (text[:72] if text else "-")]))
        elif name == "import":
            rows.append("\t".join(["import", str(index), "namespace\t%s" % field_attrs(kid, "namespace"),
                                   "loc\t%s" % field_attrs(kid, "schemaLocation")]))
        elif name == "include":
            rows.append("\t".join(["include", str(index), "loc\t%s" % field_attrs(kid, "schemaLocation")]))
        elif name in KINDS:
            rows.append("\t".join(["comp", str(index), "kind\t%s" % name,
                                   "name\t%s" % field_attrs(kid, "name")] + detail(kid, name)))
        else:
            rows.append("\t".join(["other", str(index), "kind\t%s" % name]))
    if len(list(root)) > cap:
        rows.append("cut\tcomponents\t%d\tlisted\t%d" % (len(list(root)), cap))
    return rows


def tree_globals(root):
    """Kind to the global names the document declares, in the order the file lists them.

    Read from the tree rather than from the rows, because the rows stop at the listing cap and the
    compilers' component maps do not - `many.xsd` is the file that tells the two apart.
    """
    out = {}
    for kid in root:
        name = local(kid.tag)
        if name in KINDS:
            out.setdefault(name, []).append(kid.get("name", "-"))
    return out


def java_answers(path):
    probe = os.path.join(SCRATCH, "XsdProbe.java")
    with open(probe, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(JAVA)
    out = subprocess.run([shutil.which("java") or "java", "-Duser.language=en", "-Duser.country=US",
                          probe, os.path.basename(path)], capture_output=True, shell=False,
                         timeout=600, cwd=SCRATCH)
    if out.returncode != 0:
        raise SystemExit("java probe failed on %s: %s"
                         % (path, out.stderr.decode("utf-8", "replace")[:400]))
    lines = out.stdout.decode("utf-8", "replace").splitlines()
    facts = dict(line.split("\t", 1) for line in lines[:4])
    return {"returned": facts.get("returned"), "errors": int(facts.get("errors", "-1")),
            "warnings": int(facts.get("warnings", "-1")),
            "messages": [line[:200] for line in lines[4:]]}


def compiler_answers(path):
    # `lax` collects errors but never resolves the references that make a schema wrong, so it reports
    # `broken.xsd` as clean; `strict` is the mode that actually builds the component tree, and it
    # raises. A raise is the answer here, not a failure of the probe, so it is caught and recorded.
    try:
        schema = xmlschema.XMLSchema(path, validation="strict")
    except Exception as exc:
        return {"valid": False, "raised": type(exc).__name__,
                "errors": [str(exc)[:200]], "target": None, "maps": None,
                "imports": None, "includes": None}

    def names(view):
        # A global map yields `{uri}name` strings while `simple_types` and `complex_types` yield
        # component objects whose `.name` is that same string, so both shapes go through the local
        # half - the same strip the reader applies to an element's prefixed spelling.
        return sorted(local(str(getattr(one, "name", one))) for one in view)

    errors = [str(one)[:200] for one in schema.errors]
    return {
        "valid": not errors,
        "raised": None,
        "errors": sorted(errors),
        "target": schema.target_namespace or "-",
        "imports": len(list(schema.imports)),
        "includes": len(list(schema.includes)),
        "maps": dict((kind, names(getattr(schema, MAPS[kind]))) for kind in KINDS),
    }


def main():
    if not shutil.which("java"):
        raise SystemExit("no java on PATH: Xerces is one of the two compilers this label is gated on")
    files = {"lab.xsd": LAB, "hand.xsd": HAND, "part.xsd": PART, "broken.xsd": BROKEN,
             "many.xsd": many(MANY)}
    if os.path.isdir(SCRATCH):
        shutil.rmtree(SCRATCH)
    os.makedirs(SCRATCH)
    # Every file lands in the scratch directory before anything is read: `hand.xsd` includes
    # `part.xsd`, and a compiler that cannot resolve that reference answers about a different
    # document than the one being probed.
    for name, text in files.items():
        with open(os.path.join(SCRATCH, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    # An included schema's globals are merged into the includer's maps, so the compiler's element list
    # for `hand.xsd` names part.xsd's two elements as well. That is part.xsd's own row set, recorded
    # here as the observation it is rather than subtracted out of the comparison below.
    merged = {"hand.xsd": "part.xsd"}

    probe = {}
    for name, text in sorted(files.items()):
        path = os.path.join(SCRATCH, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        raw = text.encode("utf-8")
        root = ET.fromstring(text)
        if space(root.tag) != XSD or local(root.tag) != "schema":
            raise SystemExit("%s: the root is %s, not a schema in the XSD namespace" % (name, root.tag))
        rows = rows_for(root, len(raw))
        own = tree_globals(root)
        machine = compiler_answers(path)
        jvm = java_answers(path)
        extras = own_of(files, merged.get(name)) if name in merged else {}
        for kind in KINDS:
            want = sorted(own.get(kind, []) + extras.get(kind, []))
            if machine["maps"] is not None and machine["maps"][kind] != want:
                raise SystemExit("%s: xmlschema's %s map is %r, the tree's globals %r%s"
                                 % (name, kind, machine["maps"][kind], want,
                                    " (plus %s)" % merged[name] if name in merged else ""))
        own_target = field(rows[0], "target")
        if machine["target"] is not None and machine["target"] != own_target:
            raise SystemExit("%s: xmlschema says target %r, the root attribute says %r"
                             % (name, machine["target"], own_target))
        if name == "broken.xsd":
            if machine["valid"] or jvm["errors"] == 0:
                raise SystemExit("%s: neither compiler complained, so this fixture tests nothing" % name)
        elif not machine["valid"] or jvm["errors"] != 0:
            raise SystemExit("%s: a compiler refused a fixture meant to be valid: %r / %r"
                             % (name, machine["errors"], jvm["messages"]))
        if jvm["returned"] != "yes":
            raise SystemExit("%s: Xerces returned no Schema at all: %r" % (name, jvm))
        probe[name] = {"bytes": len(raw), "rows": rows, "counts": counts_of(rows[0]),
                       "globals": own, "xmlschema": machine, "xerces": jvm}
        for row in rows:
            print("%-11s %s" % (name, row.replace("\t", " | ")))
        print("%-11s xerces errors=%d warnings=%d  xmlschema errors=%d%s"
              % ("", jvm["errors"], jvm["warnings"], len(machine["errors"]),
                 ("  first: " + jvm["messages"][0][:110]) if jvm["messages"] else ""))

    for name, text in files.items():
        with open(os.path.join(FIX, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    with open(os.path.join(FIX, "xsd.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("%d files; ElementTree, xmlschema and Xerces agree" % len(files))
    return 0


def own_of(files, name):
    """The global names a second document declares, for the merge an `include` performs."""
    return {} if not name else tree_globals(ET.fromstring(files[name]))


def counts_of(head):
    out = {}
    parts = head.split("\t")
    for at in range(1, len(parts) - 1, 2):
        if parts[at + 1].isdigit():
            out[parts[at]] = int(parts[at + 1])
    return out


if __name__ == "__main__":
    sys.exit(main())
