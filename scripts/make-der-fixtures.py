#!/usr/bin/env python3
"""Write the X.509 DER fixtures and print the rows a reader has to reproduce.

A DER certificate states one thing in its own bytes that every reader can check for itself: the whole
file is exactly one length-prefixed object, so the top SEQUENCE's extent has to land on the end of the
file. Everything past that is a walk of tag, header length and content length - which is precisely why
it must be checked against somebody else's reading rather than against a specification remembered.

The producer and both witnesses are OpenSSL 3.5.7 (the Git for Windows build). No command line here can
go through a POSIX shell: MSYS rewrites `-subj /C=CN/...` into a Windows path before openssl sees it, so
every call is a `subprocess` with `shell=False`. The key is random, so the DER files are committed once
and only regenerated when absent; the probe is rebuilt from the bytes that are in the repository.

  * `asn1parse -inform DER -i` is the structural witness. It prints offset, depth, header length,
    content length, cons/prim and the type name for every object, and it names the OIDs it knows
    (`:commonName`, `:sha256WithRSAEncryption`). This script refuses to write its probe unless its own
    walk produces the same list in the same order, and OID_NAMES below is checked against the printed
    names in both directions. The type names the reader prints are the ones recorded in the probe.
  * `x509 -text -noout` is the semantic witness: version, serial, signature algorithm, issuer and
    subject as strings, the two validity times, the public-key algorithm and - for RSA - the key size.
    The reader reaches those fields by position, which is only legitimate because each value printed is
    then compared with what that command says about the same bytes. RSA's size is derived from the
    modulus INTEGER; EC's is not derived at all, because the curve name is the only thing in the file
    that states it and a bits column copied from a curve table would be a recalled number.

Usage: temp/venv/Scripts/python.exe scripts/make-der-fixtures.py
"""
import io
import json
import os
import re
import subprocess
import sys

OUT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test", "fixtures"))
SCRATCH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "temp", "der-work"))
LISTED_TLVS = 40
MAX_DEPTH = 24
# Names OpenSSL printed for these OIDs, kept as a table so the reader can be checked: main() fails if
# the witness names an OID that is missing here, or names one differently.
OID_NAMES = {
    "2.5.4.3": "commonName",
    "2.5.4.6": "countryName",
    "2.5.4.10": "organizationName",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10045.3.1.7": "prime256v1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.19": "X509v3 Basic Constraints",
}
TARGETS = [
    ("rsa.crt", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
    ("ec.crt", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"]),
]


def openssl(command, text=True):
    made = subprocess.run(["openssl"] + command, capture_output=True, shell=False)
    if made.returncode != 0:
        raise SystemExit(
            "openssl {} failed: {}".format(
                " ".join(command[:3]), made.stderr.decode("latin1")[:300]
            )
        )
    return made.stdout.decode("latin1") if text else made.stdout


def oid_of(raw):
    """A dotted OID from its value bytes: 40*a + b for the first component, base-128 for the rest."""
    if not raw:
        return "?"
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def tlvs(data, at, end, depth, out):
    """Append every object in [at, end) as (offset, depth, header, length, tag, kind)."""
    stopped = 0
    while at < end:
        if depth > MAX_DEPTH or at + 2 > end:
            return out, stopped + 1
        tag = data[at]
        first = data[at + 1]
        if tag & 0x1F == 0x1F:
            raise SystemExit("high-tag-number form is not produced by openssl here")
        if first & 0x80:
            digits = first & 0x7F
            if digits == 0 or digits > 4 or at + 2 + digits > end:
                return out, stopped + 1
            length = int.from_bytes(data[at + 2 : at + 2 + digits], "big")
            header = 2 + digits
        else:
            length = first & 0x7F
            header = 2
        body = at + header
        if body + length > end:
            return out, stopped + 1
        out.append((at, depth, header, length, tag, "cons" if tag & 0x20 else "prim"))
        if tag & 0x20:
            _, deeper = tlvs(data, body, body + length, depth + 1, out)
            stopped += deeper
        at = body + length
    return out, stopped


def header_of(data, at):
    """(tag, header length, content length) of the object that starts at `at`."""
    tag = data[at]
    first = data[at + 1]
    if first & 0x80:
        digits = first & 0x7F
        return tag, 2 + digits, int.from_bytes(data[at + 2 : at + 2 + digits], "big")
    return tag, 2, first & 0x7F


def kids(data, at):
    """The immediate children of one constructed object, as (offset, tag, header, length)."""
    _tag, header, length = header_of(data, at)
    rows = []
    cursor = at + header
    end = cursor + length
    while cursor < end:
        tag, head, sub = header_of(data, cursor)
        rows.append((cursor, tag, head, sub))
        cursor += head + sub
    return rows


def body_of(data, at):
    """(start, end) of one object's content."""
    _tag, header, length = header_of(data, at)
    return at + header, at + header + length


def asn1_witness(path):
    text = openssl(["asn1parse", "-inform", "DER", "-in", path, "-i"])
    seen = []
    for line in text.splitlines():
        match = re.match(
            r"\s*(\d+):d=(\d+)\s+hl=\s*(\d+) l=\s*(-?\d+)\s+(cons|prim):\s+(.*?)\s*(?::(.*))?$",
            line,
        )
        if match:
            seen.append(
                {
                    "offset": int(match.group(1)),
                    "depth": int(match.group(2)),
                    "hl": int(match.group(3)),
                    "length": int(match.group(4)),
                    "kind": match.group(5),
                    "name": re.sub(r"\s+\[HEX DUMP\]$", "", match.group(6).strip()).replace("  ", " "),
                    "value": (match.group(7) or "").strip(),
                }
            )
    if not seen:
        raise SystemExit("{}: asn1parse printed nothing".format(path))
    return seen


def x509_witness(path):
    text = openssl(["x509", "-inform", "DER", "-in", path, "-text", "-noout"])

    def grab(pattern):
        found = re.search(pattern, text)
        return found.group(1).strip() if found else None

    return {
        "version": grab(r"Version:\s*(\d+)"),
        "serial": grab(r"Serial Number:.*\((0x[0-9a-f]+)\)"),
        "sigalg": grab(r"Signature Algorithm:\s*(\S+)"),
        "issuer": grab(r"Issuer:\s*(.*)"),
        "subject": grab(r"Subject:\s*(.*)"),
        "not_before": grab(r"Not Before:\s*(.*)"),
        "not_after": grab(r"Not After\s*:\s*(.*)"),
        "pubalg": grab(r"Public Key Algorithm:\s*(\S+)"),
        "pubbits": grab(r"Public-Key:\s*\((\d+) bit\)"),
    }


def name_of_oid(dotted, printed, label, offset):
    known = OID_NAMES.get(dotted)
    if known is None:
        raise SystemExit(
            "{}: OBJECT at {} is {} which asn1parse calls {!r}; add it to OID_NAMES or stop naming it"
            .format(label, offset, dotted, printed)
        )
    if printed and known not in (printed, printed.split("(")[0]):
        raise SystemExit(
            "{}: the table calls {} {!r} but asn1parse prints {!r}".format(
                label, dotted, known, printed
            )
        )
    return known


def rdn_text(data, at):
    """A Name (SEQUENCE OF SET OF AttributeTypeAndValue) as `oid=value` parts plus the RDN count."""
    parts = []
    for set_at, _tag, _head, _length in kids(data, at):
        for pair_at, _t2, _h2, _l2 in kids(data, set_at):
            inner = kids(data, pair_at)
            t_start, t_end = body_of(data, inner[0][0])
            v_start, v_end = body_of(data, inner[1][0])
            parts.append(
                "{}={}".format(oid_of(data[t_start:t_end]), data[v_start:v_end].decode("latin1"))
            )
    return parts, len(kids(data, at))


def rows_for(label, data, path):
    objects, stopped = tlvs(data, 0, len(data), 0, [])
    seen = asn1_witness(path)
    mine = [(o, d, h, l, k) for o, d, h, l, _t, k in objects]
    theirs = [(e["offset"], e["depth"], e["hl"], e["length"], e["kind"]) for e in seen]
    if mine != theirs:
        for a, b in zip(theirs, mine):
            if a != b:
                raise SystemExit("{}: asn1parse says {}, walk says {}".format(label, a, b))
        raise SystemExit(
            "{}: asn1parse lists {} objects, walk lists {}".format(label, len(theirs), len(mine))
        )
    fields = x509_witness(path)
    names = {e["offset"]: e["name"] for e in seen}
    values = {e["offset"]: e["value"] for e in seen}

    # Every OBJECT in the file, not just the two the rows name, is checked against the table in both
    # directions: an entry the witness does not confirm fails, and one it confirms but the table lacks
    # fails too, so the table cannot quietly drift ahead of or behind what openssl says about these bytes.
    for offset, _depth, _header, _length, tag, _kind in objects:
        if tag != 0x06:
            continue
        start, end = body_of(data, offset)
        dotted = oid_of(data[start:end])
        printed = values.get(offset, "").lstrip(":")
        known = OID_NAMES.get(dotted)
        if known is not None and known != printed:
            raise SystemExit(
                "{}: the table names {} {!r}, asn1parse prints {!r}".format(
                    label, dotted, known, printed
                )
            )
        if known is None and printed != dotted:
            raise SystemExit(
                "{}: asn1parse names {} {!r}, which OID_NAMES does not carry".format(
                    label, dotted, printed
                )
            )

    outer = kids(data, 0)
    if len(outer) != 3:
        raise SystemExit("{}: the certificate has {} top children, not 3".format(label, len(outer)))
    tbs_at, sig_at, bit_at = outer[0][0], outer[1][0], outer[2][0]
    inner = kids(data, tbs_at)
    # [0] EXPLICIT version, then serial, signature algorithm, issuer, validity, subject, SPKI - the
    # order the reader navigates by, and every value it takes from those positions is compared against
    # what `x509 -text` states about the same bytes at the end of this function.
    cursor = 0
    version = 1
    if inner[0][1] == 0xA0:
        inside = kids(data, inner[0][0])
        ver_start, ver_end = body_of(data, inside[0][0])
        version = int.from_bytes(data[ver_start:ver_end], "big") + 1
        cursor = 1
    serial_start, serial_end = body_of(data, inner[cursor][0])
    serial = data[serial_start:serial_end].hex()
    sig_at = inner[cursor + 1][0]
    sig_obj = kids(data, sig_at)[0][0]
    sig_start, sig_end = body_of(data, sig_obj)
    sig_oid = oid_of(data[sig_start:sig_end])
    issuer_at = inner[cursor + 2][0]
    validity_at = inner[cursor + 3][0]
    subject_at = inner[cursor + 4][0]
    spki_at = inner[cursor + 5][0]
    v_start, v_end = body_of(data, validity_at)
    times = kids(data, validity_at)
    nb_start, nb_end = body_of(data, times[0][0])
    na_start, na_end = body_of(data, times[1][0])
    not_before = data[nb_start:nb_end].decode("latin1")
    not_after = data[na_start:na_end].decode("latin1")
    time_tag = times[0][1]
    algs = kids(data, spki_at)
    pub_alg_at = algs[0][0]
    pub_obj = kids(data, pub_alg_at)[0][0]
    alg_start, alg_end = body_of(data, pub_obj)
    pub_oid = oid_of(data[alg_start:alg_end])
    key_start, key_end = body_of(data, algs[1][0])
    bits = None
    if pub_oid == "1.2.840.113549.1.1.1":
        modulus = kids(data, key_start + 1)
        m_start, m_end = body_of(data, modulus[0][0])
        raw = data[m_start:m_end]
        bits = (len(raw) - (1 if raw[:1] == b"\x00" else 0)) * 8
    issuer_parts, issuer_count = rdn_text(data, issuer_at)
    subject_parts, subject_count = rdn_text(data, subject_at)
    # `asn1parse` keeps the type in one column and the decoded value in another: an OBJECT prints
    # `:sha256WithRSAEncryption`, so the name a reader may print for an OID comes from the value column
    # and nothing else.
    sig_name = name_of_oid(
        sig_oid, values.get(sig_obj, "").lstrip(":"), label, sig_obj
    )
    pub_name = name_of_oid(
        pub_oid, values.get(pub_obj, "").lstrip(":"), label, pub_obj
    )

    broken = stopped
    if objects[0][4] != 0x30 or objects[0][0] != 0:
        raise SystemExit("{}: the top object is not a SEQUENCE".format(label))
    # The one claim the format makes about itself, stated rather than demanded: a certificate whose top
    # length does not account for the file is still a certificate, and the row says `end no`.
    spans = objects[0][2] + objects[0][3] == len(data)
    if not spans:
        broken += 1
    rows = [
        "der\t{}\tbroken\t{}\ttlvs\t{}\tdepth\t{}\tend\t{}".format(
            len(data),
            broken,
            len(objects),
            max(o[1] for o in objects),
            "yes" if spans else "no",
        ),
        "cert\tversion\t{}\tserial\t{}\tsig\t{}({})\tpub\t{}({})".format(
            version, serial, sig_name, sig_oid, pub_name, pub_oid
        ),
        "valid\tkind\t{:02x}({})\tnot_before\t{}\tnot_after\t{}".format(
            time_tag, names.get(v_start, "?"), not_before, not_after
        ),
        "name\tissuer\t{}\t{}".format(issuer_count, ",".join(issuer_parts)),
        "name\tsubject\t{}\t{}".format(subject_count, ",".join(subject_parts)),
        "key\talgorithm\t{}({})\tbits\t{}\tpoint\t{}".format(
            pub_name, pub_oid, "-" if bits is None else bits, key_end - key_start - 1
        ),
    ]
    listed = 0
    for offset, depth, header, length, tag, kind in objects:
        if listed >= LISTED_TLVS:
            break
        rows.append(
            "tlv\t{}\td{}\t{}\thl\t{}\tl\t{}\t{:02x}({}|{})".format(
                listed, depth, offset, header, length, tag, kind, names.get(offset, "?")
            )
        )
        listed += 1
    if len(objects) > listed:
        rows.append("cut\ttlvs\t{}".format(len(objects)))
    rows.append("walked\tend" if broken == 0 else "stopped\tbroken\t{}".format(broken))
    checks = {
        "version": (str(version), fields["version"]),
        "serial": (serial, (fields["serial"] or "").replace("0x", "")),
        "sigalg": (sig_name, fields["sigalg"]),
        "pubalg": (pub_name, fields["pubalg"]),
    }
    if bits is not None:
        checks["bits"] = (str(bits), fields["pubbits"])
    # The two times are printed as the DER string itself, so the witness is asn1parse's own rendering of
    # those bytes rather than a date parse with a remembered two-digit-year rule. The names go the other
    # way: every value the walk pulls out of the RDNs has to appear in x509's own Issuer/Subject line.
    checks["not_before"] = (not_before, values.get(times[0][0], "").lstrip(":"))
    checks["not_after"] = (not_after, values.get(times[1][0], "").lstrip(":"))
    for key, (got, want) in checks.items():
        if key.startswith("not_") and want == "":
            raise SystemExit("{}: asn1parse printed no value for the {} object".format(label, key))
        if want is not None and got != want:
            raise SystemExit(
                "{}: x509 -text says {} is {!r}, the walk says {!r}".format(label, key, want, got)
            )
    for part, line in ((issuer_parts, fields["issuer"]), (subject_parts, fields["subject"])):
        for item in part:
            value = item.split("=", 1)[1]
            if value not in (line or ""):
                raise SystemExit(
                    "{}: the walk reads {!r} out of the name, x509 prints {!r}".format(
                        label, value, line
                    )
                )
    return rows, {
        "x509": fields,
        "tag_names": sorted({"{:02x}:{}".format(t, names.get(o, "?")) for o, _d, _h, _l, t, _k in objects}),
        "asn1": seen,
    }


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    built = {}
    for label, keygen in TARGETS:
        fixture = os.path.join(OUT, label)
        if not os.path.exists(fixture):
            key = os.path.join(SCRATCH, label + ".key")
            pem = os.path.join(SCRATCH, label + ".pem")
            openssl(keygen + ["-out", key])
            openssl(
                [
                    "req", "-new", "-x509", "-key", key, "-days", "3650",
                    "-subj", "/C=CN/O=apk-lens lab/CN=test.example.invalid",
                    "-set_serial", "0x2a",
                    "-not_before", "20260101000000Z", "-not_after", "20360101000000Z",
                    "-out", pem,
                ]
            )
            openssl(["x509", "-in", pem, "-outform", "DER", "-out", fixture])
        data = open(fixture, "rb").read()
        rows, extra = rows_for(label, data, fixture)
        print("==", label, len(data), "bytes,", len(rows), "rows")
        for row in rows:
            print("   ", row.replace("\t", " | "))
        built[label] = {"bytes": len(data), "rows": rows, **extra}
    with open(os.path.join(OUT, "der.probe.json"), "w", encoding="utf8") as handle:
        json.dump(built, handle, indent=1, sort_keys=True)
    print("wrote der.probe.json for", ", ".join(label for label, _ in TARGETS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
