#!/usr/bin/env python3
"""Write the OpenPGP fixtures with GnuPG, and record what `gpg --list-packets` reads back from them.

`pgp` is one of magika's 219 binary labels ("PGP", extensions `gpg`/`pgp`). An OpenPGP transfer is a
packet *framing* rather than a header: every packet states its own payload length, so - like DER, binary
STL and bencode elsewhere in this repo - the bytes either tile the file exactly or the file is not what it
claims. There are two header disciplines (RFC 9580's old and new packet formats) and one file mixes them:
gpg writes old-format headers for key, signature and literal packets and a new-format one for the encrypted
data packet.

`gpg` is producer and witness, and the witness is stronger than a version print: for every packet
`--list-packets` emits `# off=N ctb=XX tag=T hlen=H plen=P` - offset, raw first octet, tag number, header
size, payload size. This script walks the bytes itself (that walk is the shadow the Rust reader was ported
from, and its rows go into the probe) and refuses to write unless:

  * its own top-level walk tiles the file to the final byte with nothing broken;
  * every packet it found appears in gpg's listing with the same offset, tag, header size and payload
    size, and gpg's label for the tag is the name the reader prints;
  * the tag encoded in `ctb`'s own bits equals the tag gpg prints beside it, in both formats;
  * each decoded field it names - signature class and algorithms, session-key version and cipher, key
    version and creation time, literal file name and raw size - is also spelled out in gpg's own words for
    that packet.

The length rules themselves are derived from those 20-odd observed packets rather than recalled: an
old-format header puts the length octet count in the two low bits of the tag octet (0 -> one, 1 -> two,
2 -> four, 3 -> indeterminate) while a new-format one lets the first length octet pick its own form. Both
branches that matter are demonstrated - the ed25519 export fits in one octet per packet, the rsa2048
export does not - and the row prints `old` or `new` so a reader can see which was used.

Three packet types hold bytes that are not packet framing - compressed, and the two encrypted forms - so
the walk stops there and says so (`descend no deflate` / `descend no encrypted`) instead of pretending to
read through them. That is also why gpg's listing is compared only as a prefix: past such a packet it
prints positions inside a decompressed or decrypted stream, which are not offsets in this file.

The keys are generated per run, so the fixtures are committed and only the probe is re-derived from the
committed bytes (`--probe-only`), as with the DER round. The private halves stay in `temp/` and are never
written next to the fixtures.

Six fixtures, one per thing the framing has to survive:

  lab-key.pgp      exported ed25519 certificate: 5 packets, every old-format length in one octet
  lab-rsa.pgp      exported rsa2048 certificate: same shape, lengths that need the two-octet form
  lab-signed.pgp   `--compress-algo 0` signature: onepass + literal + signature, in the clear
  lab-signedz.pgp  default signature: one compressed packet of indeterminate length running to EOF
  lab-encr.pgp     public-key session key + SEIPD: two packets, the second opaque
  lab-sym.pgp      symmetric-key session key + SEIPD, same shape, different first packet

Usage: temp/venv/Scripts/python.exe scripts/make-pgp-fixtures.py [--probe-only]
"""
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
OUT = os.path.join(ROOT, "test", "fixtures")
WORK = os.path.join(ROOT, "temp", "pgp-work")
NOTES = os.path.join(ROOT, "temp", "pgp-notes")
NOTE = b"signed by the lab fixture key\n"
PASSPHRASE = "lab-passphrase"
MAX_PACKETS = 24


def rel(path):
    """A path gpg can take. The MSYS build turns a Windows-style GNUPGHOME into a relative
    path of its own, so everything handed to it is relative to this repo instead.
"""
    return os.path.relpath(path, ROOT).replace("\\", "/")

HEADER = re.compile(r"^# off=(\d+) ctb=([0-9a-f]{2}) tag=(\d+) hlen=(\d+) plen=(\d+)(.*)$")
LABEL = re.compile(r"^:(.+?) packet: ?(.*)$")
LITERAL_NAME = re.compile(r'name="([^"]*)"')
LITERAL_RAW = re.compile(r"raw data: (\d+) bytes")
SIG_CLASS = re.compile(r"sigclass 0x([0-9a-f]{2})")
SIG_DIGEST = re.compile(r"digest algo (\d+)")
SIG_ALGO = re.compile(r"^signature algo ([0-9a-fA-F]+)")
KEY_DETAIL = re.compile(r"version (\d+), algo (\d+), created (\d+)")
PKESF = re.compile(r"version (\d+), algo (\d+), keyid ([0-9a-fA-F]{16})")
SKESF = re.compile(r"version (\d+), cipher (\d+), aead (\d+), s2k (\d+), hash (\d+)")

# gpg's own words for the tags that appear in the fixtures below; asserted against the listing, so a name
# here cannot be a recollection. A tag with no entry prints as `tag N`.
NAMES = {
    1: "pubkey enc",
    2: "signature",
    3: "symkey enc",
    4: "onepass_sig",
    6: "public key",
    8: "compressed",
    11: "literal data",
    13: "user ID",
    14: "public sub key",
    18: "encrypted data",
}
# Tags whose body is not packet framing, and the reason the walk says it stopped.
OPAQUE = {8: "deflate", 17: "encrypted", 18: "encrypted"}
KEY_TAGS = (6, 14)


def gpg(args, home, allow_fail=False):
    env = dict(os.environ, GNUPGHOME=rel(home))
    proc = subprocess.run(
        [shutil.which("gpg") or "gpg", "--batch", "--no-tty", "--yes"] + list(args),
        cwd=ROOT, env=env, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0 and not allow_fail:
        raise SystemExit("gpg {} failed: {}".format(
            " ".join(args), proc.stderr.decode("utf8", "replace")))
    return proc.stdout, proc.stderr.decode("utf8", "replace")


def fingerprint(home, name):
    out, _ = gpg(["--fingerprint", "--list-keys", name], home)
    found = re.findall(r"[0-9A-F]{40}", out.decode("utf8", "replace").replace(" ", ""))
    if not found:
        raise SystemExit("no fingerprint for {}".format(name))
    return found[0]


def build(home, notes):
    for each in (home, notes):
        if os.path.isdir(each):
            shutil.rmtree(each)
    os.makedirs(home)
    os.makedirs(notes)
    note = os.path.join(notes, "note.txt")
    with open(note, "wb") as handle:
        handle.write(NOTE)
    made = {}
    for label, algo in (("ed", "default"), ("rsa", "rsa2048")):
        uid = "APK Lens {} Fixture <{}@example.invalid>".format(label, label)
        gpg(["--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--quick-generate-key",
             uid, algo, "default", "never"], home)
        made[label] = (uid, fingerprint(home, uid))
    ed_uid, ed = made["ed"]
    rsa_uid, rsa = made["rsa"]
    gpg(["--export", "--output", rel(os.path.join(notes, "lab-key.pgp")), ed], home)
    gpg(["--export", "--output", rel(os.path.join(notes, "lab-rsa.pgp")), rsa], home)
    gpg(["--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--local-user", ed[-16:],
         "--compress-algo", "0", "--sign", "--output", rel(os.path.join(notes, "lab-signed.pgp")),
         rel(note)], home)
    gpg(["--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--local-user", ed[-16:],
         "--sign", "--output", rel(os.path.join(notes, "lab-signedz.pgp")), rel(note)], home)
    gpg(["--trust-model", "always", "--recipient", ed[-16:], "--compress-algo", "0", "--encrypt",
         "--output", rel(os.path.join(notes, "lab-encr.pgp")), rel(note)], home)
    gpg(["--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--symmetric",
         "--cipher-algo", "AES256", "--compress-algo", "0", "--output",
         rel(os.path.join(notes, "lab-sym.pgp")), rel(note)], home)


def listing(path, home):
    """Every packet gpg prints for the file, in print order - including those inside a wrapper."""
    out, err = gpg(["--list-packets", rel(path)], home, allow_fail=True)
    text = out.decode("utf8", "replace")
    found, current = [], None
    for line in text.splitlines():
        header = HEADER.match(line.strip())
        if header:
            off, ctb, tag, hlen, plen, rest = header.groups()
            current = {
                "off": int(off), "ctb": "%02x" % int(ctb, 16), "tag": int(tag), "hlen": int(hlen),
                "plen": int(plen), "flags": rest.split(), "label": None, "detail": [],
            }
            found.append(current)
            continue
        label = LABEL.match(line.strip())
        if label and current is not None:
            current["label"] = label.group(1)
            if label.group(2):
                current["detail"].append(label.group(2).strip())
            continue
        if current is not None and line[:1] in ("\t", " "):
            current["detail"].append(line.strip())
    if not found:
        raise SystemExit("{} yields no packets ({})".format(path, err.strip()))
    return found, text


def read_length(raw, at, ctb):
    """(payload, octets used, special) for the length field at `at`, or None when it does not fit.

    `special` is `indeterminate` (the body runs to the end of the file) or `partial` (a power-of-two chain
    the walk cannot size). The two header formats count their length octets in different ways, and this is
    the mapping the observed listings show:

      old (bit 6 clear) - the two low bits of the tag octet are the length octet count: 0 -> one, 1 -> two,
        2 -> four, 3 -> indeterminate, and the octets are a plain big-endian number. The ed25519 export
        reaches only the one-octet branch (every packet under 192 bytes); the rsa2048 export needs the
        two-octet one for its 269- and 334-byte packets, and its compressed cousin shows indeterminate.
      new (bit 6 set) - the first length octet selects the form: below 192 is the value, 192..223 adds a
        second octet with 192 subtracted, 224 is the partial chain, 255 a four-octet length. The SEIPD
        packets here are new-format with a one-octet length (87 bytes).

    A four-octet old length and the partial chain are implemented from the table but not demonstrated by
    any fixture, so the report shows which header form it used and nothing else about them is claimed.
    """
    if at >= len(raw):
        return None
    first = raw[at]
    if ctb & 0x40:
        if first < 192:
            return first, 1, None
        if first < 224:
            if at + 2 > len(raw):
                return None
            return ((first - 192) << 8) + raw[at + 1] + 192, 2, None
        if first == 224:
            return 0, 1, "partial"
        if first == 255:
            if at + 5 > len(raw):
                return None
            return int.from_bytes(raw[at + 1:at + 5], "big"), 5, None
        return None
    kind = ctb & 3
    if kind == 3:
        return 0, 0, "indeterminate"
    need = (1, 2, 4)[kind]
    if at + need > len(raw):
        return None
    return int.from_bytes(raw[at:at + need], "big"), need, None


def walk(raw):
    """The top-level packet walk: the reader's own claim about these bytes, tile or fail."""
    packets, at, broken, ends, opaque = [], 0, 0, False, False
    while at < len(raw):
        ctb = raw[at]
        if not ctb & 0x80:
            break
        fmt = "new" if ctb & 0x40 else "old"
        tag = (ctb & 0x3F) if fmt == "new" else ((ctb >> 2) & 0x0F)
        read = read_length(raw, at + 1, ctb)
        if read is None:
            broken += 1
            break
        plen, used, special = read
        body = at + 1 + used
        if special == "partial":
            broken += 1
            break
        if special == "indeterminate":
            packets.append({"off": at, "ctb": "%02x" % ctb, "format": fmt, "tag": tag, "hlen": body - at,
                            "plen": None, "indeterminate": True})
            ends = True
            opaque = tag in OPAQUE
            break
        if body + plen > len(raw):
            broken += 1
            break
        packets.append({"off": at, "ctb": "%02x" % ctb, "format": fmt, "tag": tag, "hlen": body - at,
                        "plen": plen, "indeterminate": False})
        at = body + plen
        ends = at == len(raw)
        if tag in OPAQUE:
            opaque = True
            break
    return packets, broken, ends, opaque


def rows_for(raw, packets, broken, ends):
    kind = "message"
    if packets and packets[0]["tag"] in KEY_TAGS:
        kind = "key"
    rows = ["openpgp\tpackets\t{}\tbytes\t{}\tends\t{}\tbroken\t{}".format(
        len(packets), len(raw), "yes" if ends else "no", broken), "kind\t{}".format(kind)]
    shown = packets[:MAX_PACKETS]
    for each in shown:
        name = NAMES.get(each["tag"], "tag {}".format(each["tag"]))
        if each["indeterminate"]:
            rows.append("packet\t{}\t{}\ttag\t{}\t{}\thlen\t{}\tplen\t-\tindeterminate".format(
                each["off"], each["format"], each["tag"], name, each["hlen"]))
            continue
        rows.append("packet\t{}\t{}\ttag\t{}\t{}\thlen\t{}\tplen\t{}".format(
            each["off"], each["format"], each["tag"], name, each["hlen"], each["plen"]))
    if len(packets) > MAX_PACKETS:
        rows.append("stopped\tpackets\t{}".format(MAX_PACKETS))
    details = []
    for index, each in enumerate(shown):
        body = raw[each["off"] + each["hlen"]:each["off"] + each["hlen"] + (each["plen"] or 0)]
        tag = each["tag"]
        if tag in OPAQUE:
            details.append((index, "descend\tno\t{}".format(OPAQUE[tag])))
        elif tag == 13:
            text = body.decode("utf8", "replace")
            if "\n" in text or "\x00" in text:
                raise SystemExit("a user ID packet that is not one printable line")
            details.append((index, "userid\t{}".format(text)))
        elif tag == 11:
            if len(body) < 6:
                raise SystemExit("literal packet too short to hold its fields")
            named = body[1]
            name = body[2:2 + named].decode("utf8", "replace")
            framing = 2 + named + 4
            if len(body) < framing:
                raise SystemExit("literal packet shorter than its own fields")
            details.append((index, "literal\t{}\tbody\t{}\tfields\t{}".format(
                name, len(body) - framing, framing)))
        elif tag == 2:
            if len(body) < 4:
                raise SystemExit("signature packet without its four leading octets")
            details.append((index, "sig\tv{}\tfull\tsigclass\t0x{:02x}\tpubkey\t{}\thash\t{}".format(
                body[0], body[1], body[2], body[3])))
        elif tag == 4:
            details.append((index, "sig\tv{}\tonepass".format(body[0]) if body else "sig\t-\tonepass"))
        elif tag == 3:
            if len(body) < 4:
                raise SystemExit("symkey enc packet without its four leading octets")
            details.append((index, "skesf\tv{}\tcipher\t{}\ts2k\t{}\thash\t{}".format(
                body[0], body[1], body[2], body[3])))
        elif tag == 1:
            # version, then the eight-octet key ID, then the algorithm - the order the packet spells, which
            # is not the order gpg's sentence lists them in. Reading algo at body[1] returns 65, the first
            # byte of the key ID, and the cross-check below is what catches that.
            if len(body) < 10:
                raise SystemExit("pubkey enc packet too short for version, key ID and algo")
            details.append((index, "pkesf\tv{}\talgo\t{}\tkeyid\t{}".format(
                body[0], body[9], "".join("%02x" % each for each in body[1:9]))))
        elif tag in KEY_TAGS:
            if len(body) < 6:
                raise SystemExit("key packet without version, time and algo")
            details.append((index, "key\tv{}\talgo\t{}\tcreated\t{}".format(
                body[0], body[5], int.from_bytes(body[1:5], "big"))))
    return rows + [row for _, row in details], details


def check(name, raw, packets, printed, details):
    """gpg's listing must start with the walk, packet for packet, field for field, name for name."""
    if len(printed) < len(packets):
        raise SystemExit("{}: gpg prints {} packets, the walk found {}".format(
            name, len(printed), len(packets)))
    for mine, theirs in zip(packets, printed):
        for field, label in (("off", "offset"), ("tag", "tag"), ("hlen", "header length")):
            if mine[field] != theirs[field]:
                raise SystemExit("{}: {} at off {} is {} for the walk and {} for gpg".format(
                    name, label, mine["off"], mine[field], theirs[field]))
        sized = 0 if mine["indeterminate"] else mine["plen"]
        if sized != theirs["plen"] or ("indeterminate" in theirs["flags"]) != mine["indeterminate"]:
            raise SystemExit("{}: payload at off {} is {} for the walk and {} {} for gpg".format(
                name, mine["off"], mine["plen"], theirs["plen"], theirs["flags"]))
        coded = (int(theirs["ctb"], 16) >> 2) & 0x0F if not int(theirs["ctb"], 16) & 0x40 \
            else int(theirs["ctb"], 16) & 0x3F
        if coded != theirs["tag"]:
            raise SystemExit("{}: ctb {} does not encode tag {}".format(name, theirs["ctb"], theirs["tag"]))
        spelled = NAMES.get(mine["tag"])
        if spelled and theirs["label"] != spelled:
            raise SystemExit("{}: tag {} is {!r} to gpg, {!r} here".format(
                name, mine["tag"], theirs["label"], spelled))
    for index, row in details:
        theirs = printed[index]
        line = "{} {}".format(theirs["label"] or "", " ".join(theirs["detail"]))
        fields = row.split("\t")
        head = fields[0]
        if head == "sig" and len(fields) > 2 and fields[2] == "full":
            found, digest = SIG_CLASS.search(line), SIG_DIGEST.search(line)
            algo = SIG_ALGO.search(line)
            if not (found and digest):
                raise SystemExit("{}: a signature packet gpg does not spell out: {!r}".format(name, line))
            if int(found.group(1), 16) != int(fields[4], 16):
                raise SystemExit("{}: sigclass {} here, {} for gpg".format(name, fields[4], found.group(1)))
            if int(digest.group(1)) != int(fields[8]):
                raise SystemExit("{}: hash {} here, {} for gpg".format(name, fields[8], digest.group(1)))
            if algo and int(algo.group(1)) != int(fields[6]):
                raise SystemExit("{}: pubkey {} here, {} for gpg".format(name, fields[6], algo.group(1)))
        elif head == "userid":
            if '"{}"'.format(fields[1]) not in line:
                raise SystemExit("{}: gpg does not print the user ID the walk read".format(name))
        elif head == "literal":
            found = LITERAL_NAME.search(line)
            sized = LITERAL_RAW.search(line)
            if not found or found.group(1) != fields[1]:
                raise SystemExit("{}: gpg does not name the literal file {}".format(name, fields[1]))
            if not sized or int(sized.group(1)) != int(fields[3]) or int(sized.group(1)) != len(NOTE):
                raise SystemExit("{}: raw body {} is not what gpg reads".format(name, fields[3]))
        elif head == "key":
            found = KEY_DETAIL.search(line)
            if not found:
                raise SystemExit("{}: gpg spells no key packet detail: {!r}".format(name, line))
            if (int(found.group(1)), int(found.group(2)), int(found.group(3))) != \
                    (int(fields[1][1:]), int(fields[3]), int(fields[5])):
                raise SystemExit("{}: key {} {} {} here, {} {} {} for gpg".format(
                    name, fields[1], fields[3], fields[5],
                    found.group(1), found.group(2), found.group(3)))
        elif head == "skesf":
            found = SKESF.search(line)
            if not found or (int(found.group(1)), int(found.group(2)), int(found.group(4)),
                             int(found.group(5))) != (int(fields[1][1:]), int(fields[3]), int(fields[5]),
                                                      int(fields[7])):
                raise SystemExit("{}: symkey packet fields disagree with gpg: {!r}".format(name, line))
        elif head == "pkesf":
            found = PKESF.search(line)
            if not found or (found.group(1), found.group(2), found.group(3).lower()) != (
                    fields[1][1:], fields[3], fields[5]):
                raise SystemExit("{}: pubkey enc fields disagree with gpg: {!r} vs {}".format(
                    name, line, fields[1:]))


def describe(name, path, home):
    raw = open(path, "rb").read()
    packets, broken, ends, opaque = walk(raw)
    if not packets or not ends or broken:
        raise SystemExit("{} does not tile: {} packets, ends {}, broken {}".format(
            name, len(packets), ends, broken))
    printed, _ = listing(path, home)
    rows, details = rows_for(raw, packets, broken, ends)
    check(name, raw, packets, printed, details)
    entry = {
        "bytes": len(raw),
        "packets": len(packets),
        "tiles": True,
        "ends": ends,
        "opaque": opaque,
        "rows": rows,
        "walk": packets,
        # gpg's own words for each packet, kept so a test can assert that a field the row prints is a
        # field the witness printed too, rather than trusting this script's parsing of it.
        "gpg": [dict(each) for each in printed],
    }
    print("== {} {} bytes, {} packets, opaque {}".format(name, len(raw), len(packets), opaque))
    for row in rows:
        print("    ", repr(row))
    return entry


def main():
    probe_only = "--probe-only" in sys.argv
    names = ["lab-key.pgp", "lab-rsa.pgp", "lab-signed.pgp", "lab-signedz.pgp", "lab-encr.pgp",
             "lab-sym.pgp"]
    if probe_only:
        for name in names:
            if not os.path.exists(os.path.join(OUT, name)):
                raise SystemExit("--probe-only needs the committed fixtures; {} is missing".format(name))
        source, home = OUT, WORK
    else:
        build(WORK, NOTES)
        source, home = NOTES, WORK
    report = {}
    for name in names:
        report[name] = describe(name, os.path.join(source, name), home)
    with open(os.path.join(OUT, "pgp.probe.json"), "w", encoding="utf8", newline="\n") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print("wrote pgp.probe.json")
    if not probe_only:
        for name in names:
            shutil.copyfile(os.path.join(source, name), os.path.join(OUT, name))
            print("copied", name, os.path.getsize(os.path.join(OUT, name)), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
