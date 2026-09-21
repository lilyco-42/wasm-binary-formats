"""Produce and check the JSONC fixtures - JSON with comments and trailing commas.

Two independent readers check this format, and they disagree on purpose:
`json.loads` is *strict* JSON and must refuse the file, while Microsoft's
`jsonc-parser` - the parser VS Code uses for its own settings - must accept it and
hand back the same tree. A reader that only agreed with one of them could be wrong
about what makes this format what it is: the strict refusal is the difference between
a JSONC file and a JSON file, and the tree is the content.

    temp/venv/Scripts/python.exe scripts/make-jsonc-fixtures.py

`jsonc-parser` is a git-ignored npm dependency (MIT, `microsoft/node-jsonc-parser`): install it with
`npm install jsonc-parser` in the repo root, which is where Node looks for it from. The fixtures are
authored here, because a text format has no producer to ask: what the witness settles is not the bytes
but what they mean, and every claim the reader makes is checked against that.
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")
NODE = os.path.join(ROOT, "node_modules")

# A settings file of the shape VS Code actually keeps: two comment styles, a trailing
# comma, and the two traps a scanner has to survive - `//` inside a string, and `/*`
# inside a string.
SETTINGS = """\
// Editor settings for this workspace.
// The second line is a comment too, and a block comment follows.
{
  "editor.formatOnSave": true,
  "editor.tabSize": 4,
  "window.title": "${activeEditorShort}${separator}my workspace",
  "docs.homepage": "https://example.test/docs",
  // A URL is not a comment marker: "https://example.test/x" lives inside a string.
  "files.exclude": {
    "**/tmp": true,
    "**/*.log": false,
  },
  "search.exclude": ["out", "dist",],
  "editor.rulers": [80, 100, 120],
  /* a block comment
     across lines, with a brace { inside it */
  "workbench.colorCustomizations": {
    "editor.background": "#1e1e1e",
  },
  "preview.opacity": 0.75,
  "preview.indent": -1,
  "preview.theme": null,
}
"""

# A file whose only un-commenting is a trailing comma: still JSONC by structure, and
# still refused by strict JSON, but with no comment to find.
TRAILING = """\
{
  "name": "trailing-comma-only",
  "count": 3,
}
"""

# An unterminated block comment: no reader should call this parsed.
BROKEN = """\
{
  "a": 1,
  /* never closed
"""


def witness(source, path):
    """What Microsoft's parser says: the tree it builds, the comment spans it scans, and
    whether it reported any errors."""
    script = """
const parser = require('jsonc-parser');
const fs = require('fs');
const text = fs.readFileSync(process.argv[2], 'utf8');
const errors = [];
const tree = parser.parseTree(text, errors);
const scanner = parser.createScanner(text, false);
const kinds = [];
const scanErrors = [];
// The scanner's own numbering: LineCommentTrivia 12, BlockCommentTrivia 13, EOF 17 - and after
// EOF it keeps answering 17, so the loop has to stop on the token, not on zero.
let previous = -1;
for (let guard = 0; guard < 100000; guard += 1) {
  const token = scanner.scan();
  const offset = scanner.getTokenOffset();
  if (token === 17 || offset === previous) break;
  previous = offset;
  // One trivia token can hold several comments and carries the whitespace before them, so the
  // count is of the comment openers that start a line (a `//` inside a comment's own text is not
  // one) and of `/*` for blocks, which cannot nest.
  if (token === 12) {
    const value = scanner.getTokenValue();
    for (const line of value.split(String.fromCharCode(10))) {
      if (line.trim().startsWith('//')) kinds.push('line');
    }
  } else if (token === 13) {
    const value = scanner.getTokenValue();
    for (let at = 0; ; at += 2) {
      const found = value.indexOf('/*', at);
      if (found < 0) break;
      kinds.push('block');
      at = found;
    }
  }
  const bad = scanner.getTokenError();
  if (bad !== 0) scanErrors.push(parser.ScanError[bad]);
}
// parseTree nodes carry a `parent` pointer, so the tree cannot be stringified as it stands.
const detach = (key, value) => key === 'parent' ? undefined : value;
console.log(JSON.stringify({
  tree: tree,
  parse: parser.parse(text),
  comments: kinds,
  errors: errors,
  scanErrors: scanErrors,
  stripped: parser.stripComments(text),
}, detach));
"""
    out = subprocess.run(["node", "-e", script, "node", path], capture_output=True,
                         stdin=subprocess.DEVNULL, timeout=120,
                         env=dict(os.environ, NODE_PATH=NODE))
    if out.returncode != 0:
        raise SystemExit("jsonc-parser failed: %s" % out.stderr.decode("utf-8", "replace")[:400])
    return json.loads(out.stdout.decode("utf-8"))


def pair(node):
    """A property node is `[key, value]` in `children` - the parser gives no `key`/`value`
    fields, which is the first thing a reader of this tree gets wrong."""
    children = node.get("children") or []
    return children[0], children[1]


def scalar_spelling(text, node):
    """Every scalar row is the source spelling of the value, so the generator checks that this
    fixture's scalars are written the way both readers would print them - and refuses the fixture
    if a number or string ever makes that a lie."""
    raw = text[node["offset"]:node["offset"] + node["length"]]
    want = json.dumps(node.get("value"), ensure_ascii=False)
    if node["type"] in ("number", "string") and raw != want:
        raise SystemExit("%s: the file writes %r, the reader would print %r"
                         % (node["type"], raw, want))
    return raw


def trailing_commas(node, text):
    """One per container whose last member is followed by a comma before the closing bracket.

    The gap is cut from the file at the offsets the witness tree reports, so it holds nothing but the
    whitespace, the comma and the bracket - a fixture that puts a comment there is refused rather than
    guessed at, because `stripComments` collapses the text it removes and offsets would then lie."""
    children = node.get("children") or []
    count = 0
    if node["type"] in ("object", "array") and children:
        last = children[-1]
        gap = text[last["offset"] + last["length"]:node["offset"] + node["length"]]
        # A container's own span runs to just past its closing bracket, and a property node's stops
        # at its value, so what is left between them is the comma - if the file wrote one.
        closer = "}" if node["type"] == "object" else "]"
        if not re.fullmatch(r"[\s,]*" + re.escape(closer), gap):
            raise SystemExit("a container closes on %r, which is not a comma and whitespace" % gap)
        if gap.count(",") > 1:
            raise SystemExit("the gap %r holds more than one comma" % gap)
        count += gap.count(",")
    for child in children:
        count += trailing_commas(child, text)
    return count


def walk(node, path, out, depth=1, text=""):
    """The rows, in the order a reader that stops at a cap would emit them: a member, then
    everything under it."""
    kind = node["type"]
    children = node.get("children") or []
    if kind == "object":
        out.append((path, depth, kind, str(len(children))))
        for child in children:
            key, value = pair(child)
            walk(value, "%s.%s" % (path, key["value"]), out, depth + 1, text)
        return
    if kind == "array":
        out.append((path, depth, kind, str(len(children))))
        for number, child in enumerate(children):
            walk(child, "%s[%d]" % (path, number), out, depth + 1, text)
        return
    spelled = (scalar_spelling(text, node) if kind in ("number", "string")
               else json.dumps(node.get("value")))
    out.append((path, depth, kind, spelled))


def main():
    import tempfile
    work = tempfile.mkdtemp(prefix="jsonc")
    written = {}
    for name, text in (("lab.jsonc", SETTINGS), ("trailing.jsonc", TRAILING),
                       ("broken.jsonc", BROKEN)):
        path = os.path.join(work, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        written[name] = (path, text)
    probe = {}
    for name, (path, text) in written.items():
        found = witness(text, path)
        try:
            json.loads(text)
            strict = "yes"
        except ValueError:
            strict = "no"
        root = found["tree"]
        # Comment removal has to leave the comments out and the content in: the stripped text
        # keeps every top-level key the tree has, and no line of it starts with a comment marker.
        # (It may still carry a trailing comma, which is a separate fact from having comments, and
        # it is not offset-preserving, so the comma count below is taken from the file itself.)
        trailing = 0
        if root and found["tree"]["type"] == "object":
            stripped_lines = [each.strip() for each in found["stripped"].splitlines()]
            if [each for each in stripped_lines if each.startswith("//") or each.startswith("/*")]:
                raise SystemExit("%s: stripComments left a comment in" % name)
            for child in root.get("children") or []:
                key, _value = pair(child)
                if key["value"] not in (found["parse"] or {}):
                    raise SystemExit("%s: %s is in the tree but not in the parsed value"
                                     % (name, key["value"]))
        rows = []
        # A scanner error means the file does not finish what it starts; the rows are then not
        # expected at all, and the probe says so rather than listing a tree nobody should claim.
        if root and root["type"] in ("object", "array") and not found["scanErrors"]:
            lines = [c for c in found["comments"] if c == "line"]
            blocks = [c for c in found["comments"] if c == "block"]
            listed = []
            for child in root.get("children") or []:
                key, value = pair(child)
                walk(value, key["value"], listed, 1, text)
            trailing = trailing_commas(root, text)
            rows.append("jsonc\tmembers\t%d\tline\t%d\tblock\t%d\ttrailing\t%d\tstrict\t%s\tdepth\t%d\tbytes\t%d"
                        % (len(root.get("children") or []), len(lines), len(blocks), trailing,
                           strict,
                           max((each[1] for each in listed), default=0),
                           len(text.encode("utf-8"))))
            rows += ["key\t%s\t%d\t%s\t%s" % each for each in listed]
        probe[name] = {
            "bytes": len(text.encode("utf-8")),
            "strict": strict,
            "comments": found["comments"],
            "trailing": trailing,
            "errors": found["errors"],
            "scanErrors": found["scanErrors"],
            "rows": rows,
            "parse": found["parse"],
        }
    # The gates this repo writes its own fixtures under: the witness has to see what the fixture
    # claims, strict JSON has to refuse what the parser accepts, and a broken comment has to be
    # reported as broken rather than silently absorbed.
    lab = probe["lab.jsonc"]
    if sorted(lab["comments"]) != ["block", "line", "line", "line"]:
        raise SystemExit("the witness did not find the four comments: %s" % lab["comments"])
    # Four containers close on a trailing comma here: the nested object, the nested array, the
    # colour object and the root. A count that came out differently means the gap scan is not
    # measuring what it claims, and the reader's `trailing` column would be a guess.
    if lab["trailing"] != 4:
        raise SystemExit("the settings file holds four trailing commas, the witness counted %d"
                         % lab["trailing"])
    if lab["strict"] != "no":
        raise SystemExit("a file with comments must not parse as strict JSON")
    trailing = probe["trailing.jsonc"]
    if trailing["strict"] != "no" or trailing["comments"]:
        raise SystemExit("a trailing comma alone is still not strict JSON, and has no comment")
    if trailing["trailing"] != 1:
        raise SystemExit("one trailing comma was written, the witness counted %d"
                         % trailing["trailing"])
    broken = probe["broken.jsonc"]
    if "UnexpectedEndOfComment" not in broken["scanErrors"]:
        raise SystemExit("the unterminated comment was not reported: %s" % broken["scanErrors"])
    if broken["rows"]:
        raise SystemExit("a file that does not finish its comment lists no rows")
    for name in ("lab.jsonc", "trailing.jsonc", "broken.jsonc"):
        with open(os.path.join(FIX, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(written[name][1])
    with open(os.path.join(FIX, "jsonc.probe.json"), "w", encoding="utf-8") as handle:
        json.dump(probe, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    for name, body in probe.items():
        print("%s: %d bytes, strict %s, comments %s, errors %s, %d rows"
              % (name, body["bytes"], body["strict"], body["comments"], body["errors"],
                 len(body["rows"])))
        for row in body["rows"][:6]:
            print("   ", row)


if __name__ == "__main__":
    main()
