#!/usr/bin/env bash
# Write the PDF fixtures the page-tree tests read, and a probe file beside each one.
#
# Two producers on purpose. Pillow's PDF driver writes objects in a order of its own and keeps every
# page box whole; the PDF writer inside Chromium's headless print path (Skia) numbers objects
# differently, writes A4 as 594.95996 points, and puts a `/Count` in the tree. A reader that passes
# on both is reading the format, not one writer's habits.
#
# The probe is a byte-level reading made with the standard library only - there is no PDF tool on
# this host - so it records what the producer wrote rather than an independent parser's opinion.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/test/fixtures"
mkdir -p "$out"

probe() { # probe <fixture> <producer> <detail> <expected page boxes>
  python - "$1" "$2" "$3" "$out" "$4" <<'PY'
import json, re, sys
path, producer_label, detail, out, expect = sys.argv[1:6]
raw = open(path, "rb").read()
boxes = [list(map(float, m.group(1).split())) for m in re.finditer(rb"/MediaBox\s*\[([^\]]*)\]", raw)]
kids = re.findall(rb"/Kids\s*\[([^\]]*)\]", raw)
first_kids = (
    [int(m.group(1)) for m in re.finditer(rb"(\d+)\s+\d+\s+R", kids[0])] if kids else []
)
root_ref = re.search(rb"/Root\s+(\d+)\s+\d+\s+R", raw)
producer = re.search(rb"/Producer \(([^)]*)\)", raw)
report = {
    "fixture": path[len(out) + 1:].replace("\\", "/"),
    "written_by": producer.group(1).decode("latin-1") if producer else producer,
    "producer": producer_label,
    "detail": detail,
    "bytes": len(raw),
    "header": raw[:8].decode("latin-1"),
    "startxref": int(re.search(rb"startxref\s+(\d+)", raw).group(1)),
    "objects": len(re.findall(rb"(?m)^(\d+) (\d+) obj", raw)),
    "xref_stream": b"/Type/XRef" in raw or b"/Type /XRef" in raw,
    "root_object": int(root_ref.group(1)) if root_ref else None,
    "count": [int(v) for v in re.findall(rb"/Count\s+(\d+)", raw)],
    "kids_first_array": first_kids,
    "mediaboxes": boxes,
}
with open(path[:-4] + ".probe.json", "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("probe", report["fixture"], report["bytes"], "bytes,", len(boxes), "page boxes")
if len(boxes) != int(expect):
    sys.exit("%s has %d page boxes, the tests expect %s" % (report["fixture"], len(boxes), expect))
PY
}

python - "$out" <<'PY'
import sys
from PIL import Image
out = sys.argv[1]
sizes = [(5, 3), (7, 4), (2, 9)]
pages = [Image.new("RGB", size, (10 * (i + 1), 120, 200)) for i, size in enumerate(sizes)]
pages[0].save(f"{out}/pillow-3p.pdf", save_all=True, append_images=pages[1:])
print("made pillow-3p.pdf", sizes)
PY
probe "$out/pillow-3p.pdf" "Pillow PDF driver" "three pages appended with save_all" 3
# tiny.pdf is written by make-media-fixtures.sh; probing it here keeps one readable record per PDF
# the page-tree tests depend on.
if [ -f "$out/tiny.pdf" ]; then
  probe "$out/tiny.pdf" "Pillow PDF driver" "single page, from make-media-fixtures.sh" 1
fi

browser=""
for candidate in \
  "/c/Program Files/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
  "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"; do
  if [ -x "$candidate" ]; then browser="$candidate"; break; fi
done

if [ -z "$browser" ]; then
  echo "skipped: no headless browser, chromium.pdf and chromium-2p.pdf stay as committed"
  exit 0
fi

work="$(cygpath -u "$(python -c 'import tempfile; print(tempfile.mkdtemp())')")"
trap 'rm -rf "$work"' EXIT
printf '<!doctype html><html><head><title>lab fixture</title></head><body><p>hello from chromium</p></body></html>' \
  > "$work/one.html"
# One format string, not several arguments: `printf` treats extra arguments as substitutions, so a
# continued string of words here silently dropped the `@page` rule and printed Letter instead of A4.
printf '<!doctype html><html><head><title>two page lab</title><style>@page{size:A4;margin:0}p{font:12pt sans-serif}</style></head><body><p>first page</p><div style="page-break-after:always"></div><p>second page</p></body></html>' \
  > "$work/two.html"

make() { # make <html> <fixture>
  "$browser" --headless=new --disable-gpu --no-sandbox \
    --user-data-dir="$(cygpath -w "$work/profile" 2>/dev/null || echo "$work/profile")" \
    --no-pdf-header-footer \
    --print-to-pdf="$(cygpath -w "$out/$2" 2>/dev/null || echo "$out/$2")" \
    "$(cygpath -w "$work/$1" 2>/dev/null || echo "$work/$1")" >/dev/null 2>&1
  echo "made $2"
}
make one.html chromium.pdf
make two.html chromium-2p.pdf
# The version is read back out of the files rather than from `--version`: a Windows browser prints
# that in the console codepage, and the mojibake landed in the probe when it was tried here.
probe "$out/chromium.pdf" "Chromium headless print-to-pdf" "default sheet, one page" 1
probe "$out/chromium-2p.pdf" "Chromium headless print-to-pdf" "@page size A4, two sheets" 2
