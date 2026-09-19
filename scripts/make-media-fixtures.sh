#!/usr/bin/env bash
# Media fixtures for the container readers, written by ffmpeg. ffprobe - a parser we do not
# control - is run over every file it produces and its JSON is kept next to the fixture, so the
# Rust and JS tests assert against numbers taken from that independent reading rather than from
# offsets we chose ourselves. That is what stops a wrong field offset from passing because it is
# wrong in the reader and in the test at the same time.
#
#   bash scripts/make-media-fixtures.sh [out_dir]   (default: test/fixtures)
#
# Encoder availability differs between builds, so a missing one prints `skipped:` and the rest of
# the run continues; a fixture that is absent for that reason is visible rather than silently
# assumed to be there.
set -u
out=${1:-test/fixtures}
mkdir -p "$out"
cd "$out" || exit 1

# Synthetic sources: deterministic, a few kilobytes, and no third-party media to licence.
V='-f lavfi -i testsrc2=size=64x48:rate=10:duration=1'
A='-f lavfi -i sine=frequency=440:duration=0.2'

names=()
make() { # make <name> <encoder args...>
  local name=$1; shift
  if ffmpeg -hide_banner -loglevel error -nostdin -y "$@" "$name"; then
    echo "made $name $(wc -c < "$name") B"
    names+=("$name")
  else
    rm -f "$name"
    echo "skipped: $name"
  fi
}

# ISO base media file format.
make media.mp4 $V -c:v libx264 -pix_fmt yuv420p -g 5
make media-av.mp4 $V -i "sine=frequency=440:duration=1" -c:v libx264 -c:a aac -shortest

# Matroska and its WebM profile: the EBML tree, which no Kaitai spec covers.
make media.mkv $V -c:v libx264
make media.webm $V -c:v libvpx-vp9

# Audio: RIFF, an MPEG frame chain, and two containers of their own.
make media.wav $A -ar 8000 -c:a pcm_s16le
make media.mp3 $A -c:a libmp3lame -b:a 32k
make media.flac $A -c:a flac
make media.ogg $A -c:a libvorbis -q:a 1

# AVI is RIFF again, but with the LIST nesting that webp never exercises.
make media.avi $V -c:v mpeg4 -q:v 10

# PDF, from Pillow: an independent writer, and the object/xref layer is what the reader claims to
# walk. PSD is not saved here because Pillow can only read it, so its fixture stays handwritten.
python - <<'PY'
from PIL import Image
try:
    Image.new("RGB", (5, 3), (10, 120, 200)).save("tiny.pdf")
    print("made tiny.pdf")
except Exception as exc:
    print("skipped: tiny.pdf", exc.__class__.__name__)
PY

# Ground truth for the files that exist.
for f in "${names[@]}"; do
  ffprobe -hide_banner -loglevel error -print_format json -show_format -show_streams "$f" \
    > "${f//./_}.probe.json" && echo "probed $f"
done
