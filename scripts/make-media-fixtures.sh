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
# AVIF is the same box framing with a different brand, so one fixture covers both readers. There is
# no HEIF muxer in this ffmpeg build, which is why `heif` is not claimed.
make tiny.avif -f lavfi -i testsrc2=size=32x24 -frames:v 1 -c:v libsvtav1
# 3GP is the same framing under another brand; it exists as a magika label of its own.
make media.3gp -f lavfi -i testsrc2=size=32x24:rate=5:duration=1 -c:v libx264 -pix_fmt yuv420p

# Matroska and its WebM profile: the EBML tree, which no Kaitai spec covers.
make media.mkv $V -c:v libx264
make media.webm $V -c:v libvpx-vp9

# Audio: RIFF, an MPEG frame chain, and two containers of their own.
make media.wav $A -ar 8000 -c:a pcm_s16le
# The AU muxer only accepts the codecs it can name in a Sun header, and 8 kHz is the rate the
# classic header describes; pcm_s16le is refused outright by ffmpeg 9 here.
make media.au $A -ar 8000 -c:a pcm_mulaw
make media.mp3 $A -c:a libmp3lame -b:a 32k
make media.flac $A -c:a flac
make media.ogg $A -c:a libvorbis -q:a 1

# AVI is RIFF again, but with the LIST nesting that webp never exercises.
make media.avi $V -c:v mpeg4 -q:v 10
# ASF/WMV/WMA share a GUID-object framing that no Kaitai spec covers. Kept small on purpose: 8 kHz
# mono for 0.2 s is 6 906 bytes, and its layout is measured in the README's next-steps section.
make media.asf $A -ar 8000 -ac 1 -c:a pcm_s16le

# PDF and PCX, from Pillow: independent writers, and both formats are ones the pinned Kaitai bundle
# has a spec for, so the same bytes get read by three implementations.
python - <<'PY'
from PIL import Image
try:
    Image.new("RGB", (5, 3), (10, 120, 200)).save("tiny.pdf")
    print("made tiny.pdf")
except Exception as exc:
    print("skipped: tiny.pdf", exc.__class__.__name__)
try:
    indexed = Image.new("P", (7, 5))
    indexed.paste(2, (0, 0, 3, 4))
    indexed.save("tiny.pcx")
    print("made tiny.pcx")
except Exception as exc:
    print("skipped: tiny.pcx", exc.__class__.__name__)
PY

# Ground truth for the files that exist.
for f in "${names[@]}"; do
  ffprobe -hide_banner -loglevel error -print_format json -show_format -show_streams "$f" \
    > "${f//./_}.probe.json" && echo "probed $f"
done
