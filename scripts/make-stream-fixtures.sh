#!/usr/bin/env bash
# The fixtures for engine/tests/streams.rs are written by each format's reference command-line tool
# and verified by it afterwards, so the reader under test never sees bytes this repo produced.
#
# Names are prefixed stream.* on purpose: tiny.gz is already the input of the generated Gzip
# reader assertion in test/kaitai.test.mjs, and overwriting it there broke that test the first time
# this script ran. One fixture per generator, no shared filenames.
# Every compressor is invoked directly with its own -o flag rather than through a helper that
# echoes progress: the first version of this script piped a status line into the binary output and
# produced an .xz file its own producer called corrupt, which is exactly the kind of fixture that
# must not be committed.
set -euo pipefail
out="$(cd "$(dirname "$0")/.." && pwd)/test/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

printf 'lyco stream framing fixture payload.\n%.0s' {1..12} > "$work/payload.bin"
want=$(wc -c < "$work/payload.bin")

xz    -1 -c "$work/payload.bin" > "$out/stream.xz"
bzip2 -1 -c "$work/payload.bin" > "$out/stream.bz2"
gzip  -1 -c "$work/payload.bin" > "$out/stream.gz"
lz4 -1 --no-crc -f "$work/payload.bin" "$out/stream.lz4"
zstd -1 --no-check -f "$work/payload.bin" -o "$out/stream.zst"

fail=0
check() { # file, tool
  local got
  got=$("$2" -dc "$out/$1" | wc -c)
  if [ "$got" != "$want" ]; then echo "FAIL $1: round-trips to $got, expected $want"; fail=1; else echo "ok   $1 ($(wc -c < "$out/$1") bytes, round-trips to $got)"; fi
}
check stream.xz xz
check stream.bz2 bzip2
check stream.gz gzip
check stream.lz4 lz4
check stream.zst zstd
test "$fail" = 0 || { echo "one or more fixtures failed their own tool"; exit 1; }
