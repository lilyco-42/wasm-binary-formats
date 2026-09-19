// Parses the self-authored image fixtures with parsers generated from Kaitai Struct .ksy specs.
// This is the feasibility gate for using a third-party format catalogue instead of hand-writing
// one reader per format: the same bytes are checked three ways - what the generator wrote, what
// Chrome's image decoder reports, and what the generated reader reports.
//
//   node test/kaitai.test.mjs path/to/generated   (default: generated/kaitai)
import { createRequire } from 'node:module';
import { readFileSync, statSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const KaitaiStream = require('kaitai-struct/KaitaiStream');

function load(name) {
  const file = join(generatedDir, `${name}.js`);
  const bytes = statSync(file);
  return { mod: require(file), bytes: bytes.size };
}

const read = (name) => new Uint8Array(readFileSync(join(fixtures, name)));

// Passing a bare Uint8Array is the convenience form in the generated constructor, and it is the
// thing that broke: on Node 22 the reader ended up with an `_io` that had no readBytes, while an
// explicit KaitaiStream parses the same file completely. So the stream is built here, once.
const parse = (Model, bytes) => new Model(new KaitaiStream(bytes), null, null);

const CASES = [
  { format: 'Png', fixture: 'tiny.png', expected: { width: 4, height: 2 } },
  { format: 'Gif', fixture: 'tiny.gif', expected: { width: 2, height: 2 } },
  { format: 'Bmp', fixture: 'tiny.bmp', expected: { width: 3, height: 2 } },
];

const sizes = {};

for (const { format, fixture, expected } of CASES) {
  test(`${format}: the generated reader agrees with the bytes we wrote`, () => {
    const { mod, bytes } = load(format);
    sizes[format] = bytes;
    const Model = mod[format] ?? mod.default ?? mod;
    const parsed = parse(Model, read(fixture));
    const dims = format === 'Png'
      ? { width: parsed.ihdr.width, height: parsed.ihdr.height }
      : format === 'Gif'
        ? { width: parsed.logicalScreenDescriptor.screenWidth, height: parsed.logicalScreenDescriptor.screenHeight }
        : { width: parsed.dibInfo.header.imageWidth, height: parsed.dibInfo.header.imageHeight };
    assert.deepEqual(dims, expected, `${format} dimensions from ${fixture}`);
    if (format === 'Png') {
      assert.equal(parsed.ihdr.bitDepth, 8);
      assert.equal(parsed.ihdr.colorType, 2, 'truecolour');
      assert.equal(parsed.chunks.length, 3, 'tEXt, IDAT and IEND follow the IHDR');
    }
    if (format === 'Bmp') assert.equal(parsed.dibInfo.header.bitsPerPixel, 24);
  });
}

test('bundle cost per format stays small enough to ship many of them', () => {
  const known = Object.keys(sizes);
  assert.equal(known.length, CASES.length, 'every case must have been loaded first');
  const total = known.reduce((sum, key) => sum + sizes[key], 0);
  // Recorded, not asserted as a target: the number that decides whether 189 specs is realistic.
  console.log(`generated JS bytes per format: ${known.map((k) => `${k}=${sizes[k]}`).join(' ')} · mean ${(total / known.length).toFixed(0)}`);
  assert.ok(total / known.length < 40960, `mean ${total / known.length} B per parser is too big to scale`);
});
