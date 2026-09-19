// Cross-checks generated Kaitai readers against archives and images written by other tools:
// Pillow produced tiny.jpg and Python's zipfile produced tiny.zip, so the expected structure below
// comes from those implementations, not from this repo's idea of the format.
//
//   node test/kaitai_formats.test.mjs path/to/generated
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const KaitaiStream = require('kaitai-struct/KaitaiStream');

function read(format, fixture) {
  const Model = require(join(generatedDir, `${format}.js`))[format];
  return new Model(new KaitaiStream(new Uint8Array(readFileSync(join(fixtures, fixture)))), null, null);
}

test('jpeg: the marker sequence Pillow wrote comes back in order', () => {
  const jpeg = read('Jpeg', 'tiny.jpg');
  const markers = jpeg.segments.map((segment) => segment.marker);
  assert.equal(markers[0], 0xd8, 'SOI opens the file');
  assert.ok(markers.includes(0xe0), 'JFIF APP0');
  assert.ok(markers.includes(0xdb), 'quantisation tables');
  assert.ok(markers.includes(0xc0), 'baseline SOF0 carries the frame');
  assert.equal(markers[markers.length - 1], 0xda, 'SOS is last, entropy data follows unparsed');
  assert.equal(markers.length, 10, `full marker list: ${markers.map((m) => m.toString(16))}`);
  const sof = jpeg.segments.find((segment) => segment.marker === 0xc0);
  assert.equal(sof.data.length, sof.length - 2, 'the segment body matches its declared length');
});

test('zip: section kinds match the member count Python wrote', () => {
  const zip = read('Zip', 'tiny.zip');
  const counts = zip.sections.reduce((acc, section) => {
    acc[section.sectionType] = (acc[section.sectionType] ?? 0) + 1;
    return acc;
  }, {});
  assert.deepEqual(counts, { 1027: 2, 513: 2, 1541: 1 }, 'two members means two local and two central records');

  const central = zip.sections.filter((section) => section.sectionType === 513);
  assert.deepEqual(central.map((section) => section.body.compressionMethod), [8, 8], 'both deflated by zipfile');
  assert.ok(central.every((section) => section.body.crc32 > 0), 'every central record carries a CRC');

  const end = zip.sections.find((section) => section.sectionType === 1541);
  assert.equal(end.body.numCentralDirEntriesTotal, 2, 'the EOCD agrees with Python about the member count');
});
