// Real-byte assertions for the generated Kaitai media readers, against files ffmpeg wrote.
//
// This is the third opinion on the same bytes: `test/fixtures/media_*.probe.json` is what ffprobe
// read, engine/tests/media.rs is what this repo's Rust engine reads, and this file is what a reader
// generated from a third-party .ksy spec reads. The values asserted here were taken from the
// committed fixtures, and the attribute paths from the specs themselves - both are pinned in CI.
//
//   node test/kaitai_media.test.mjs path/to/generated   (default: generated/kaitai)
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

const read = (name) => new Uint8Array(readFileSync(join(fixtures, name)));

// The generated modules export their class under a name we would have to guess at (id3v2_4 -> ?), so
// take the class the file exports rather than asserting on the spelling: a module that exports
// nothing callable is a real failure and falls through to the constructor throwing.
function load(name) {
  const file = join(generatedDir, `${name}.js`);
  assert.ok(statSync(file).size > 0, `${file} is empty`);
  const mod = require(file);
  const Model = mod[name] ?? mod.default
    ?? Object.values(mod).find((value) => typeof value === 'function')
    ?? mod;
  return Model;
}

const model = (name, fixture) => {
  const Model = load(name);
  return new Model(new KaitaiStream(read(fixture)), null, null);
};

// A four-character code as the little-endian u32 the specs read it as.
const cc = (text) => ((text.charCodeAt(0)) | (text.charCodeAt(1) << 8)
  | (text.charCodeAt(2) << 16) | (text.charCodeAt(3) << 24)) >>> 0;

test('Wav: the generated reader walks the chunks ffmpeg wrote', () => {
  const wav = model('Wav', 'media.wav');
  assert.equal(wav.chunk.len, 3278 - 8, 'RIFF length is the file size minus its own header');
  assert.equal(wav.formType, cc('WAVE'), 'the form type is WAVE');
  const sizes = wav.subchunks.map((entry) => entry.chunk.len);
  const ids = wav.subchunks.map((entry) => entry.chunk.id);
  assert.ok(ids.includes(cc('fmt ')), `fmt chunk present, ids ${ids}`);
  assert.ok(ids.includes(cc('data')), `data chunk present, ids ${ids}`);
  assert.equal(sizes[ids.indexOf(cc('data'))], 3200, '0.2 s of 8 kHz mono s16le');
  assert.equal(sizes[ids.indexOf(cc('fmt '))], 16, 'a classic PCM format chunk');
  // Chunk lengths plus their 8-byte headers must tile what the RIFF body holds.
  const tiled = wav.subchunks.reduce((sum, entry) => sum + entry.chunk.len + 8, 0);
  assert.equal(tiled, wav.chunk.len - 4, 'subchunk sizes account for the form type and every chunk');
});

test('Riff: the generic reader agrees with the WAVE-specific one', () => {
  const riff = model('Riff', 'media.wav');
  assert.equal(riff.chunk.id, cc('RIFF'));
  assert.equal(riff.chunk.len, 3270);
  assert.ok(riff.subchunks.length >= 2, 'fmt and data at least');
  assert.equal(riff.parentChunkData.formType, cc('WAVE'));
});

test('Ogg: pages, sequence numbers and the granule position ffmpeg wrote', () => {
  const ogg = model('Ogg', 'media.ogg');
  assert.ok(ogg.pages.length >= 2, `${ogg.pages.length} pages, expected a multi-page stream`);
  ogg.pages.forEach((page, index) => {
    assert.equal(page.pageSeqNum, index, `page ${index} carries sequence number ${index}`);
    assert.equal(page.bitstreamSerial, ogg.pages[0].bitstreamSerial, 'one logical bitstream');
    assert.equal(page.version, 0, 'the spec pins version 0 as a constant');
  });
  assert.equal(ogg.pages[ogg.pages.length - 1].granulePos, 8820,
    'sample count for vorbis: -t 0.2 at 44100 Hz, matching ffprobe and engine/tests/media.rs');
  assert.equal(ogg.pages[0].isBeginningOfStream, true, 'the first page is the bootstrap page');
  assert.equal(ogg.pages[ogg.pages.length - 1].isEndOfStream, true, 'and the last one ends it');
});

test('Avi: the RIFF/AVI header and block list ffmpeg wrote', () => {
  const avi = model('Avi', 'media.avi');
  assert.equal(Buffer.from(avi.magic1).toString('latin1'), 'RIFF');
  assert.equal(Buffer.from(avi.magic2).toString('latin1'), 'AVI ');
  assert.equal(avi.fileSize, 7162 - 8);
  const blocks = avi.data.entries;
  assert.ok(blocks.length >= 2, `${blocks.length} top-level blocks`);
  const fourCc = (value) => String.fromCharCode(value & 0xff, (value >> 8) & 0xff,
    (value >> 16) & 0xff, (value >> 24) & 0xff);
  const names = blocks.map((block) => fourCc(block.fourCc >>> 0));
  assert.ok(names.includes('hdrl'), `the header LIST is one of ${names}`);
  assert.ok(names.includes('movi'), `the media LIST is one of ${names}`);
  assert.ok(names.includes('idx1'), `the index is last: ${names}`);
  assert.equal(names[names.length - 1], 'idx1');
  assert.equal(names[names.length - 2], 'movi');
});

test('QuicktimeMov: the same box sizes the Rust walk reported', () => {
  const mov = model('QuicktimeMov', 'media.mp4');
  const items = mov.atoms.items;
  assert.deepEqual(items.map((item) => item.len32), [32, 8, 2977, 949],
    'ftyp, free, mdat, moov - exactly the boxes engine/tests/media.rs lists');
  assert.equal(items.reduce((sum, item) => sum + item.len32, 0), 3966, 'the walk consumes the file');
  assert.equal(items[0].atomType, cc('ftyp'));
  assert.equal(items[3].atomType, cc('moov'));
  const children = items[3].body.items;
  assert.deepEqual(children.map((item) => item.len32), [108, 736, 97],
    'mvhd, trak, udta inside moov');
});
