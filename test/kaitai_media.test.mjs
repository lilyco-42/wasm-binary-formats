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

// The MOV spec is big-endian, so the same four characters arrive as a different number.
const ccBe = (text) => ((text.charCodeAt(0) << 24) | (text.charCodeAt(1) << 16)
  | (text.charCodeAt(2) << 8) | text.charCodeAt(3)) >>> 0;

// A `contents:` member of one byte is handed back as raw bytes by the JS runtime, not as a number.
const byteOf = (value) => (value instanceof Uint8Array ? value[0] : value);

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
    assert.equal(byteOf(page.version), 0, 'the spec pins version 0 as a constant');
    assert.equal(byteOf(page.reserved1), 0, 'the five bits before the flags are zero');
  });
  const last = ogg.pages[ogg.pages.length - 1];
  assert.equal(Number(last.granulePos), 8820,
    'sample count for vorbis: -t 0.2 at 44100 Hz, matching ffprobe and engine/tests/media.rs');
  assert.equal(ogg.pages[0].numSegments, 1, 'the bootstrap page holds one 30-byte packet');
  assert.ok(ogg.pages[0].isBeginningOfStream, 'the first page is the beginning of the stream');
  assert.ok(last.isEndOfStream, 'and the last one ends it');
});

test('Pcx: the header Pillow wrote comes back field for field', () => {
  const pcx = model('Pcx', 'tiny.pcx');
  assert.equal(byteOf(pcx.hdr.magic), 10, 'the manufacturer code is 0x0A');
  assert.equal(pcx.hdr.version, 5, 'PCX version 5, i.e. 256 colours with an RLE encoder');
  assert.equal(pcx.hdr.encoding, 1, '1 is run-length encoded');
  assert.equal(pcx.hdr.bitsPerPixel, 8);
  assert.equal(pcx.hdr.numPlanes, 1);
  // A 7x5 image is indexed 0..6 and 0..4: the window corners are inclusive, which is the classic
  // off-by-one trap in this header. (The failure message picks scalars because a generated reader
  // is full of `_root` back-references, so stringifying it throws inside the assertion itself.)
  const window = [pcx.hdr.imgXMin, pcx.hdr.imgYMin, pcx.hdr.imgXMax, pcx.hdr.imgYMax];
  assert.deepEqual(
    window,
    [0, 0, 6, 4],
    `the picture window is ${window} for a 7x5 image`
  );
  assert.equal(pcx.hdr.hdpi, 100, 'Pillow writes 100 dpi for both axes');
  assert.equal(pcx.hdr.vdpi, 100);
  // The spec only walks the trailing 769-byte VGA palette when `version == 3`, so a version 5 file
  // - which is exactly the kind that has that palette - leaves it unread. Asserting the absence
  // keeps the gap visible: PCX's credit here is the fixed header, not its colour table.
  assert.equal(pcx.palette256, undefined, 'the conditional palette is not parsed for version 5');
  assert.equal(pcx._io.size, 920);
});

test('Au: the Sun/NeXT header ffmpeg wrote agrees with its own data length', () => {
  const au = model('Au', 'media.au');
  assert.equal(Buffer.from(au.magic).toString('latin1'), '.snd');
  assert.equal(au.ofsData, 32, 'the header carries a comment past the fixed fields');
  assert.equal(au.header.dataSize, 1600);
  assert.equal(au.header.sampleRate, 8000, '-ar 8000, and ffprobe reads the same');
  assert.equal(au.header.numChannels, 1);
  assert.equal(Number(au.lenData), 1600, 'derived: data size is explicit here, not EOF-relative');
  assert.equal(au.ofsData + Number(au.lenData), au._io.size, 'header plus data is the whole file');
  // ffmpeg labels 8-bit mu-law with encoding code 1 rather than the 3 the Sun table uses for
  // G.711 mu-law, which is why the number is asserted from the bytes and not from the codec name.
  assert.equal(au.header.encoding, 1);
});

test('Avi: the pinned spec cannot read a real ffmpeg AVI, so the AVI credit rests on our reader', () => {
  // media/avi.ksy steps from one block to the next by the declared size alone and never skips
  // RIFF's odd-size padding byte. ffmpeg's file has five such blocks nested inside the LISTs -
  // the ISFT software chunk is 13 bytes and the 00dc video frames are 41, 23, 21 and 33 - so the
  // generated reader desyncs and runs off the end. Asserting the failure keeps the gap on the
  // record and will fail loudly if the spec is ever fixed upstream.
  assert.throws(() => model('Avi', 'media.avi'), /end of data|EOF|out of bounds/i,
    'the generated AVI reader should still be unable to walk this file');
});

test('QuicktimeMov: the same box sizes the Rust walk reported', () => {
  const mov = model('QuicktimeMov', 'media.mp4');
  const items = mov.atoms.items;
  assert.deepEqual(items.map((item) => item.len32), [32, 8, 2977, 949],
    'ftyp, free, mdat, moov - exactly the boxes engine/tests/media.rs lists');
  assert.equal(items.reduce((sum, item) => sum + item.len32, 0), 3966, 'the walk consumes the file');
  assert.equal(items[0].atomType, ccBe('ftyp'));
  assert.equal(items[3].atomType, ccBe('moov'));
  const children = items[3].body.items;
  assert.deepEqual(children.map((item) => item.len32), [108, 736, 97],
    'mvhd, trak, udta inside moov');
  assert.equal(children[0].atomType, ccBe('mvhd'));
});
