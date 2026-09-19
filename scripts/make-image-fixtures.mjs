// Writes the tiny, self-authored image fixtures the Kaitai cross-check parses.
// Everything here is generated from the published format specs by this script, so the repo
// ships no third-party sample files and the bytes are reproducible.
//
//   node scripts/make-image-fixtures.mjs
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(bytes) {
  let c = -1;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

const be16 = (v) => [(v >>> 8) & 255, v & 255];
const be32 = (v) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
const le16 = (v) => [v & 255, (v >>> 8) & 255];
const le32 = (v) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];

function pngChunk(type, data) {
  const name = [...type].map((ch) => ch.charCodeAt(0));
  return Uint8Array.from([...be32(data.length), ...name, ...data, ...be32(crc32(Uint8Array.from([...name, ...data])))]);
}

// 4x2 8-bit RGB, filter byte 0 per scanline.
function makePng(width, height) {
  const raw = new Uint8Array(height * (1 + width * 3));
  for (let y = 0; y < height; y += 1) {
    const row = y * (1 + width * 3);
    raw[row] = 0;
    for (let x = 0; x < width; x += 1) {
      raw[row + 1 + x * 3] = (x * 40) & 255;
      raw[row + 2 + x * 3] = (y * 90) & 255;
      raw[row + 3 + x * 3] = 0x80;
    }
  }
  const ihdr = Uint8Array.from([
    ...be32(width), ...be32(height), 8, 2, 0, 0, 0,
  ]);
  const text = Uint8Array.from([...'author\0lyco'].map((ch) => ch.charCodeAt(0)));
  return Uint8Array.from([
    ...[137, 80, 78, 71, 13, 10, 26, 10],
    ...pngChunk('IHDR', ihdr),
    ...pngChunk('tEXt', text),
    ...pngChunk('IDAT', deflateSync(raw)),
    ...pngChunk('IEND', new Uint8Array(0)),
  ]);
}

// 2x2 GIF89a with a two-entry global colour table and a terminator.
function makeGif(width, height) {
  return Uint8Array.from([
    ...[...'GIF89a'].map((c) => c.charCodeAt(0)),
    ...le16(width), ...le16(height),
    0b1000_0000, // global colour table present, size index 0 -> 2 entries
    0, 0,
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00,
    0x3b,
  ]);
}

// 3x2 24-bit bottom-up BMP with a 40-byte BITMAPINFOHEADER, rows padded to 4 bytes.
function makeBmp(width, height) {
  const stride = Math.ceil((width * 3) / 4) * 4;
  const pixels = new Uint8Array(stride * height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const at = y * stride + x * 3;
      pixels[at] = 0x40;
      pixels[at + 1] = (x * 60) & 255;
      pixels[at + 2] = (y * 120) & 255;
    }
  }
  const dib = new Uint8Array(40);
  dib.set(le32(40), 0);
  dib.set(le32(width), 4);
  dib.set(le32(height), 8);
  dib.set(le16(1), 12);
  dib.set(le16(24), 14);
  const offset = 14 + 40;
  const file = new Uint8Array(offset + pixels.length);
  file.set([0x42, 0x4d], 0);
  file.set(le32(file.length), 2);
  file.set(le32(offset), 10);
  file.set(dib, 14);
  file.set(pixels, offset);
  return file;
}

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures');
mkdirSync(out, { recursive: true });
const fixtures = {
  'tiny.png': makePng(4, 2),
  'tiny.gif': makeGif(2, 2),
  'tiny.bmp': makeBmp(3, 2),
};
for (const [name, bytes] of Object.entries(fixtures)) {
  writeFileSync(join(out, name), bytes);
  console.log(`${name}: ${bytes.length} bytes`);
}
