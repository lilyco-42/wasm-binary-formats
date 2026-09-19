// Loads the wasm artifact and drives it through the same C ABI the demo uses.
// The archive is built here from raw bytes (stored entries + CRC-32) so the test does
// not depend on any Node zip package.
//
//   node test/wasm.test.mjs path/to/apk_lens.wasm
import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';

const wasmPath = process.argv[2] ?? 'engine/target/wasm32-unknown-unknown/release/apk_lens.wasm';
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const ex = instance.exports;

const crcTable = new Uint32Array(256).map((_, i) => {
  let c = i;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

const crc32 = (bytes) => {
  let c = 0xffffffff;
  for (const b of bytes) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

function storedZip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const [name, body] of entries) {
    const nameBytes = new TextEncoder().encode(name);
    const data = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    const crc = crc32(data);
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(8, 0, true);          // stored
    local.setUint32(14, crc, true);
    local.setUint32(18, data.length, true);
    local.setUint32(22, data.length, true);
    local.setUint16(26, nameBytes.length, true);
    chunks.push(new Uint8Array(local.buffer), nameBytes, data);

    const header = new DataView(new ArrayBuffer(46));
    header.setUint32(0, 0x02014b50, true);
    header.setUint16(4, 20, true);
    header.setUint16(6, 20, true);
    header.setUint16(12, 0, true);
    header.setUint32(16, crc, true);
    header.setUint32(20, data.length, true);
    header.setUint32(24, data.length, true);
    header.setUint16(28, nameBytes.length, true);
    header.setUint32(42, offset, true);
    central.push(new Uint8Array(header.buffer), nameBytes);
    offset += 30 + nameBytes.length + data.length;
  }
  const centralStart = offset;
  const centralSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true);
  eocd.setUint16(8, entries.length, true);
  eocd.setUint16(10, entries.length, true);
  eocd.setUint32(12, centralSize, true);
  eocd.setUint32(16, centralStart, true);
  return new Uint8Array([...chunks, ...central, new Uint8Array(eocd.buffer)].reduce((a, b) => { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out }, new Uint8Array()));
}

function load(bytes) {
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  const rc = ex.open(ptr, bytes.length);
  ex.dealloc(ptr, bytes.length);
  return rc;
}

function readString(fn, ...args) {
  const cap = 4096;
  const ptr = ex.alloc(cap);
  const written = fn(...args, ptr, cap);
  const text = new TextDecoder().decode(new Uint8Array(ex.memory.buffer.slice(ptr, ptr + Math.max(written, 0))));
  ex.dealloc(ptr, cap);
  return { written, text };
}

test('rejects a non-archive and explains itself', () => {
  const rc = load(new TextEncoder().encode('this is definitely not a zip'));
  assert.ok(rc < 0, 'garbage must be refused');
  const { text } = readString(ex.last_error);
  assert.match(text, /zip/i, text);
});

test('lists and extracts entries through the wasm ABI', () => {
  const zip = storedZip([
    ['assets/index.html', '<h1>apk-lens</h1>'],
    ['AndroidManifest.xml', 'binary-xml-placeholder'],
    ['classes.dex', new Uint8Array([0x64, 0x65, 0x78, 0x0a, 1, 2, 3])],
  ]);
  assert.equal(load(zip), 0, 'a valid archive must open');
  assert.equal(ex.count(), 3);

  const { text } = readString(ex.entry, 0);
  const [name, size] = text.split('\t');
  assert.equal(name, 'assets/index.html');
  assert.equal(Number(size), 17);

  const cap = 64;
  const ptr = ex.alloc(cap);
  const written = ex.extract(0, ptr, cap);
  const body = new TextDecoder().decode(new Uint8Array(ex.memory.buffer.slice(ptr, ptr + written)));
  ex.dealloc(ptr, cap);
  assert.equal(body, '<h1>apk-lens</h1>');
});

test('refuses to write past the caller buffer', () => {
  assert.equal(load(storedZip([['big.txt', 'x'.repeat(40)]])), 0);
  const cap = 8;
  const ptr = ex.alloc(cap);
  const rc = ex.extract(0, ptr, cap);
  ex.dealloc(ptr, cap);
  assert.equal(rc, -4);
});

test('handles a binary entry byte-for-byte', () => {
  const payload = new Uint8Array(Array.from({ length: 512 }, (_, i) => (i * 37) & 0xff));
  assert.equal(load(storedZip([['classes.dex', payload]])), 0);
  const cap = 1024;
  const ptr = ex.alloc(cap);
  const written = ex.extract(0, ptr, cap);
  const got = new Uint8Array(ex.memory.buffer.slice(ptr, ptr + written));
  ex.dealloc(ptr, cap);
  assert.equal(written, payload.length);
  assert.deepEqual([...got], [...payload]);
});
