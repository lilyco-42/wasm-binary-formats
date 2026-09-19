// Writes test/fixtures/lab-fixture.apk: an APK-shaped archive with a real web asset inside.
// Deterministic (fixed timestamps, fixed order) so CI can assert on the exact bytes.
// Stored entries exercise the no-compression path, deflated ones exercise the zlib path.
import { deflateRawSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// The DOS date/time the zip format uses for 2020-01-01 00:00:00, so the output is stable.
const STAMP_DATE = ((2020 - 1980) << 9) | (1 << 5) | 1;
const STAMP_TIME = 0;

function chunk(value) { return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].reverse(); }
function short(value) { return [value & 255, (value >>> 8) & 255]; }

// A res/AAPT chunk header: type, header size, total size. Real binary AXML and resources.arsc
// start this way, which is all the fixture needs to look like one.
function resChunk(type) { return Uint8Array.from([...short(type), ...short(8), ...chunk(28), ...new Array(20).fill(0)]); }

const INDEX_HTML = `<!doctype html>
<meta charset="utf-8">
<link rel="stylesheet" href="style.css">
<h1 id="title">lab fixture</h1>
<img src="logo.svg" width="32" height="32" alt="logo">
<p id="probe">pending</p>
<script src="app.js"></script>
`;

const STYLE_CSS = '#title{color:#1f5fd0}body{font-family:system-ui;padding:16px}\n';
const APP_JS = "document.getElementById('probe').textContent = 'guest script ran';\ntry { parent.postMessage('GUEST_RAN', '*'); } catch (e) {}\n";
const LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="#e07a2f"/></svg>';

// A real 0x70-byte DEX header, laid out per the format so engine/src/dex.rs can parse it.
function dexHeader(counts) {
  const out = new Uint8Array(0x70);
  out.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00], 0);
  const put = (at, v) => out.set(chunk(v), at);
  put(0x08, 0xdeadbeef);
  put(0x20, 0x400);
  put(0x24, 0x70);
  put(0x28, 0x12345678);
  put(0x34, counts.mapOff);
  put(0x38, counts.strings);
  put(0x40, counts.types);
  put(0x58, counts.methods);
  put(0x60, counts.classes);
  return out;
}

// A RES_XML_TYPE chunk holding a UTF-16 RES_STRING_POOL_TYPE chunk, the layout aapt emits for a
// compiled AndroidManifest.xml. Same byte plan the passing Rust test builds.
function axmlPool(strings) {
  const header = 28;
  const stringsStart = header + 4 * strings.length;
  const payloads = [];
  const offsets = [];
  for (const text of strings) {
    offsets.push(payloads.length / 2);
    const units = [...text].map((ch) => ch.charCodeAt(0));
    const framed = [units.length, ...units, 0];
    for (const unit of framed) payloads.push(unit & 255, unit >> 8);
  }
  if (payloads.length % 2) payloads.push(0);
  const chunkSize = stringsStart + payloads.length;
  const out = new Uint8Array(8 + chunkSize);
  const put16 = (at, v) => out.set(short(v), at);
  const put = (at, v) => out.set(chunk(v), at);
  put16(0, 0x0003); put16(2, 8); put(4, out.length);
  put16(8, 0x0001); put16(10, header); put(12, chunkSize);
  put(16, strings.length); put(20, 0); put(24, stringsStart);
  offsets.forEach((offset, index) => put(header + 8 + index * 4, offset * 2));
  out.set(payloads, 8 + stringsStart);
  return out;
}

const DEX = dexHeader({ mapOff: 0x300, strings: 12, types: 3, methods: 7, classes: 2 });
const MANIFEST = axmlPool(['package', 'android.intent.action.MAIN', 'Lcom/example/app/MainActivity;']);

const ENTRIES = [
  { name: 'AndroidManifest.xml', data: Buffer.from(MANIFEST), deflate: false },
  { name: 'resources.arsc', data: Buffer.from(resChunk(0x0002)), deflate: false },
  { name: 'classes.dex', data: Buffer.from(DEX), deflate: false },
  { name: 'META-INF/CERT.SF', data: Buffer.from('Signature-Version: 1.0\r\n'), deflate: true },
  { name: 'assets/www/index.html', data: Buffer.from(INDEX_HTML), deflate: true },
  { name: 'assets/www/style.css', data: Buffer.from(STYLE_CSS), deflate: true },
  { name: 'assets/www/app.js', data: Buffer.from(APP_JS), deflate: true },
  { name: 'assets/www/logo.svg', data: Buffer.from(LOGO_SVG), deflate: false },
];

const locals = [];
const centrals = [];
let offset = 0;

for (const entry of ENTRIES) {
  const name = Buffer.from(entry.name);
  const raw = entry.data;
  const body = entry.deflate ? deflateRawSync(raw, { level: 9 }) : raw;
  const method = entry.deflate ? 8 : 0;
  const crc = crc32(raw);
  locals.push(Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from(short(20)), Buffer.from(short(0)),
    Buffer.from(short(method)), Buffer.from(short(STAMP_TIME)), Buffer.from(short(STAMP_DATE)),
    Buffer.from(chunk(crc)), Buffer.from(chunk(body.length)), Buffer.from(chunk(raw.length)),
    Buffer.from(short(name.length)), Buffer.from(short(0)), name, body,
  ]));
  centrals.push(Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x01, 0x02]), Buffer.from(short(20)), Buffer.from(short(20)),
    Buffer.from(short(0)), Buffer.from(short(method)), Buffer.from(short(STAMP_TIME)),
    Buffer.from(short(STAMP_DATE)), Buffer.from(chunk(crc)), Buffer.from(chunk(body.length)),
    Buffer.from(chunk(raw.length)), Buffer.from(short(name.length)), Buffer.from(short(0)),
    Buffer.from(short(0)), Buffer.from(short(0)), Buffer.from(short(0)), Buffer.from(chunk(0)),
    Buffer.from(chunk(offset)), name,
  ]));
  offset += 30 + name.length + body.length;
}

const centralDirectory = Buffer.concat(centrals);
const archive = Buffer.concat([
  Buffer.concat(locals), centralDirectory,
  Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.from(short(0)), Buffer.from(short(0)),
  Buffer.from(short(ENTRIES.length)), Buffer.from(short(ENTRIES.length)),
  Buffer.from(chunk(centralDirectory.length)), Buffer.from(chunk(offset)), Buffer.from(short(0)),
]);

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'test', 'fixtures', 'lab-fixture.apk');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, archive);
console.log(`${out} · ${archive.length} bytes · ${ENTRIES.length} entries`);
