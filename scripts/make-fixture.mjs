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

const ENTRIES = [
  { name: 'AndroidManifest.xml', data: Buffer.from(resChunk(0x0003)), deflate: false },
  { name: 'resources.arsc', data: Buffer.from(resChunk(0x0002)), deflate: false },
  { name: 'classes.dex', data: Buffer.from('dex\n035\0', 'latin1'), deflate: false },
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
