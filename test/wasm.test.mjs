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

// The same archive both ways: this file is generated by scripts/make-fixture.mjs, checked
// against Python's zipfile, and mixes stored and deflated entries.
test('reads the handwritten apk-shaped fixture', () => {
  const bytes = new Uint8Array(readFileSync('test/fixtures/lab-fixture.apk'));
  assert.equal(load(bytes), 0, 'the fixture must open');
  assert.equal(ex.count(), 8);

  const entries = Array.from({ length: ex.count() }, (_, index) => {
    const [name, size, compressed] = readString(ex.entry, index).text.split('\t');
    return { name, size: Number(size), compressed: Number(compressed) };
  });
  assert.deepEqual(entries.map((entry) => entry.name), [
    'AndroidManifest.xml', 'resources.arsc', 'classes.dex', 'META-INF/CERT.SF',
    'assets/www/index.html', 'assets/www/style.css', 'assets/www/app.js', 'assets/www/logo.svg',
  ]);

  const web = entries.find((entry) => entry.name === 'assets/www/index.html');
  assert.ok(web.compressed < web.size, 'index.html is deflated in the fixture');
  const cap = 4096;
  const ptr = ex.alloc(cap);
  const written = ex.extract(entries.indexOf(web), ptr, cap);
  const body = new TextDecoder().decode(new Uint8Array(ex.memory.buffer.slice(ptr, ptr + written)));
  ex.dealloc(ptr, cap);
  assert.ok(body.startsWith('<!doctype html>'), body.slice(0, 40));
  assert.match(body, /src="app\.js"/, 'the guest page keeps its relative references');

  // The demo's end-to-end check depends on this: the guest script has to answer with a
  // postMessage, which is only observable from the host if it actually executed.
  const scriptIndex = entries.findIndex((entry) => entry.name === 'assets/www/app.js');
  const scriptCap = 4096;
  const scriptPtr = ex.alloc(scriptCap);
  const scriptWritten = ex.extract(scriptIndex, scriptPtr, scriptCap);
  const script = new TextDecoder().decode(new Uint8Array(ex.memory.buffer.slice(scriptPtr, scriptPtr + scriptWritten)));
  ex.dealloc(scriptPtr, scriptCap);
  assert.match(script, /parent\.postMessage\('GUEST_RAN'/, script);
});

const NT = 64;

function minimalPe({ pe32plus = true, dll = false, cli = 0, optionalSize = null } = {}) {
  const optional = optionalSize ?? (pe32plus ? 240 : 224);
  const file = new DataView(new ArrayBuffer(NT + 24 + optional + 80));
  const u8 = new Uint8Array(file.buffer);
  const set16 = (at, v) => file.setUint16(at, v, true);
  const set32 = (at, v) => file.setUint32(at, v, true);
  const set64 = (at, v) => file.setBigUint64(at, BigInt(v), true);
  u8.set([0x4d, 0x5a], 0);
  set32(0x3c, NT);
  u8.set([0x50, 0x45], NT);
  set16(NT + 4, pe32plus ? 0x8664 : 0x014c);
  set16(NT + 6, 2);
  set16(NT + 20, optional);
  set16(NT + 22, dll ? 0x2000 : 0x0102);
  const opt = NT + 24;
  set16(opt, pe32plus ? 0x20b : 0x10b);
  set32(opt + 16, 0x1000);
  if (pe32plus) set64(opt + 24, 0x14000000); else set32(opt + 28, 0x400000);
  set16(opt + 68, 2);
  set32(opt + (pe32plus ? 108 : 92), 15);
  set32(opt + (pe32plus ? 112 : 96) + 14 * 8, cli);
  const table = opt + optional;
  ['.text', '.rdata'].forEach((name, index) => {
    const at = table + index * 40;
    new Uint8Array(file.buffer, at, name.length).set(new TextEncoder().encode(name));
    set32(at + 8, 0x120);
    set32(at + 12, 0x1000 * (index + 1));
    set32(at + 16, 0x200);
    set32(at + 20, 0x400 * (index + 1));
    set32(at + 36, 0x60000020);
  });
  return new Uint8Array(file.buffer);
}

function parsePe(bytes) {
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  const rc = ex.parse_pe(ptr, bytes.length);
  const values = rc === 0 ? {
    machine: ex.pe_machine(), magic: ex.pe_magic(), entry: ex.pe_entry_rva(),
    base: ex.pe_image_base(), subsystem: ex.pe_subsystem(), characteristics: ex.pe_characteristics(),
    cli: ex.pe_cli_rva(), sections: readString(ex.pe_sections).text,
  } : null;
  ex.dealloc(ptr, bytes.length);
  return { rc, values };
}

test('inspects a 64-bit PE through the wasm ABI', () => {
  const { rc, values } = parsePe(minimalPe({ dll: true, cli: 0x20d0 }));
  assert.equal(rc, 0);
  assert.equal(values.machine, 0x8664);
  assert.equal(values.magic, 0x20b);
  assert.equal(Number(values.base), 0x14000000, 'ImageBase is 64-bit in PE32+');
  assert.equal(Number(values.entry), 0x1000);
  assert.equal(values.subsystem, 2);
  assert.equal(values.characteristics & 0x2000, 0x2000, 'IMAGE_FILE_DLL');
  assert.equal(Number(values.cli), 0x20d0, 'COM descriptor marks .NET');
  assert.deepEqual(values.sections.split('\n').map((row) => row.split('\t')[0]), ['.text', '.rdata']);
});

test('inspects a 32-bit PE and marks it as not .NET', () => {
  const { rc, values } = parsePe(minimalPe({ pe32plus: false }));
  assert.equal(rc, 0);
  assert.equal(values.machine, 0x014c);
  assert.equal(values.magic, 0x10b);
  assert.equal(Number(values.base), 0x400000);
  assert.equal(Number(values.cli), 0);
  assert.equal(values.characteristics & 0x2000, 0, 'an exe, not a dll');
});

test('refuses to treat an archive as an executable', () => {
  const bytes = new Uint8Array(readFileSync('test/fixtures/lab-fixture.apk'));
  const { rc } = parsePe(bytes);
  assert.equal(rc, -2, 'MZ signature is required');
  assert.match(readString(ex.last_error).text, /MZ/);
});

test('reads a legal but smaller optional header at its real size', () => {
  // 96 bytes of standard fields plus 15 directories = 216, which real PE32 images use. A reader
  // that forced the canonical 224 would start the section table eight bytes late.
  const { rc, values } = parsePe(minimalPe({ pe32plus: false, cli: 0x20d0, optionalSize: 216 }));
  assert.equal(rc, 0);
  assert.equal(Number(values.cli), 0x20d0);
  assert.deepEqual(values.sections.split('\n').map((row) => row.split('\t')[0]), ['.text', '.rdata']);
});

test('falls back when the optional size is not a size', () => {
  const bytes = minimalPe({ pe32plus: false });
  new DataView(bytes.buffer).setUint16(NT + 20, 0, true);
  const { rc, values } = parsePe(bytes);
  assert.equal(rc, 0, 'a zero field must not be read as "the table starts at the header"');
  assert.deepEqual(values.sections.split('\n').map((row) => row.split('\t')[0]), ['.text', '.rdata']);
});

// The demo's structure panel drives these four readers through the same ABI and prints the code it
// gets back next to the format name, so the numbers asserted here are the ones a visitor sees.
const SHAPES = {
  container: { parse: 'parse_container', count: 'container_count', field: 'container_entry', name: 'container_name' },
  audio: { parse: 'parse_audio', count: 'audio_count', field: 'audio_field', name: 'audio_name' },
  stream: { parse: 'parse_stream', count: 'stream_field_count', field: 'stream_field', name: 'stream_name' },
  document: { parse: 'parse_document', count: 'document_count', field: 'document_field', name: 'document_name' },
};

function drive(shape, file) {
  const { parse, count, field, name } = SHAPES[shape];
  const bytes = new Uint8Array(readFileSync(`test/fixtures/${file}`));
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  const code = ex[parse](ptr, bytes.length);
  ex.dealloc(ptr, bytes.length);
  if (code <= 0) return { code, name: '', total: 0, rows: [] };
  const total = ex[count]();
  const rows = [];
  for (let index = 0; index < total; index += 1) rows.push(readString(ex[field], index).text);
  return { code, name: readString(ex[name]).text, total, rows };
}

function assertReadable(shape, file, code) {
  const seen = drive(shape, file);
  assert.equal(seen.code, code, `${file} answered with a different format code`);
  assert.equal(seen.rows.length, seen.total, `${file} lied about how many rows it has`);
  assert.ok(seen.total >= 1, `${file} reported no rows at all`);
  assert.match(seen.name, /^[a-z0-9-]+$/, `${file} named itself ${JSON.stringify(seen.name)}`);
  for (const row of seen.rows) {
    assert.ok(row.length > 0 && !row.includes('\0'), `${file} returned an unusable row`);
  }
  return seen;
}

test('every container the demo offers answers with the code the page prints', () => {
  const cases = [
    ['gnu.tar', 1], ['plain.ar', 2], ['lab-fixture.deb', 23], ['media.wav', 3], ['media.avi', 3],
    ['tiny.webp', 3], ['tiny.tif', 4], ['media.mp4', 10], ['tiny.avif', 10], ['media.3gp', 10],
    ['media.mkv', 11], ['media.webm', 11], ['tiny.pdf', 16], ['chromium.pdf', 16],
    ['pillow-3p.pdf', 16], ['tiny.pbm', 19], ['media.asf', 20], ['media.wma', 20], ['media.wmv', 20], ['media.flv', 21], ['tiny.cab', 22],
    ['lab-fixture.deb', 23], ['media.ts', 25], ['tiny.ttf', 27], ['tiny.woff', 28], ['tiny.icns', 30],
    ['tiny.bplist', 31], ['keyed.bplist', 31],
    ['tiny.qoi', 32], ['srgb.qoi', 32], ['all6.qoi', 32],
    ['tiny.jp2', 33], ['rgba.jp2', 33], ['grey.jp2', 33],
    ['tiny.woff2', 34],
    ['f64.npy', 35], ['i32.npy', 35], ['v2.npy', 35], ['v3.npy', 35],
    ['tree-v0.h5', 36], ['links-v3.h5', 36],
  ];
  for (const [file, code] of cases) assertReadable('container', file, code);
});

test('a binary plist keeps its object graph and its text across the ABI', () => {
  const keyed = assertReadable('container', 'keyed.bplist', 31).rows;
  assert.ok(keyed.includes('obj\t11\tuid\t4'), 'the UID reference between two objects is gone');
  assert.ok(keyed.some((row) => row.startsWith('child\t19\t')), 'no reference rows');
  assert.equal(keyed.filter((row) => row.startsWith('child\t')).length, 22);
  assert.ok(keyed.includes('edges\t22\tunresolved\t0'), `broken references: ${keyed.find((r) => r.startsWith('edges'))}`);
  assert.ok(keyed.includes('walked\tend'), 'the table and trailer do not account for the file');

  // Non-ASCII text travels as UTF-8 through a byte buffer, so it is the part most likely to come
  // back mangled on the other side.
  const tiny = assertReadable('container', 'tiny.bplist', 31).rows;
  assert.ok(tiny.includes('obj\t50\tutf16\t7\théllo世界'), `utf16 row: ${tiny.find((r) => r.startsWith('obj\t50'))}`);
  assert.ok(tiny.includes('obj\t18\tdate\t2026-09-20\t02:47:12'), 'the date walked back is not the one written');
  assert.ok(tiny.includes('obj\t24\tint\t-7\t8'), 'a negative integer came back unsigned');
});

test('a QOI chunk stream arrives with its six classes apart', () => {
  const rows = assertReadable('container', 'all6.qoi', 32).rows;
  assert.equal(rows[0], 'qoi	64	8	4	1');
  assert.equal(rows[1], 'chunks	296	rgb	11	argb	14	index	162	diff	28	luma	1	run	80');
  assert.equal(rows[2], 'pixels	512	walked	512	terminator	1');
  assert.ok(rows.includes('walked	end'), rows.join(' | '));
});

test('a JPEG 2000 container keeps its box order and its height-first ihdr', () => {
  const rows = assertReadable('container', 'tiny.jp2', 33).rows;
  assert.equal(rows[0], 'jp2	316	316	4	0');
  assert.equal(rows[7], 'ihdr	20	32	3	8	filter	7', 'the 32x20 image must not come out 20x32');
  assert.ok(rows.includes('colr	1	16'), rows.join(' | '));
  assert.ok(rows.includes('walked	end'), rows.join(' | '));
  const grey = assertReadable('container', 'grey.jp2', 33).rows;
  assert.equal(grey[7], 'ihdr	8	64	1	8	filter	7');
  assert.equal(grey[8], 'colr	1	17');
});

test('a WOFF2 directory arrives with the lengths its TTF parent gives', () => {
  const rows = assertReadable('container', 'tiny.woff2', 34).rows;
  assert.equal(rows[0], 'woff2	312	312	10	0');
  assert.equal(rows[1], 'flavor	10000	sfnt	636', 'the sfnt size is the length of tiny.ttf');
  assert.ok(rows.includes('table	2	glyf	28	54	0'), 'the one table with a transform length: ' + rows[6]);
  assert.ok(rows.includes('table	6	loca	6	0	0'), rows.slice(4, 14).join(' | '));
  assert.ok(rows.includes('directory	70	read	10	broken	0	data_end	309	padding	3'), rows[14]);
  assert.ok(rows.includes('walked	end'), rows[15]);
});

test('a numpy header arrives with the size arithmetic numpy itself agrees to', () => {
  const rows = assertReadable('container', 'f64.npy', 35).rows;
  assert.equal(rows[0], 'npy	1	0	118	128');
  assert.equal(rows[4], 'sizes	8	elements	6	expects	48	available	48', rows.join(' | '));
  assert.ok(rows.includes('walked	end'), rows.join(' | '));
  const unicode = assertReadable('container', 'unicode.npy', 35).rows;
  assert.equal(unicode[1], 'dtype	<U4');
  assert.equal(unicode[4], 'sizes	16	elements	2	expects	32	available	32', 'four characters are sixteen bytes');
  const v2 = assertReadable('container', 'v2.npy', 35).rows;
  assert.equal(v2[0], 'npy	2	0	180	192', 'version 2 widens the header length');
  assert.ok(!v2.includes('walked	end'), 'a field list has no item size to claim');
});

test('an HDF5 superblock keeps the addresses that sign their structures', () => {
  const old = assertReadable('container', 'tree-v0.h5', 36).rows;
  assert.equal(old[0], 'h5	0	8	8	29	4');
  assert.equal(old[1], 'eof	40	10240	file	10240');
  assert.ok(old.includes('addr	88	680	sig	HEAP'), old.join(' | '));
  assert.ok(old.includes('walked	end'), old.join(' | '));
  const modern = assertReadable('container', 'links-v3.h5', 36).rows;
  assert.equal(modern[0], 'h5	3	8	8	29	2');
  assert.equal(modern[2], 'addr	36	48	sig	OHDR', modern.join(' | '));
});

test('the page tree of both PDF producers survives the trip through the wasm ABI', () => {
  for (const file of ['chromium.pdf', 'pillow-3p.pdf', 'tiny.pdf']) {
    const rows = assertReadable('container', file, 16).rows;
    assert.ok(rows.some((row) => row.startsWith('resolves\tRoot\t') && row.endsWith('\t1')),
      `${file}: nothing resolved through the table`);
    assert.ok(rows.some((row) => row.startsWith('page\t') && row.includes('\tmedia\t')),
      `${file}: no page row`);
    const leaves = rows.find((row) => row.startsWith('leaves\t'));
    assert.ok(Number(leaves.split('\t')[1]) >= 1, `${file}: ${leaves}`);
    assert.equal(Number(leaves.split('\t')[5]), 0, `${file}: the walk hit a cap`);
  }
});

test('the audio, stream and package readers answer the same way', () => {
  const cases = [
    ['audio', 'media.flac', 12], ['audio', 'media.mp3', 13],
    ['audio', 'media.ogg', 14], ['audio', 'media.wav', 15],
    ['audio', 'media.mp2', 24], ['audio', 'media-192k.mp2', 24],
    ['stream', 'stream.gz', 9], ['stream', 'stream.xz', 5], ['stream', 'stream.bz2', 6],
    ['stream', 'stream.lz4', 7], ['stream', 'stream.zst', 8],
    ['document', 'tiny.docx', 1], ['document', 'tiny.xlsx', 2], ['document', 'tiny.pptx', 3],
    ['document', 'tiny.odt', 4], ['document', 'tiny.ods', 5], ['document', 'tiny.odp', 6],
    ['document', 'tiny.epub', 7],
  ];
  for (const [shape, file, code] of cases) assertReadable(shape, file, code);
});

test('readers stay in their lane, so the panel cannot show a confident wrong name', () => {
  // A zip is none of the ten container families, a tar is not an office package, and neither one is
  // audio. Each of those has to come back refused rather than with a plausible row.
  assert.ok(drive('container', 'lab-fixture.apk').code <= 0, 'a zip walked as a container');
  assert.ok(drive('document', 'gnu.tar').code <= 0, 'a tar classified as a document package');
  assert.ok(drive('audio', 'gnu.tar').code <= 0, 'a tar parsed as audio');
  assert.ok(drive('stream', 'gnu.tar').code <= 0, 'a tar read as a compressed stream');
  assert.ok(drive('container', 'tiny.docx').code <= 0, 'an office package walked as a container');
});

test('the reader names the family, not the first row it happened to walk', () => {
  // A tar's first row is a member name: a panel that read the label off row zero printed "tiny.tif"
  // for gnu.tar. The name has to come from the reader that accepted the bytes.
  const cases = [
    ['container', 'gnu.tar', 'tar'], ['container', 'plain.ar', 'ar'], ['container', 'lab-fixture.deb', 'deb'],
    ['container', 'media.wav', 'riff'], ['container', 'tiny.tif', 'tiff'], ['container', 'media.mp4', 'iso-base-media'],
    ['container', 'media.mkv', 'ebml'], ['container', 'tiny.pdf', 'pdf'], ['container', 'tiny.pbm', 'netpbm'],
    ['container', 'media.asf', 'asf'], ['container', 'media.flv', 'flv'], ['container', 'tiny.cab', 'cab'], ['container', 'media.ts', 'mpegts'], ['container', 'tiny.ttf', 'ttf'], ['container', 'tiny.woff', 'woff'], ['container', 'tiny.icns', 'icns'], ['container', 'tiny.bplist', 'bplist'], ['container', 'keyed.bplist', 'bplist'], ['container', 'all6.qoi', 'qoi'], ['container', 'tiny.jp2', 'jp2'], ['container', 'tiny.woff2', 'woff2'], ['container', 'f64.npy', 'npy'], ['container', 'tree-v0.h5', 'h5'], ['container', 'links-v3.h5', 'h5'],
    ['audio', 'media.flac', 'flac'], ['audio', 'media.mp3', 'mpeg-audio'], ['audio', 'media.ogg', 'ogg'],
    ['audio', 'media.wav', 'wave'], ['audio', 'media.mp2', 'mp2'], ['audio', 'media-192k.mp2', 'mp2'],
    ['stream', 'stream.gz', 'gzip'], ['stream', 'stream.xz', 'xz'], ['stream', 'stream.bz2', 'bzip2'],
    ['stream', 'stream.lz4', 'lz4'], ['stream', 'stream.zst', 'zstd'],
    ['document', 'tiny.docx', 'docx'], ['document', 'tiny.epub', 'epub'], ['document', 'tiny.odp', 'odp'],
  ];
  for (const [shape, file, name] of cases) {
    assert.equal(drive(shape, file).name, name, `${file} reported a different family name`);
  }
});

test('a WebAssembly module reads back through the container reader', () => {
  // The artifact under test is the module the browser is loading right now: LLVM output, not a
  // fixture of ours. The check that matters is agreement - what the walk counts as exports has to be
  // what the host engine itself reports, or the section boundaries are wrong even though the bytes
  // added up.
  const bytes = new Uint8Array(readFileSync(wasmPath));
  const module = new WebAssembly.Module(bytes);
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  const code = ex.parse_container(ptr, bytes.length);
  const total = ex.container_count();
  const rows = [];
  for (let index = 0; index < total; index += 1) rows.push(readString(ex.container_entry, index).text);
  const family = readString(ex.container_name).text;
  ex.dealloc(ptr, bytes.length);
  assert.equal(code, 26, `the module was not read as WebAssembly (code ${code})`);
  assert.equal(family, 'wasm');
  assert.ok(rows.includes('walked	end'), 'the sections must tile the module');
  assert.ok(!rows.some((row) => row.startsWith('section	unknown')), 'no id should be unnamed');
  const column = (prefix) => Number(rows.find((row) => row.startsWith(prefix)).split('	')[1]);
  assert.equal(column('exports	'), WebAssembly.Module.exports(module).length,
    'the reader and the engine disagree about the export count');
  assert.equal(column('code_bodies	'), column('functions	'),
    'one code body per declared function');
  assert.ok(column('types	') > 0 && column('data_segments	') > 0, 'counts should be present');
  assert.ok(rows.some((row) => row.startsWith('custom	producers')),
    'the toolchain records itself in a custom section');
});
