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

function driveBytes(shape, bytes) {
  const { parse, count, field, name } = SHAPES[shape];
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

function drive(shape, file) {
  return driveBytes(shape, new Uint8Array(readFileSync(`test/fixtures/${file}`)));
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
    ['tiny.webp', 3], ['tiny.tif', 4], ['media.mp4', 10], ['tiny.avif', 10], ['media.3gp', 10], ['wide.mov', 10],
    ['media.mkv', 11], ['media.webm', 11], ['tiny.pdf', 16], ['chromium.pdf', 16],
    ['pillow-3p.pdf', 16], ['tiny.pbm', 19], ['media.asf', 20], ['media.wma', 20], ['media.wmv', 20], ['media.flv', 21], ['tiny.cab', 22],
    ['lab-fixture.deb', 23], ['media.ts', 25], ['tiny.ttf', 27], ['tiny.woff', 28], ['lab.otf', 51], ['lab.vcard', 52], ['lab.torrent', 53],
    ['lab-key.pgp', 54], ['lab-rsa.pgp', 54], ['lab-signed.pgp', 54], ['lab-signedz.pgp', 54], ['lab-encr.pgp', 54], ['lab-sym.pgp', 54],
    ['tiny.icns', 30],
    ['tiny.bplist', 31], ['keyed.bplist', 31],
    ['tiny.qoi', 32], ['srgb.qoi', 32], ['all6.qoi', 32],
    ['tiny.jp2', 33], ['rgba.jp2', 33], ['grey.jp2', 33],
    ['tiny.woff2', 34],
    ['f64.npy', 35], ['i32.npy', 35], ['v2.npy', 35], ['v3.npy', 35],
    ['tree-v0.h5', 36], ['links-v3.h5', 36],
    ['rows.avro', 37], ['deflate.avro', 37], ['many.avro', 37],
    ['rows.arrow', 38], ['batches.arrow', 38], ['dict.arrow', 38], ['lz4.arrow', 38],
    ['zstd.arrow', 38], ['file.arrow', 38], ['file_dict.arrow', 38],
    ['rows.parquet', 39], ['plain.parquet', 39], ['zstd.parquet', 39], ['gzip.parquet', 39],
    ['nodict.parquet', 39], ['nulls.parquet', 39], ['groups.parquet', 39], ['typed.parquet', 39],
    ['add.onnx', 40], ['symbolic.onnx', 40], ['types.onnx', 40],
    ['photo.heic', 41], ['block.heic', 41], ['seq.heic', 41], ['container.heif', 41],
    ['word97.doc', 42], ['excel97.xls', 42], ['wide97.xls', 42],
    ['tet.stl', 43], ['many.stl', 43], ['normals.stl', 43],
    ['srgb.icc', 44], ['xyz.icc', 44],
    ['page.emf', 45], ['gdi.emf', 45],
    ['preview.eps', 46], ['plain.ps', 46],
    ['answer.obj', 47], ['i686.obj', 47],
    ['rsa.crt', 48], ['ec.crt', 48],
    ['encoded.7z', 49], ['plain.7z', 49], ['libarchive.7z', 49],
    ['rgb.psd', 50], ['grey.psd', 50], ['rgba.psd', 50], ['raw.psd', 50],
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

test('an Avro container walks its blocks and the records add up', () => {
  const rows = assertReadable('container', 'many.avro', 37).rows;
  assert.equal(rows[0], 'avro	5094	5094	5	0');
  assert.equal(rows[2], 'codec	null');
  assert.equal(rows[3], 'schema	116	name	Sample');
  assert.equal(rows[rows.length - 3], 'block	4	82	820', rows.join(' | '));
  assert.equal(rows[rows.length - 2], 'records	500', 'five block counts summed, which is what fastavro reads back');
  assert.equal(rows[rows.length - 1], 'walked	end');
  const deflate = assertReadable('container', 'deflate.avro', 37).rows;
  assert.equal(deflate[2], 'codec	deflate', 'the codec name is reported, the payload is not inflated');
});

test('an Arrow stream keeps its envelope arithmetic and a file keeps its block index', () => {
  const stream = assertReadable('container', 'batches.arrow', 38).rows;
  assert.equal(stream[0], 'arrow\t904\t4\t0\tframing\tstream', stream.join(' | '));
  assert.equal(stream[1], 'message\t0\thead\tSchema\tmeta\t168\tbody\t0\tversion\t4');
  assert.ok(stream.includes('field\t1\tname\tnullable\t1\ttype\t5'), 'the column names travel as text');
  assert.ok(stream.includes('batch\t2\trows\t3\tnodes\t2\tbuffers\t5'), 'three batches, three bodies');
  assert.equal(stream[stream.length - 1], 'walked\tend');

  // A file framing footer is not an encapsulated message: it is a flatbuffer behind an int32, and
  // its blocks index envelopes rather than bodies, so both numbers have to arrive intact.
  const file = assertReadable('container', 'file.arrow', 38).rows;
  assert.equal(file[0], 'arrow\t922\t3\t0\tframing\tfile', file.join(' | '));
  assert.equal(
    file[file.length - 5],
    'footer\t680\tbytes\t232\tenvelope\t912\tversion\t4\tbatches\t2\tdicts\t0\tmagic\t1',
    file.join(' | ')
  );
  assert.equal(file[file.length - 4], 'block\t0\tenvelope\t184\tmeta\t208\tbody\t48');
  assert.equal(file[file.length - 3], 'block\t1\tenvelope\t440\tmeta\t208\tbody\t24');
  assert.equal(file[file.length - 1], 'walked\tend');

  // A codec equal to the enum's zero is written by omitting the field, so the two compressed files
  // have to differ by more than their sizes.
  const lz4 = assertReadable('container', 'lz4.arrow', 38).rows;
  assert.ok(lz4.includes('batch\t0\trows\t3\tnodes\t2\tbuffers\t5\tcodec\t0'), lz4.join(' | '));
  const zstd = assertReadable('container', 'zstd.arrow', 38).rows;
  assert.ok(zstd.includes('batch\t0\trows\t3\tnodes\t2\tbuffers\t5\tcodec\t1'), zstd.join(' | '));
});

test('a Parquet footer keeps its field ids and its page offsets across the ABI', () => {
  const lines = assertReadable('container', 'rows.parquet', 39).rows;
  assert.equal(lines[0], 'parquet\t703\tfooter\t174\tbytes\t521\tgroups\t1', lines.join(' | '));
  assert.equal(lines[1], 'version\t2\trows\t3\tschema\t3\tcolumns\t2');
  assert.ok(lines.includes('column\t2\tname\ttype\t6\tname\tbyte_array\trep\t1\tconverted\t0'), lines.join(' | '));
  assert.equal(
    lines.find((line) => line.startsWith('chunk\t0')),
    'chunk\t0\tpath\tid\tgroup\t0\trows\t3\ttype\t1\tname\tint32\tcodec\t1\tcodec_name\tsnappy\tuncompressed\t83\tcompressed\t87\tencodings\t0,3,8\tdata\t32\tdict\t4'
  );
  assert.equal(lines[lines.length - 1], 'walked\tend');

  // Nulls are the case a count-only reader gets wrong: the extremes have to ignore them.
  const nulls = assertReadable('container', 'nulls.parquet', 39).rows;
  assert.ok(nulls.includes('stats\t0\tnull\t2\tmin\t07000000\tmax\t09000000'), nulls.join(' | '));
  const groups = assertReadable('container', 'groups.parquet', 39).rows;
  assert.equal(groups[0], 'parquet\t2256\tfooter\t939\tbytes\t1309\tgroups\t3');
});

test('an ONNX model keeps its field numbers and its unknown axes across the ABI', () => {
  const lines = assertReadable('container', 'types.onnx', 40).rows;
  assert.equal(lines[0], 'onnx	324	nodes	1	tensors	11	opsets	1	bad	0', lines.join(' | '));
  assert.ok(lines.includes('tensor	1	i32	type	6	type_name	int32	dims	3	int32	3	raw	0'), lines.join(' | '));
  assert.ok(lines.includes('tensor	10	raw	type	1	type_name	float	dims	3	raw	12'), 'the raw-bytes tensor');
  assert.equal(lines[lines.length - 1], 'walked	end');
  const symbolic = assertReadable('container', 'symbolic.onnx', 40).rows;
  assert.ok(symbolic.includes('input	0	x	type	1	type_name	float	dims	pN,d3,u'), symbolic.join(' | '));
  assert.ok(symbolic.includes('opset	1	domain	ai.onnx.ml	version	3'), symbolic.join(' | '));
});

test('a HEIF keeps the coded size and the visible size apart across the ABI', () => {
  const cropped = assertReadable('container', 'photo.heic', 41).rows;
  assert.equal(cropped[0], 'heif	453	boxes	16	broken	0	brand	heic', cropped.join(' | '));
  assert.ok(cropped.includes('coded	64x64'), 'ispe is the coded size');
  assert.ok(cropped.includes('visible	23/1x17/1'), 'clap is the picture');
  assert.ok(cropped.includes('colour	1	transfer	13	matrix	6	range	1'), cropped.join(' | '));
  assert.equal(cropped[cropped.length - 1], 'walked	end');
  const exact = assertReadable('container', 'block.heic', 41).rows;
  assert.ok(!exact.some((row) => row.startsWith('visible	')), 'no crop box, so no crop row');
  const sequence = assertReadable('container', 'seq.heic', 41).rows;
  assert.ok(sequence.includes('items	3	primary	1	descs	3'), sequence.join(' | '));
});

test('a compound file keeps its mini streams apart from its sectors across the ABI', () => {
  const word = assertReadable('container', 'word97.doc', 42).rows;
  assert.equal(word[0], 'cfb	18432	broken	0	version	3.59	sector	512	mini	64', word.join(' | '));
  assert.ok(word.includes('root	start	3	size	4352	sectors	9	holds	4608	mini	68'
    + '	clsid	0609020000000000C000000000000046'), word.join(' | '));
  assert.ok(word.includes('stream	5	WordDocument	size	3645	start	8	where	mini	sectors	57'
    + '	holds	3648'), 'the Word stream is chained through the mini FAT');
  assert.ok(word.includes('stream	3	1Table	size	10485	start	4	where	regular	sectors	21'
    + '	holds	10752'), 'and the table stream through the real one');
  assert.ok(word.includes('inventory	streams	6	storages	0	free	1	bytes	14700'
    + '	collisions	0	hint	word'), word.join(' | '));
  assert.equal(word[word.length - 1], 'walked	end');
  const workbook = assertReadable('container', 'wide97.xls', 42).rows;
  assert.ok(workbook.includes('layout	fat	2	difat	0	dir	1	minifat	0	sectors	187'),
    workbook.join(' | '));
  assert.ok(workbook.includes('stream	1	Workbook	size	94208	start	0	where	regular'
    + '	sectors	184	holds	94208'), workbook.join(' | '));
});

test('a binary STL keeps its count and its arithmetic together across the ABI', () => {
  const tet = assertReadable('container', 'tet.stl', 43).rows;
  assert.equal(tet[0], 'stl	284	tris	4	solid	This file was generated by meshio v5.3.5.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', tet.join(' | '));
  assert.equal(tet[1], 'sizes	declared	284	actual	284	fit	exact');
  assert.ok(tet.includes('tri	3	normal	0.577350,0.577350,0.577350	v0	1.000000,0.000000,0.000000'
    + '	v1	0.000000,1.000000,0.000000	v2	0.000000,0.000000,1.000000	attr	0'), tet.join(' | '));
  assert.ok(tet.includes('box	min	0.000000,0.000000,0.000000	max	1.000000,1.000000,1.000000'), tet.join(' | '));
  assert.equal(tet[tet.length - 1], 'walked	end');
  const many = assertReadable('container', 'many.stl', 43).rows;
  assert.equal(many.filter((row) => row.startsWith('tri	')).length, 16);
  assert.ok(many.includes('cut	tris	722'), many.join(' | '));
  assert.ok(many.includes('normals	zero	0	wrong	0	counted	722'), many.join(' | '));
  assert.ok(many.includes('box	min	0.000000,0.000000,0.000000	max	4.750000,4.750000,0.750000'),
    'the extent is over the whole mesh, not the listed prefix');
  const odd = assertReadable('container', 'normals.stl', 43).rows;
  assert.ok(odd.includes('normals	zero	1	wrong	1	counted	2'), odd.join(' | '));
});

test('an ICC profile keeps its table inside its own stated length across the ABI', () => {
  const srgb = assertReadable('container', 'srgb.icc', 44).rows;
  assert.equal(srgb[0], 'icc\t588\tdeclared\t588\tbroken\t0\tversion\t4.4\tcmm\tlcms', srgb.join(' | '));
  assert.equal(
    srgb[1],
    'profile\tclass\tmntr\tspace\tRGB\tpcs\tXYZ\tintent\tperceptual\tcreator\tlcms'
  );
  assert.ok(srgb.includes('tag\t0\tdesc\tsig\tmluc\tat\t264\tlen\t54'), srgb.join(' | '));
  assert.ok(srgb.includes('tag\t10\tchrm\tsig\tchrm\tat\t552\tlen\t36'), 'the last of eleven tags');
  assert.equal(
    srgb[srgb.length - 2],
    'table\ttags\t11\tlisted\t11\toutside\t0\tdata_end\t588\ttail\t0'
  );
  assert.equal(srgb[srgb.length - 1], 'walked\tend');

  // The identity profile is where a tag type stops being a colour table: A2B0 is a curve/matrix/lut
  // sequence, so the reader names the type it read and leaves the transform alone.
  const xyz = assertReadable('container', 'xyz.icc', 44).rows;
  assert.ok(xyz.includes('tag\t4\tA2B0\tsig\tmAB\tat\t404\tlen\t80'), xyz.join(' | '));
  assert.ok(
    xyz.includes('table\ttags\t5\tlisted\t5\toutside\t0\tdata_end\t484\ttail\t0'),
    xyz.join(' | ')
  );
  assert.ok(xyz[1].startsWith('profile\tclass\tabst'), 'an abstract profile, not a display one');
});

test('a 64-bit box length is read where the format puts it', () => {
  // No ordinary file carries this form - a 64-bit length means a box past 4 GB - so the fixture is
  // hand-built and the byte order is checked against mutagen, not against this reader's own opinion.
  const wide = assertReadable('container', 'wide.mov', 10).rows;
  assert.equal(wide[wide.length - 2], 'box\tmdat\t48\t148\twide', wide.join(' | '));
  assert.equal(wide[wide.length - 1], 'walked\tend');
  assert.ok(wide.includes('duration\t44100\t110250\t2500'), 'the version-1 mvhd times');

  // The ffmpeg-written control says nothing about wide boxes: the row only grows when the header does.
  const ordinary = assertReadable('container', 'media.mp4', 10).rows;
  assert.ok(!ordinary.some((row) => row.endsWith('\twide')), ordinary.join(' | '));
  assert.equal(ordinary[0], 'ftyp\tisom\t512');
  assert.ok(ordinary.includes('duration\t1000\t1000\t1000'), ordinary.join(' | '));
});

test('an enhanced metafile is walked record by record, and both counts are printed', () => {
  // GDI counts its own header record in `records`; LibreOffice does not. Neither is corrected here:
  // the claim and the walk are printed next to each other.
  const gdi = assertReadable('container', 'gdi.emf', 45).rows;
  assert.equal(gdi[0], 'emf	308	broken	0	version	1.0	nsize	108	records	5	walked	5', gdi.join(' | '));
  assert.ok(gdi.includes('record	4	type	14	size	20'), gdi.join(' | '));
  assert.equal(gdi[gdi.length - 1], 'walked	end');
  const page = assertReadable('container', 'page.emf', 45).rows;
  assert.equal(page[0], 'emf	808	broken	0	version	1.0	nsize	108	records	22	walked	23');
  assert.ok(page.includes('device	px	898x1309	mm	190x277	dpi	120.05'), page.join(' | '));
  assert.ok(page.includes('bounds	0	0	897	1308	wh	897x1308'), page.join(' | '));
});

test('a PostScript header buried behind a preview is found by its own arithmetic', () => {
  // LibreOffice states `%%Pages: 0` for a file that carries one page comment, ImageMagick states 1 for
  // one page, and the reader reports both numbers without correcting either.
  const eps = assertReadable('container', 'preview.eps', 46).rows;
  assert.equal(eps[0], 'ps	14149	broken	0	preview	yes	start	11908	dsc	PS-Adobe-3.0 EPSF-3.0', eps.join(' | '));
  assert.equal(eps[1], 'preview	header	30	data	11878	to	11908	bytes	842e0000c10800000000000000000000');
  assert.ok(eps.includes('pages	claimed	0	found	1'), eps.join(' | '));
  assert.equal(eps[eps.length - 1], 'walked	end');

  const plain = assertReadable('container', 'plain.ps', 46).rows;
  assert.equal(plain[0], 'ps	5720	broken	0	preview	none	start	0	dsc	PS-Adobe-3.0', plain.join(' | '));
  assert.ok(plain.includes('comment	0	Creator	(ImageMagick)'), plain.join(' | '));
  assert.ok(plain.includes('pages	claimed	1	found	1'), plain.join(' | '));
  assert.ok(plain.includes('bounds	0	0	2	2	wh	2x2'), plain.join(' | '));
});

test('a COFF object gives up its sections, its symbols and the names in the string table', () => {
  // clang 22.1.8 wrote both objects and GNU objdump read them back: `make-coff-fixtures.py` refuses to
  // write its probe unless its walk matches `objdump -h` and `objdump -t` on every field below. The
  // record index steps 0, 2, 4 because a section symbol owns an auxiliary record, and `.llvm_addrsig`
  // is not in either record - it is offset 4 of the table that follows the last one.
  const answer = assertReadable('container', 'answer.obj', 47);
  assert.equal(answer.name, 'coff');
  const rows = answer.rows;
  assert.equal(rows[0], 'coff\t904\tbroken\t0\tmachine\t8664(x86-64)\tsections\t7\topts\t0', rows.join(' | '));
  assert.equal(rows[1], 'layout\tstamp\t0\tsyms\t19\tat\t544\tstrings\t18@886\tchars\t0000');
  assert.ok(rows.includes('section\t0\t.text\tvsize\t0\tvaddr\t0\traw\t31@300\treloc\t331x1\tlines\t0x0\tchars\t60500020'), rows.join(' | '));
  assert.ok(rows.includes('section\t6\t.llvm_addrsig\tvsize\t0\tvaddr\t0\traw\t1@543\treloc\t0x0\tlines\t0x0\tchars\t00100800'), rows.join(' | '));
  assert.ok(rows.includes('symbol\t12\t.llvm_addrsig\tvalue\t0\tsect\t7\ttype\t0000\tscl\t3\taux\t1\tbase\t4'), rows.join(' | '));
  assert.ok(rows.includes('symbol\t17\t.file\tvalue\t0\tsect\t-2\ttype\t0000\tscl\t103\taux\t1\tbase\t-'), 'the negative section numbers are the format saying "not in a section"');
  // The relocation rows are the ones that use a symbol index as an index, so they are worth pinning on
  // their own: 15 has to come back as `answer`, sixteenth record rather than sixteenth entry, and the
  // type names are only here because objdump -r spells them for these bytes.
  assert.ok(rows.includes('reloc\t0\t0\toffset\t15\ttype\t4(REL32)\tsym\t15(answer)'), rows.join(' | '));
  assert.ok(rows.includes('reloc\t5\t2\toffset\t8\ttype\t3(ADDR32NB)\tsym\t6(.xdata)'), rows.join(' | '));
  assert.equal(rows[rows.length - 5], 'reloc\t0\t0\toffset\t15\ttype\t4(REL32)\tsym\t15(answer)');
  assert.equal(rows[rows.length - 1], 'walked\tend');

  const i686 = assertReadable('container', 'i686.obj', 47).rows;
  assert.equal(i686[0], 'coff\t697\tbroken\t0\tmachine\t014c(i386)\tsections\t5\topts\t0');
  assert.ok(i686.includes('symbol\t12\t_helper\tvalue\t10\tsect\t1\ttype\t0020\tscl\t2\taux\t0\tbase\t-'), i686.join(' | '));

  // One 32-bit field is the whole reason this runs through the ABI rather than only in Rust: on wasm32
  // `usize` is exactly as wide as a section's size word, so an extent that overflows it is where a
  // desktop build and the deployed module would disagree. The bound is 64-bit, so both print the claim
  // and count it broken instead of following it or losing the file.
  const bytes = new Uint8Array(readFileSync('test/fixtures/answer.obj'));
  new DataView(bytes.buffer).setUint32(36, 0xffffffff, true);
  const wild = driveBytes('container', bytes);
  assert.equal(wild.code, 47);
  assert.equal(wild.rows[0], 'coff\t904\tbroken\t1\tmachine\t8664(x86-64)\tsections\t7\topts\t0', wild.rows.join(' | '));
  assert.match(wild.rows[2], /^section\t0\t\.text\t.*\traw\t4294967295@300\t/);
  assert.equal(wild.rows[wild.rows.length - 1], 'stopped\tbroken\t1');

  // And the same shape on a claimed table that does not fit: 600 records at 331 would run nine bytes
  // past the end of the file, so none are read, the three that do fit still are, and the cut row says
  // what the sections claimed in total.
  const tooFar = new Uint8Array(readFileSync('test/fixtures/answer.obj'));
  new DataView(tooFar.buffer).setUint16(52, 600, true);
  const cut = driveBytes('container', tooFar);
  assert.equal(cut.code, 47);
  assert.equal(cut.rows[0], 'coff\t904\tbroken\t1\tmachine\t8664(x86-64)\tsections\t7\topts\t0', cut.rows.join(' | '));
  assert.equal(cut.rows[cut.rows.length - 3], 'reloc\t5\t2\toffset\t8\ttype\t3(ADDR32NB)\tsym\t6(.xdata)');
  assert.equal(cut.rows[cut.rows.length - 2], 'cut\trelocs\t603');
  assert.equal(cut.rows[cut.rows.length - 1], 'stopped\tbroken\t1');
});

test('an X.509 certificate keeps its tree and its names through the wasm ABI', () => {
  // OpenSSL 3.5.7 signed both files and read them back: `make-der-fixtures.py` writes no probe unless
  // `asn1parse -i` lists the same objects in the same order and `x509 -text` states the same version,
  // serial, algorithm names, validity strings and - for the RSA one - the same key size.
  const rsa = assertReadable('container', 'rsa.crt', 48);
  assert.equal(rsa.name, 'der');
  const rows = rsa.rows;
  assert.equal(rows[0], 'der\t856\tbroken\t0\ttlvs\t58\tdepth\t5\tend\tyes', rows.join(' | '));
  assert.equal(rows[1], 'cert\tversion\t3\tserial\t2a\tsig\tsha256WithRSAEncryption(1.2.840.113549.1.1.11)\tpub\trsaEncryption(1.2.840.113549.1.1.1)');
  assert.ok(rows.includes('name\tissuer\t3\t2.5.4.6=CN,2.5.4.10=apk-lens lab,2.5.4.3=test.example.invalid'), rows.join(' | '));
  assert.ok(rows.includes('key\talgorithm\trsaEncryption(1.2.840.113549.1.1.1)\tbits\t2048\tpoint\t270'), rows.join(' | '));
  assert.ok(rows.includes('tlv\t0\td0\t0\thl\t4\tl\t852\t30(cons|SEQUENCE)'), rows.join(' | '));
  assert.ok(rows.includes('tlv\t2\td2\t8\thl\t2\tl\t3\ta0(cons|cont [ 0 ])'), 'the context tag around the version');
  assert.equal(rows[rows.length - 2], 'cut\ttlvs\t58');
  assert.equal(rows[rows.length - 1], 'walked\tend');
  assert.equal(rows.length, 48);

  // The EC certificate is the second shape: same tree walk, and no key size, because "256 bit" is a
  // fact about the named curve rather than one the bytes state.
  const ec = assertReadable('container', 'ec.crt', 48).rows;
  assert.equal(ec[0], 'der\t459\tbroken\t0\ttlvs\t56\tdepth\t5\tend\tyes');
  assert.equal(ec[5], 'key\talgorithm\tid-ecPublicKey(1.2.840.10045.2.1)\tbits\t-\tpoint\t65');

  // One byte past the end is a claim about framing, not a reason to refuse: wasm32 and the host build
  // have to say the same thing, so this goes through the ABI rather than only through the Rust test.
  const bytes = new Uint8Array(readFileSync('test/fixtures/rsa.crt'));
  const wild = driveBytes('container', new Uint8Array([...bytes, 0]));
  assert.equal(wild.code, 48);
  assert.equal(wild.rows[0], 'der\t857\tbroken\t2\ttlvs\t58\tdepth\t5\tend\tno', wild.rows.join(' | '));
  assert.equal(wild.rows[wild.rows.length - 1], 'stopped\tbroken\t2');
});

test('a 7z archive is checked against its own two CRCs, in both header shapes', () => {
  // py7zr 1.1.3 wrote both files and listed the member back out of each, and `make-7z-fixtures.py`
  // refuses to write its probe unless the start header's CRC over bytes 12..32 and the header block's
  // CRC over the bytes the offset points at both recompute - so the two numbers below are the archive's
  // own claims about its own bytes, not a reader's opinion.
  const encoded = assertReadable('container', 'encoded.7z', 49);
  assert.equal(encoded.name, 'sevenzip');
  assert.deepEqual(encoded.rows, [
    '7z\t215\tbroken\t0\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tencoded',
    'crc\tstart\tc104601b\tok\theader\tee42b910\tok',
    'note\tthe header is itself a compressed stream, so only the envelope is read',
    'walked\tend',
  ]);

  // The other shape, from the same producer with its header-mode flag off: the property tree is in the
  // open, and the report says what reaching the names inside it would take instead of guessing at them.
  const plain = assertReadable('container', 'plain.7z', 49);
  assert.equal(plain.rows[0], '7z\t191\tbroken\t0\tversion\t0.4\tpacked\t80\theader\tat\t112\tlen\t79\tkind\tplain');
  assert.equal(plain.rows[1], 'crc\tstart\t3d002d1f\tok\theader\tca020180\tok');
  assert.equal(plain.rows[2], 'note\tthe header is a property tree, and reaching its names needs the streams-info walk');
  assert.equal(plain.rows[3], 'walked\tend');

  // A second producer, because two files from one library are one library's opinion. `bsdtar` 3.8.4 - the
  // libarchive that ships with Windows - writes format version 0.3 with its own packing, py7zr lists the
  // members of the archive it did not write, and the envelope still reads the same way.
  const bsd = assertReadable('container', 'libarchive.7z', 49);
  assert.deepEqual(bsd.rows, [
    '7z\t252\tbroken\t0\tversion\t0.3\tpacked\t186\theader\tat\t218\tlen\t34\tkind\tencoded',
    'crc\tstart\t18a8e7ca\tok\theader\t5e4b942e\tok',
    'note\tthe header is itself a compressed stream, so only the envelope is read',
    'walked\tend',
  ]);

  // A file that cannot hold the header it promises is still a 7z, and says so without printing a CRC
  // for bytes that are not there.
  const bytes = new Uint8Array(readFileSync('test/fixtures/encoded.7z'));
  const cut = driveBytes('container', bytes.subarray(0, bytes.length - 24));
  assert.equal(cut.code, 49);
  assert.deepEqual(cut.rows, [
    '7z\t191\tbroken\t1\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tunreadable',
    'crc\tstart\tc104601b\tok\theader\tee42b910\tunreachable',
    'note\tthe header block is past the end of the file, so its CRC cannot be checked',
    'stopped\tbroken\t1',
  ]);

  // The offset comes from the file and points 32 bytes past itself, so the arithmetic is the part a
  // forged value can break: an offset of eight gigabytes must read as unreachable, not as a panic and
  // not as a window into memory the buffer never had.
  const far = new Uint8Array(bytes);
  new DataView(far.buffer).setUint32(12, 0xffffffff, true);
  new DataView(far.buffer).setUint32(16, 1, true);
  const wild = driveBytes('container', far);
  assert.equal(wild.code, 49);
  assert.match(wild.rows[0], /\tbroken\t2\t/, `a far offset did not count as broken: ${wild.rows[0]}`);
  assert.ok(wild.rows[0].endsWith('\tkind\tunreadable'), wild.rows[0]);
  assert.ok(wild.rows[1].endsWith('\theader\tee42b910\tunreachable'), wild.rows[1]);
  assert.equal(wild.rows[wild.rows.length - 1], 'stopped\tbroken\t2');

  // Six bytes of magic are not yet a header: below thirty-two bytes there is no CRC to check, so the
  // envelope stays silent rather than claiming an archive it cannot see.
  assert.notEqual(driveBytes('container', bytes.subarray(0, 31)).code, 49);
  const stub = driveBytes('container', new Uint8Array(bytes.subarray(0, 32)));
  assert.equal(stub.code, 49);
  assert.equal(stub.rows[0], '7z\t32\tbroken\t1\tversion\t0.4\tpacked\t163\theader\tat\t195\tlen\t20\tkind\tunreadable',
    stub.rows.join(' | '));
});

test('a Photoshop document is read to the limit of what it states about itself', () => {
  // psd-tools 1.19 wrote these; Pillow - which cannot write a PSD and shares no code with psd-tools -
  // parsed the same header, resource ids and resource sizes before `make-psd-fixtures.py` would commit
  // them, so the numbers are two implementations' agreement rather than one library's self-report.
  const rgb = assertReadable('container', 'rgb.psd', 50);
  assert.equal(rgb.name, 'psd');
  assert.equal(rgb.rows[0], 'psd\t284\tbroken\t0\tversion\t1\treserved\t000000000000\t7x5\tchannels\t3\tdepth\t8\tmode\t3(RGB)');
  assert.equal(rgb.rows[1], 'section\tlayers\t30+0\tresources\t34+94\tcolour\t132+0\timage\t132');
  assert.equal(rgb.rows[2], 'resource\t0\t1057(VERSION_INFO)\tsize\t81\tname\t-');
  assert.equal(rgb.rows[3], 'image\tcompression\t1(RLE)\trows\t15\tcounts\t120\tpayload\t120\tends\tyes');
  assert.equal(rgb.rows[4], 'layers\tnot decoded\tthe writer\'s own header mis-states this section, so its records are left alone');
  assert.equal(rgb.rows[5], 'walked\tend');

  // The uncompressed branch has no count table, so the header's own numbers predict the payload.
  const raw = assertReadable('container', 'raw.psd', 50).rows;
  assert.equal(raw[3], 'image\tcompression\t0(RAW)\tbytes\t36\texpect\t36\tends\tyes');

  const bytes = new Uint8Array(readFileSync('test/fixtures/raw.psd'));
  const short = driveBytes('container', bytes.subarray(0, bytes.length - 1));
  assert.equal(short.rows[3], 'image\tcompression\t0(RAW)\tbytes\t35\texpect\t36\tends\tno');
  assert.match(short.rows[0], /\tbroken\t1\t/, `a missing pixel did not count: ${short.rows[0]}`);
  assert.equal(short.rows[short.rows.length - 1], 'stopped\tbroken\t1');

  // Cut deeper and a section length itself falls outside the file: the report names that section, prints
  // `128+?` for a length that cannot be read, and stops rather than inventing the rest of the walk.
  const rgbBytes = new Uint8Array(readFileSync('test/fixtures/rgb.psd'));
  const stub = driveBytes('container', rgbBytes.subarray(0, 60));
  assert.equal(stub.rows[1], 'section\tlayers\t30+0\tresources\t34+94\tcolour\t128+?\timage\tunreadable');
  assert.equal(stub.rows[2], 'stopped\tbroken\t1\tcolour mode length\tdoes not fit in the file');
  assert.equal(stub.rows.length, 3);

  // And a version-2 (PSB) header is refused deeper than its own row, because its lengths are 64-bit and
  // every offset below would be read at the wrong width.
  const psb = new Uint8Array(46);
  psb.set([0x38, 0x42, 0x50, 0x53, 0x00, 0x02], 0);
  new DataView(psb.buffer).setUint16(12, 3);
  new DataView(psb.buffer).setUint32(14, 4);
  new DataView(psb.buffer).setUint32(18, 5);
  new DataView(psb.buffer).setUint16(22, 8);
  new DataView(psb.buffer).setUint16(24, 3);
  const psbRows = driveBytes('container', psb);
  assert.equal(psbRows.code, 50);
  assert.equal(psbRows.rows[0], 'psd\t46\tbroken\t1\tversion\t2\treserved\t000000000000\t5x4\tchannels\t3\tdepth\t8\tmode\t3(RGB)');
  assert.equal(psbRows.rows[1], 'note\ta version-2 document states its section lengths differently, so the walk stops here');
  assert.equal(psbRows.rows[psbRows.rows.length - 1], 'stopped\tbroken\t1');
});

test('a vCard counts properties after unfolding them, not physical lines', () => {
  // vobject wrote both fixtures and read them back (`test/fixtures/vcard.probe.json` holds both
  // readings), so 8 and 9 properties are another implementation's count, and fourteen physical lines
  // with four of them folded is what the bytes themselves say.
  const card = assertReadable('container', 'lab.vcard', 52);
  assert.equal(card.name, 'vcard');
  assert.equal(card.rows[0], 'vcard\t4.0\tprops\t8\tnames\t8\tlines\t14\tfolded\t4\tcomponents\t1');
  assert.equal(card.rows[1], 'endings\tcrlf\t14\tlf\t0\tlogical\t10\tlast_newline\tyes');
  assert.equal(card.rows[3], 'end\tyes\tbroken\t0\tescapes\t1');
  assert.ok(card.rows.includes('prop\tN\tcount\t1\tparts\t5\tparams\t-'),
    `the escaped comma must stay inside its field: ${card.rows.join(' | ')}`);
  assert.ok(card.rows.includes('prop\tADR\tcount\t1\tparts\t7\tparams\t-'),
    `ADR has seven sub-values: ${card.rows.join(' | ')}`);

  const twice = assertReadable('container', 'lab3.vcard', 52);
  assert.equal(twice.rows[0], 'vcard\t3.0\tprops\t9\tnames\t8\tlines\t15\tfolded\t4\tcomponents\t1');
  assert.ok(twice.rows.includes('prop\tEMAIL\tcount\t2\tparts\t1\tparams\tTYPE'), twice.rows.join(' | '));

  // A calendar shares the line grammar and is refused: `ics` is not one of the labels this repo scores
  // against, so the reader does not get to widen its own name from a similar-looking BEGIN.
  const calendar = new TextEncoder().encode('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n');
  assert.ok(driveBytes('container', calendar).code <= 0, 'a calendar was read as a card');
});

test('a torrent is accepted only when its stated lengths tile the file', () => {
  // `bencode.py` wrote both fixtures and re-encoded them to identical bytes, so the counts in these
  // rows are another implementation's, and `tools/torrent-sim.py` is the shadow they were taken from.
  const single = assertReadable('container', 'lab.torrent', 53);
  assert.equal(single.name, 'torrent');
  assert.equal(single.rows[0], 'bencode\tkeys\t6\tnodes\t15\tdepth\t4\tbytes\t378\tends\tyes');
  assert.equal(single.rows[1], 'sorted\tyes\tunsorted\t0');
  assert.equal(single.rows[2], 'info\tsingle\tpieces\t40\tpieces_x20\tyes\tpiece_length\t16384');
  assert.equal(single.rows[3], 'length\t4096');
  assert.equal(single.rows[4], 'announce\tudp://tracker.example.invalid:1337/announce');

  const many = assertReadable('container', 'lab-multi.torrent', 53);
  assert.equal(many.rows[2], 'info\tmulti\tpieces\t20\tpieces_x20\tyes\tpiece_length\t16384');
  assert.equal(many.rows[3], 'files\t2');

  // Bencode that is not a torrent, and a string length that runs off the end, are both refused - the
  // walk has nowhere to land, so there is no structure to report.
  for (const [label, text] of [['no info', 'd8:announce7:trackeree'], ['over-read', 'd4:name99:abce']]) {
    const seen = driveBytes('container', new TextEncoder().encode(text));
    assert.ok(seen.code <= 0, `${label} was read as a torrent: ${seen.code}`);
  }
});

test('OpenPGP is accepted by the packet lengths tiling the file and stops at a stream it cannot open', () => {
  // gpg wrote all six fixtures and `gpg --list-packets` printed `off`, `tag`, `hlen` and `plen` for every
  // packet in them (`test/fixtures/pgp.probe.json` holds that listing), so the framing numbers below are
  // another implementation's reading of the same bytes rather than this repo's own walk agreeing with
  // itself. The packet *names* come from the same listing.
  const key = assertReadable('container', 'lab-key.pgp', 54);
  assert.equal(key.name, 'pgp');
  assert.ok(key.rows.includes('kind\tkey'), key.rows.join(' | '));
  assert.ok(key.rows.includes('userid\tAPK Lens ed Fixture <ed@example.invalid>'), key.rows.join(' | '));
  // A user-ID certification and a subkey binding signature are different classes over the same algorithm,
  // and the two rows can only both be right if the reader read each packet's own body.
  assert.ok(key.rows.includes('sig\tv4\tfull\tsigclass\t0x13\tpubkey\t22\thash\t10'), key.rows.join(' | '));
  assert.ok(key.rows.includes('sig\tv4\tfull\tsigclass\t0x18\tpubkey\t22\thash\t10'), key.rows.join(' | '));

  // The branch the ed25519 export never reaches: packets whose old-format length needs two octets, so the
  // header is three bytes for them and two for the user ID in between.
  const rsa = assertReadable('container', 'lab-rsa.pgp', 54);
  assert.ok(rsa.rows.includes('packet\t0\told\ttag\t6\tpublic key\thlen\t3\tplen\t269'), rsa.rows.join(' | '));
  assert.ok(rsa.rows.includes('packet\t272\told\ttag\t13\tuser ID\thlen\t2\tplen\t42'), rsa.rows.join(' | '));

  // A compressed packet states no length at all - its body is the rest of the file - and what follows the
  // header is a deflate stream, not more packets, so the report says it stopped rather than listing what
  // gpg can only show after decompressing.
  const wrapped = assertReadable('container', 'lab-signedz.pgp', 54);
  assert.ok(wrapped.rows.some((row) => row.endsWith('\tindeterminate')), wrapped.rows.join(' | '));
  assert.ok(wrapped.rows.includes('descend\tno\tdeflate'), wrapped.rows.join(' | '));
  assert.equal(wrapped.rows.filter((row) => row.startsWith('packet\t')).length, 1, wrapped.rows.join(' | '));

  // An encrypted body is named as far as its header goes. The key ID sits between the version and the
  // algorithm in the packet, which is not the order gpg lists them in, so reading them positionally would
  // print 0xff - the key ID's first octet - as an algorithm.
  const sealed = assertReadable('container', 'lab-encr.pgp', 54);
  assert.ok(sealed.rows.some((row) => /^pkesf\tv3\talgo\t18\tkeyid\t[0-9a-f]{16}$/.test(row)), sealed.rows.join(' | '));
  assert.ok(sealed.rows.includes('packet\t96\tnew\ttag\t18\tencrypted data\thlen\t2\tplen\t87'), sealed.rows.join(' | '));
  assert.ok(sealed.rows.includes('descend\tno\tencrypted'), sealed.rows.join(' | '));

  const phrase = assertReadable('container', 'lab-sym.pgp', 54);
  assert.ok(phrase.rows.includes('skesf\tv4\tcipher\t9\ts2k\t3\thash\t10'), phrase.rows.join(' | '));

  // Bencode, a card and a plain string are all refused as packet streams: the first octet of each either
  // has no high bit or its stated length does not reach the end of the file. And a NumPy header, whose
  // first octet is an old-format packet header with no length field, is refused because an unstated length
  // only means something on a packet that carries a stream to the end of the file.
  for (const [label, bytes] of [
    ['bencode', new TextEncoder().encode('d8:announce7:trackeree')],
    ['plain text', new TextEncoder().encode('just bytes that happen to be long enough to walk over')],
    ['numpy header', new Uint8Array([0x93, 0x4e, 0x55, 0x4d, 0x50, 0x59, 4, 0, 0x45, 0, 0, 0])],
  ]) {
    const seen = driveBytes('container', bytes);
    assert.ok(seen.code !== 54, `${label} was read as OpenPGP: ${seen.code}`);
  }
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
    ['document', 'tiny.epub', 7], ['document', 'lab-fixture.dotx', 8],
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
    ['container', 'media.wav', 'riff'], ['container', 'tiny.tif', 'tiff'], ['container', 'media.mp4', 'iso-base-media'], ['container', 'wide.mov', 'iso-base-media'],
    ['container', 'media.mkv', 'ebml'], ['container', 'tiny.pdf', 'pdf'], ['container', 'tiny.pbm', 'netpbm'],
    ['container', 'media.asf', 'asf'], ['container', 'media.flv', 'flv'], ['container', 'tiny.cab', 'cab'], ['container', 'media.ts', 'mpegts'], ['container', 'tiny.ttf', 'ttf'], ['container', 'lab.otf', 'otf'], ['container', 'lab.vcard', 'vcard'], ['container', 'lab.torrent', 'torrent'], ['container', 'lab-key.pgp', 'pgp'], ['container', 'lab-sym.pgp', 'pgp'], ['container', 'tiny.woff', 'woff'], ['container', 'tiny.icns', 'icns'], ['container', 'tiny.bplist', 'bplist'], ['container', 'keyed.bplist', 'bplist'], ['container', 'all6.qoi', 'qoi'], ['container', 'tiny.jp2', 'jp2'], ['container', 'tiny.woff2', 'woff2'], ['container', 'f64.npy', 'npy'], ['container', 'tree-v0.h5', 'h5'], ['container', 'links-v3.h5', 'h5'], ['container', 'rows.avro', 'avro'], ['container', 'many.avro', 'avro'], ['container', 'rows.arrow', 'arrow'], ['container', 'file.arrow', 'arrow'], ['container', 'dict.arrow', 'arrow'], ['container', 'rows.parquet', 'parquet'], ['container', 'typed.parquet', 'parquet'], ['container', 'add.onnx', 'onnx'], ['container', 'types.onnx', 'onnx'], ['container', 'photo.heic', 'heif'], ['container', 'seq.heic', 'heif'], ['container', 'word97.doc', 'cfb'], ['container', 'excel97.xls', 'cfb'], ['container', 'tet.stl', 'stl'], ['container', 'srgb.icc', 'icc'], ['container', 'xyz.icc', 'icc'], ['container', 'page.emf', 'emf'], ['container', 'gdi.emf', 'emf'],
    ['container', 'preview.eps', 'postscript'], ['container', 'plain.ps', 'postscript'],
    ['container', 'answer.obj', 'coff'], ['container', 'i686.obj', 'coff'],
    ['container', 'rsa.crt', 'der'], ['container', 'ec.crt', 'der'],
    ['audio', 'media.flac', 'flac'], ['audio', 'media.mp3', 'mpeg-audio'], ['audio', 'media.ogg', 'ogg'],
    ['audio', 'media.wav', 'wave'], ['audio', 'media.mp2', 'mp2'], ['audio', 'media-192k.mp2', 'mp2'],
    ['stream', 'stream.gz', 'gzip'], ['stream', 'stream.xz', 'xz'], ['stream', 'stream.bz2', 'bzip2'],
    ['stream', 'stream.lz4', 'lz4'], ['stream', 'stream.zst', 'zstd'],
    ['document', 'tiny.docx', 'docx'], ['document', 'tiny.epub', 'epub'], ['document', 'tiny.odp', 'odp'],
    ['document', 'lab-fixture.dotx', 'dotx'],
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
