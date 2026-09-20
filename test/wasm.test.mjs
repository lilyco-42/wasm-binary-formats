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
    ['tiny.webp', 3], ['tiny.tif', 4], ['media.mp4', 10], ['tiny.avif', 10], ['media.3gp', 10], ['wide.mov', 10],
    ['media.mkv', 11], ['media.webm', 11], ['tiny.pdf', 16], ['chromium.pdf', 16],
    ['pillow-3p.pdf', 16], ['tiny.pbm', 19], ['media.asf', 20], ['media.wma', 20], ['media.wmv', 20], ['media.flv', 21], ['tiny.cab', 22],
    ['lab-fixture.deb', 23], ['media.ts', 25], ['tiny.ttf', 27], ['tiny.woff', 28], ['tiny.icns', 30],
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
    ['container', 'media.wav', 'riff'], ['container', 'tiny.tif', 'tiff'], ['container', 'media.mp4', 'iso-base-media'], ['container', 'wide.mov', 'iso-base-media'],
    ['container', 'media.mkv', 'ebml'], ['container', 'tiny.pdf', 'pdf'], ['container', 'tiny.pbm', 'netpbm'],
    ['container', 'media.asf', 'asf'], ['container', 'media.flv', 'flv'], ['container', 'tiny.cab', 'cab'], ['container', 'media.ts', 'mpegts'], ['container', 'tiny.ttf', 'ttf'], ['container', 'tiny.woff', 'woff'], ['container', 'tiny.icns', 'icns'], ['container', 'tiny.bplist', 'bplist'], ['container', 'keyed.bplist', 'bplist'], ['container', 'all6.qoi', 'qoi'], ['container', 'tiny.jp2', 'jp2'], ['container', 'tiny.woff2', 'woff2'], ['container', 'f64.npy', 'npy'], ['container', 'tree-v0.h5', 'h5'], ['container', 'links-v3.h5', 'h5'], ['container', 'rows.avro', 'avro'], ['container', 'many.avro', 'avro'], ['container', 'rows.arrow', 'arrow'], ['container', 'file.arrow', 'arrow'], ['container', 'dict.arrow', 'arrow'], ['container', 'rows.parquet', 'parquet'], ['container', 'typed.parquet', 'parquet'], ['container', 'add.onnx', 'onnx'], ['container', 'types.onnx', 'onnx'], ['container', 'photo.heic', 'heif'], ['container', 'seq.heic', 'heif'], ['container', 'word97.doc', 'cfb'], ['container', 'excel97.xls', 'cfb'], ['container', 'tet.stl', 'stl'], ['container', 'srgb.icc', 'icc'], ['container', 'xyz.icc', 'icc'],
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
