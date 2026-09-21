// The optional analysis module, exercised the way the browser exercises it: instantiate the file CI
// built, call the C ABI through the module's own memory, and check the rows. Nothing here imports the
// crate - if the export names or the row shapes drift, this test is what notices.
//
//   node test/module.test.mjs analysis/target/wasm32-unknown-unknown/release/apk_lens_analysis.wasm \
//        [engine/target/wasm32-unknown-unknown/release/apk_lens.wasm]
//
// The second argument is the *base* module: this test also proves the analysis exports are not in it,
// which is the whole point of shipping a second file.

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const modulePath = process.argv[2];
const basePath = process.argv[3];
assert.ok(modulePath, 'usage: node test/module.test.mjs <analysis.wasm> [apk-lens.wasm]');

async function instantiate(path) {
  const bytes = await readFile(path);
  const { instance } = await WebAssembly.instantiate(bytes.buffer.slice(0), {});
  return instance.exports;
}

const ex = await instantiate(modulePath);

function text(fn, ...args) {
  let cap = 4096;
  for (;;) {
    const ptr = ex.alloc(cap);
    const written = ex[fn](...args, ptr, cap);
    const keep = Math.max(Math.min(written, cap), 0);
    const value = new TextDecoder().decode(new Uint8Array(ex.memory.buffer.slice(ptr, ptr + keep)));
    ex.dealloc(ptr, cap);
    if (written < 0 || written <= cap || cap >= 1 << 22) return value;
    cap *= 8;
  }
}

function report(bytes) {
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  // analyse_run answers 0 for "accepted"; the number of rows is a separate question.
  const rc = ex.analyse_run(ptr, bytes.length);
  ex.dealloc(ptr, bytes.length);
  const count = rc === 0 ? ex.analyse_count() : 0;
  return { rc, rows: Array.from({ length: count }, (_, i) => text('analyse_at', i)) };
}

// The same 199-byte ELF64 stub analysis/src/lib.rs builds for its self test.
function stubElf() {
  const out = new Uint8Array(199);
  out.set([0x7F, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  new DataView(out.buffer).setUint16(16, 3, true);
  new DataView(out.buffer).setUint16(18, 0x3e, true);
  new DataView(out.buffer).setUint32(20, 1, true);
  new DataView(out.buffer).setBigUint64(40, 64n, true);
  new DataView(out.buffer).setUint16(52, 64, true);
  new DataView(out.buffer).setUint16(58, 64, true);
  new DataView(out.buffer).setUint16(60, 2, true);
  new DataView(out.buffer).setUint16(62, 1, true);
  new DataView(out.buffer).setUint32(128, 1, true);
  new DataView(out.buffer).setUint32(132, 3, true);
  new DataView(out.buffer).setBigUint64(152, 192n, true);
  new DataView(out.buffer).setBigUint64(160, 7n, true);
  new DataView(out.buffer).setBigUint64(176, 1n, true);
  out.set([0, 0x2e, 0x74, 0x65, 0x78, 0x74, 0], 192);
  return out;
}

test('the analysis module stands on its own exports', () => {
  for (const name of ['memory', 'alloc', 'dealloc', 'analyse_run', 'analyse_count', 'analyse_at',
    'names_count', 'name_at', 'region_count', 'region_at', 'abi_version', 'self_test']) {
    assert.ok(name in ex, `${modulePath} does not export ${name}`);
  }
  assert.equal(ex.abi_version(), 1);
});

test('a minimal ELF comes back as a section table', () => {
  const { rc, rows } = report(stubElf());
  assert.equal(rc, 0, 'the stub is an object file');
  assert.equal(rows.length, ex.analyse_count());
  assert.equal(
    rows[0],
    'file\telf\tbits\t64\tendian\tlittle\tkind\tdynamic\tmachine\tx86_64\tsections\t2\tsymbols\t0\tdynsym\t0\tentry\t0',
    rows.join(' | ')
  );
  assert.equal(rows[1], 'section\t0\t\taddr\t0\toff\t0\tsize\t0\tdisk\t0\talign\t0');
  assert.equal(rows[2], 'section\t1\t.text\taddr\t0\toff\t192\tsize\t7\tdisk\t7\talign\t1');
  assert.equal(ex.self_test(), rows.length, 'the loader calls self_test before it has any file');
});

test('a file that is not an object file is refused', () => {
  const { rc } = report(new TextEncoder().encode('this is a text file, not a binary'));
  assert.equal(rc, -2);
  assert.equal(ex.analyse_count(), 0, 'a refusal leaves no rows behind');
  assert.equal(ex.names_count(), 0, 'a refusal leaves no names behind either');
});

test('an address answers with the name objdump prints beside the instruction', async () => {
  // The base module's COFF reader was proved against this same object, whose objdump listing is
  // frozen in test/fixtures/coff.probe.json: `answer` at 0, `helper` at 16, and the call written
  // `call 19 <helper+0x9>` - objdump prints addresses in hex, so the target is 0x19, nine bytes into
  // helper. An object file is what the analyser hands the disassembler for one fetch, so the two
  // bases have to be the same numbers - and they are, because a section of an object has no virtual
  // address yet and a symbol's value is already its offset in one.
  const bytes = new Uint8Array(await readFile('test/fixtures/answer.obj'));
  const { rc, rows } = report(bytes);
  assert.equal(rc, 0, `a clang -c object came back refused: ${rows[0]}`);
  assert.match(rows[0], /^file\tcoff\b/, rows[0]);
  assert.match(rows[0], /\tkind\trelocatable\t/, 'an object file is not a rejected input');
  assert.equal(ex.names_count(), 2, `eleven symbols listed, two of them own an address: ${rows.join(' | ')}`);
  assert.equal(text('name_at', 0n), 'answer');
  assert.equal(text('name_at', 5n), 'answer+0x5');
  assert.equal(text('name_at', 16n), 'helper');
  assert.equal(text('name_at', 0x13n), 'helper+0x3');
  assert.equal(text('name_at', 0x19n), 'helper+0x9');
  assert.equal(text('name_at', -1n), '', 'a negative address is not an address');

  // A file with no symbol table has no names, so a panel can say "no names" rather than guess.
  report(stubElf());
  assert.equal(ex.names_count(), 0);
  assert.equal(text('name_at', 0n), '');
});

test('a distribution binary comes through the same ABI', async () => {
  let bytes;
  try {
    bytes = await readFile('/bin/ls');
  } catch {
    return; // only CI has one; the skip is the whole statement
  }
  const { rc, rows } = report(new Uint8Array(bytes));
  assert.equal(rc, 0);
  assert.match(rows[0], /^file\t/);
  const sections = rows.filter((row) => row.startsWith('section\t'));
  assert.ok(sections.length > 1, `only ${sections.length} sections of a real binary`);
  assert.ok(
    rows.some((row) => row.startsWith('dynsym\t')),
    'a dynamically linked /bin/ls has an import table; none was listed'
  );
  assert.ok(
    rows.some((row) => row.startsWith('dynsym\t') && row.includes('\taddr\t')),
    'a dynamic symbol row has no address column'
  );
});

test('the base module the page always downloads carries none of this', async () => {
  if (!basePath) return;
  const base = await instantiate(basePath);
  for (const name of ['analyse_run', 'analyse_count', 'analyse_at', 'names_count', 'name_at',
    'region_count', 'region_at', 'self_test']) {
    assert.ok(!(name in base), `${name} leaked into the base module: ${basePath}`);
  }
  assert.ok('parse_container' in base, 'the base module lost the structural readers');
});

test('the region map accounts for the whole file, in both image formats', async () => {
  // clang + lld linked both fixtures (`scripts/make-image-fixtures.py`), and that script refuses to write
  // `images.probe.json` unless its own reading of the headers agrees with `readelf` and `objdump`. The
  // rows asserted here are those readings, so the byte counts below are the linker's.
  const expect = {
    'lab.elf': 'regions\t12\tfile\t1064\tclaimed\t1046\tunloaded\t18\tloaded-unaddressed\t0',
    'lab.exe': 'regions\t9\tfile\t3072\tclaimed\t1199\tunloaded\t1873\tloaded-unaddressed\t0',
  };
  for (const [name, head] of Object.entries(expect)) {
    const bytes = new Uint8Array(await readFile(`test/fixtures/${name}`));
    report(bytes);
    const total = ex.region_count();
    assert.ok(total > 1, `${name}: the map came back empty`);
    const rows = [];
    for (let index = 0; index < total; index += 1) rows.push(text('region_at', BigInt(index)));
    assert.equal(rows[0], head, `${name}: the totals row moved`);
    let cursor = 0n;
    const kinds = new Set();
    for (const row of rows.slice(1)) {
      const cell = row.split('\t');
      assert.equal(cell[0], 'region', `${name}: ${row}`);
      assert.equal(BigInt(cell[1]), cursor, `${name}: a hole at ${cell[1]}`);
      cursor += BigInt(cell[2]);
      kinds.add(cell[3]);
    }
    assert.equal(cursor, BigInt(bytes.length), `${name}: the map stops short of the end`);
    assert.ok(kinds.has('gap'), `${name}: nothing unclaimed in a linked file? ${[...kinds]}`);
    if (name.endsWith('.elf')) {
      assert.ok(kinds.has('header') && kinds.has('tables') && kinds.has('code'), [...kinds].join(' '));
      assert.ok(!kinds.has('overlay'), 'an ELF ends with its section header table');
    } else {
      assert.ok(kinds.has('overlay'), 'this PE has bytes behind its last table');
      assert.ok(!kinds.has('cert'), 'an unsigned file must not be shown as signed');
    }
  }
  // A COFF object has no loaded segments to map, and the honest answer is no map rather than one range
  // painted over the whole file.
  report(new Uint8Array(await readFile('test/fixtures/answer.obj')));
  assert.equal(ex.region_count(), 0, 'an object file should get no map');
});
