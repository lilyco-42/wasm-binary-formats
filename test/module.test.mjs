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
    'names_count', 'name_at', 'region_count', 'region_at', 'string_count', 'string_at',
    'type_count', 'type_at', 'export_count', 'export_at', 'import_count', 'import_at',
    'abi_version', 'self_test']) {
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
    'region_count', 'region_at', 'string_count', 'string_at', 'type_count', 'type_at',
    'export_count', 'export_at', 'import_count', 'import_at', 'self_test']) {
    assert.ok(!(name in base), `${name} leaked into the base module: ${basePath}`);
  }
  assert.ok('parse_container' in base, 'the base module lost the structural readers');
});

test('the region map accounts for the whole file, in both image formats', async () => {
  // clang + lld linked both fixtures (`scripts/make-image-fixtures.py`), and that script refuses to write
  // `images.probe.json` unless its own reading of the headers agrees with `readelf` and `objdump`. The
  // rows asserted here are those readings, so the byte counts below are the linker's.
  const expect = {
    'lab.elf': 'regions\t12\tfile\t1152\tclaimed\t1128\tunloaded\t24\tloaded-unaddressed\t0',
    'lab.exe': 'regions\t9\tfile\t3072\tclaimed\t1273\tunloaded\t1799\tloaded-unaddressed\t0',
  };
  for (const [name, head] of Object.entries(expect)) {
    const bytes = new Uint8Array(await readFile(`test/fixtures/${name}`));
    report(bytes);
    const total = ex.region_count();
    assert.ok(total > 1, `${name}: the map came back empty`);
    const rows = [];
    for (let index = 0; index < total; index += 1) rows.push(text('region_at', index));
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
  assert.equal(ex.string_count(), 0, 'and no string list either');
});

test('the string list carries only bytes a running program touches', async () => {
  // Both fixtures were compiled and linked here (`scripts/make-image-fixtures.py`), and that script
  // refuses to write `images.probe.json` unless every row predicted below is one `strings -t x -a -n 4`
  // also prints at the same offset and length. What binutils prints *extra* - the linker's own
  // "Linker: LLD …" banner, which is the first byte of `.comment`, and `!This program cannot be run in
  // DOS mode.` in the MS-DOS stub - must stay out, because a tool reads those bytes and the program
  // never loads them. That is the difference between this list and `strings` output.
  const cases = {
    'lab.elf': [
      'strings\t2\tmin\t4\tscanned\t97\tranges\t1',
      'string\t0x200120\t288\t43\ta lab fixture string padded out to length!!\t.rodata',
      'string\t0x200150\t336\t48\ta second literal the linker will place beside it\t.rodata',
    ],
    'lab.exe': [
      'strings\t4\tmin\t4\tscanned\t189\tranges\t2',
      'string\t0x140002000\t1536\t43\ta lab fixture string padded out to length!!\t.rdata',
      'string\t0x140002030\t1584\t48\ta second literal the linker will place beside it\t.rdata',
      'string\t0x14000301c\t2076\t5\tRSDS,\t.buildid',
      'string\t0x140003025\t2085\t11\tovsLLD PDB.\t.buildid',
    ],
  };
  for (const [name, want] of Object.entries(cases)) {
    const bytes = new Uint8Array(await readFile(`test/fixtures/${name}`));
    report(bytes);
    const total = ex.string_count();
    assert.equal(total, want.length, `${name}: the list has ${total} rows, not ${want.length}`);
    const map = Array.from({ length: ex.region_count() }, (_, index) =>
      text('region_at', index).split('\t')
    );
    for (let index = 0; index < total; index += 1) {
      const row = text('string_at', index);
      assert.equal(row, want[index], `${name}: row ${index} moved`);
      if (!row.startsWith('string\t')) continue;
      const cell = row.split('\t');
      const address = BigInt(cell[1]);
      const offset = Number(cell[2]);
      const length = Number(cell[3]);
      assert.ok(/^[0-9a-z_.]+\t$/.test(`${cell[5]}\t`), `${name}: ${row} names no section`);
      // The address is the region's own virtual base plus the distance into that region, so a string
      // row and a disassembly row mean the same byte - the basis the page's 引用 column depends on.
      const holder = map.find((each) => each[0] === 'region'
        && BigInt(each[1]) <= BigInt(offset)
        && BigInt(offset) < BigInt(each[1]) + BigInt(each[2]));
      assert.ok(holder, `${name}: ${row} falls outside the map`);
      const base = /0x([0-9a-f]+)/.exec(holder[5]);
      assert.ok(base, `${name}: ${holder.join('\t')} is loaded but names no address`);
      assert.equal(
        address,
        BigInt(`0x${base[1]}`) + BigInt(offset - Number(holder[1])),
        `${name}: ${row} is not on ${holder[4]}'s basis`
      );
      // Length is the printable run itself, read back out of the file: the fixture's first literal is 43
      // bytes and the second starts at +48, so a run that ran on to the next byte would fail here.
      const text_cell = cell[4];
      assert.equal(
        new TextDecoder().decode(bytes.subarray(offset, offset + length)),
        text_cell,
        `${name}: ${row} does not match the bytes at ${offset}`
      );
      const after = bytes[offset + length];
      assert.ok(
        after === undefined || !(after >= 0x20 && after <= 0x7e)
          || offset + length >= Number(holder[1]) + Number(holder[2]),
        `${name}: ${text_cell} is cut mid-run at ${offset + length} (${after})`
      );
    }
  }
});

test('the type list is the record stream, leaf by leaf', async () => {
  // `scripts/make-codeview-fixtures.py` writes `cv.obj` with clang, links it with lld and refuses to
  // emit the probe unless its own walk of `.debug$T` and `llvm-pdbutil dump -types` on the resulting
  // PDB agree in both directions - including the two records a struct gets when the compiler emits a
  // forward declaration as well as a definition. So every row below is a fact about CodeView, read off
  // a second implementation, and the module has to reproduce all of them.
  const probe = JSON.parse(await readFile('test/fixtures/codeview.probe.json', 'utf8'));
  const want = probe['cv.obj'].rows;
  assert.ok(want.length > 50, `the probe lost its rows: ${want.length}`);
  report(new Uint8Array(await readFile('test/fixtures/cv.obj')));
  assert.equal(ex.type_count(), want.length, 'the module listed a different number of rows');
  for (let index = 0; index < want.length; index += 1) {
    assert.equal(text('type_at', index), want[index], `row ${index} moved`);
  }
  // A file with no CodeView stream has no types: the answer is an empty list, not a guess from the
  // section names. `answer.obj` is clang's output without -gcodeview.
  report(new Uint8Array(await readFile('test/fixtures/answer.obj')));
  assert.equal(ex.type_count(), 0, 'a plain object invented a type stream');
});

test('a program database answers with the types its TPI stream holds', async () => {
  // The engine's container reader says what a .pdb is; this is the part only the analysis module can
  // do. The rows come from the same probe the generator refused to write unless `llvm-pdbutil
  // dump --types` agreed with its own walk of the stream, so the module is checked against the
  // linker's and LLVM reader's answer rather than against this one's.
  const probe = JSON.parse(await readFile('test/fixtures/pdb.probe.json', 'utf8'));
  const want = probe['lab.pdb'].types.rows;
  assert.ok(want.length > 10, `the probe lost its type rows: ${want.length}`);
  const bytes = new Uint8Array(await readFile('test/fixtures/lab.pdb'));
  assert.equal(report(bytes).rc, 0, 'a PDB is an accepted input, not a refusal');
  assert.equal(ex.type_count(), want.length, 'the type list has a different length');
  for (let index = 0; index < want.length; index += 1) {
    assert.equal(text('type_at', index), want[index], `TPI row ${index} moved`);
  }
  // And no map, because a database image is never loaded: the panels that answer for loaded bytes
  // have nothing to say here.
  assert.equal(ex.region_count(), 0, 'a PDB is not loaded anywhere');
  assert.equal(ex.string_count(), 0, 'so it has no loaded data to scan');
});

test('a DLL hands out the exports both readers say it does', async () => {
  // `scripts/make-export-fixtures.py` links `exp.dll` with lld and refuses to write
  // `test/fixtures/exports.probe.json` unless its own walk of the directory agrees with BOTH
  // `llvm-readobj --coff-exports` and `objdump -x` - on the ordinal base, the three table addresses,
  // every slot, and the text of the forwarder. The empty slot is the reason two readings are needed:
  // llvm lists it as ordinal 8 with no address, bfd leaves it out of its table altogether, and the
  // module has to say `hole` rather than pick a side.
  const probe = JSON.parse(await readFile('test/fixtures/exports.probe.json', 'utf8'));
  const want = probe.rows;
  assert.equal(want.length, 8, `the probe lost its rows: ${want.length}`);
  const bytes = new Uint8Array(await readFile('test/fixtures/exp.dll'));
  assert.equal(report(bytes).rc, 0, 'a DLL is an accepted input');
  assert.equal(ex.export_count(), want.length, 'the module listed a different number of exports');
  for (let index = 0; index < want.length; index += 1) {
    assert.equal(text('export_at', index), want[index], `row ${index} moved`);
  }
  // A COFF object is not an image and has no export directory, so the list is empty rather than left
  // over from the DLL that was read a moment before.
  report(new Uint8Array(await readFile('test/fixtures/answer.obj')));
  assert.equal(ex.export_count(), 0, 'an object file hands out nothing');
});

test('the imports a loader will fill in come through as the readers spell them', async () => {
  // Three files, one producer: `csc.exe` wrote `lab.dll`, and the other two are its bytes with one
  // u32 changed - the lookup-table entry, to ask for ordinal 12 instead of a name; and the
  // descriptor's lookup-table pointer, to leave only the address table behind.
  // `scripts/make-import-fixtures.py` refuses to write the probe unless `objdump -x` and
  // `llvm-readobj --coff-imports` agree with its own walk on all three, so what is asserted below is
  // what the two readers say about those bytes, not what this module chose to say first.
  const probe = JSON.parse(await readFile('test/fixtures/imports.probe.json', 'utf8'));
  for (const file of ['lab.dll', 'ordinal.dll', 'noilt.dll']) {
    const want = probe[file].rows;
    assert.equal(want.length, 3, `${file} lost rows: ${want.length}`);
    const seen = report(new Uint8Array(await readFile(`test/fixtures/${file}`)));
    assert.equal(seen.rc, 0, `${file} has to be accepted`);
    assert.equal(ex.import_count(), want.length, `${file}: a different number of import rows`);
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(text('import_at', index), want[index], `${file} row ${index} moved`);
    }
  }
  // The difference between the three files is one field each, and the rows show it: the same name read
  // out of the other table, and an ordinal with no name to read at all.
  assert.match(probe['noilt.dll'].rows[1], /\tilt\t0x0\tiat\t0x2000\tnames\tiat\b/);
  assert.match(probe['ordinal.dll'].rows[2], /^thunk\tmscoree\.dll\t-\tordinal\t12\tslot\t0x2000$/);
  assert.ok(!probe['ordinal.dll'].rows[2].includes('_CorDllMain'), 'an ordinal import has no name');
  // The same addresses answer the index the disassembler labels functions with, which is the point of
  // carrying the slot at all: a call through it can be named instead of synthesised.
  report(new Uint8Array(await readFile('test/fixtures/lab.dll')));
  assert.equal(text('name_at', 0x1000_2000n), 'mscoree.dll!_CorDllMain');
  report(new Uint8Array(await readFile('test/fixtures/ordinal.dll')));
  assert.equal(text('name_at', 0x1000_2000n), 'mscoree.dll#12', 'no name to borrow, so the number');
  report(new Uint8Array(await readFile('test/fixtures/exp.dll')));
  assert.equal(text('name_at', 0x1_8000_1000n), 'shipped', 'three names, the table’s first one');
  assert.equal(ex.import_count(), 0, 'a DLL that hands out names need not ask for any');
});
