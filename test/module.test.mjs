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
    'demangle_count', 'demangle_at', 'reloc_count', 'reloc_at',
    'function_count', 'function_at', 'named_count', 'named_at', 'segment_count', 'segment_at',
    'resource_count', 'resource_at',
    'version_count', 'version_at',
    'dynamic_count', 'dynamic_at',
    'debug_count', 'debug_at',
    'symver_count', 'symver_at',
    'tls_count', 'tls_at',
    'note_count', 'note_at',
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
    'export_count', 'export_at', 'import_count', 'import_at', 'demangle_count', 'demangle_at',
    'reloc_count', 'reloc_at', 'function_count', 'function_at', 'named_count', 'named_at',
    'segment_count', 'segment_at',
    'resource_count', 'resource_at',
    'version_count', 'version_at',
    'dynamic_count', 'dynamic_at',
    'debug_count', 'debug_at',
    'symver_count', 'symver_at',
    'tls_count', 'tls_at',
    'note_count', 'note_at',
    'self_test']) {
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

test('the C++ names in an object answer as two demanglers read them', async () => {
  // `cxx.o` and `ops.o` are clang's own output for a linux target, and their `_Z` names are the
  // compiler's spelling - nothing here was typed by hand. `scripts/make-demangle-fixtures.py` read those
  // names out of each object with `llvm-readobj --symbols`, then asked binutils' `c++filt` and LLVM's
  // `llvm-cxxfilt` what each means, and kept as the claim only the names where the two wrote the same
  // string. So every row below is an answer two independent demanglers give.
  const probe = JSON.parse(await readFile('test/fixtures/demangle.probe.json', 'utf8'));
  for (const file of ['cxx.o', 'ops.o']) {
    const bytes = new Uint8Array(await readFile(`test/fixtures/${file}`));
    assert.equal(bytes.length, probe[file].bytes, `${file} is not the object the probe read`);
    const want = probe[file].rows;
    const seen = report(bytes);
    assert.equal(seen.rc, 0, `${file} has to be accepted`);
    assert.equal(ex.demangle_count(), want.length, `${file}: a different number of name rows`);
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(text('demangle_at', index), want[index], `${file} row ${index} moved`);
    }
  }
  // The operators are the bulk of a real symbol table, and every code here is the witnesses' own
  // spelling: `dl` and `da` are the scalar and array forms of delete in that order, `co` is `~`,
  // `cv i` converts to int, and a free operator prints with no class in front of it.
  const ops = probe['ops.o'].agreed;
  assert.equal(Object.keys(ops).length, 48, 'the operator fixture lost names');
  assert.equal(ops._ZN3VecdlEPv, 'Vec::operator delete(void*)');
  assert.equal(ops._ZN3VecdaEPv, 'Vec::operator delete[](void*)');
  assert.equal(ops._ZNK3VeccoEv, 'Vec::operator~() const');
  assert.equal(ops._ZNK3VeccviEv, 'Vec::operator int() const');
  assert.equal(ops._ZmiRK3VecS1_, 'operator-(Vec const&, Vec const&)');
  // `operator<`, `operator<=` and `operator<<` all carry a `<` in the answer without being templates,
  // which is the difference between reading a name and guessing at one: a return type would otherwise
  // be invented in front of each of them.
  assert.equal(ops._ZNK3VecltERKS_, 'Vec::operator<(Vec const&) const');
  assert.equal(ops._ZNK3VecleERKS_, 'Vec::operator<=(Vec const&) const');
  assert.equal(ops._ZNK3VeclsERKS_, 'Vec::operator<<(Vec const&) const');
  // A substitution names the type that *completed*, not the one inside it: the second parameter of
  // `one_ref` is the whole reference, and the free operator's is two declarators deep.
  assert.equal(probe['cxx.o'].agreed._Z7one_refRiS_, 'one_ref(int&, int&)');
  // The one name the two witnesses spell differently is answered with a refusal, and neither of their
  // spellings reaches the report: `Dn` is `decltype(nullptr)` to binutils and `std::nullptr_t` to LLVM.
  const cxx = probe['cxx.o'].rows;
  const refused = cxx.find((row) => row.includes('\tout\t-\t'));
  assert.match(refused, /^sym\t\d+\tin\t_Z4varsPcPKwDn\tout\t-\twhy\tnot in the two-witness subset$/);
  assert.ok(!cxx.some((row) => row.includes('nullptr')), 'a spelling was picked anyway');
  assert.ok(!refused.includes('wchar_t'), 'that name was half demangled');
  assert.deepEqual(Object.keys(probe['cxx.o'].unequal), ['_Z4varsPcPKwDn'], 'the divergence moved');
  assert.deepEqual(probe['ops.o'].unequal, {}, 'two demanglers stopped agreeing on an operator');
  assert.deepEqual(probe['ops.o'].untouched, [], 'a name neither witness read');
  // A C object has no mangled name in it, and the list says so rather than keeping the previous file's.
  report(new Uint8Array(await readFile('test/fixtures/answer.obj')));
  assert.equal(ex.demangle_count(), 1, 'the totals row and nothing else');
  assert.equal(text('demangle_at', 0),
    'demangle\tmangled\t0\tdemangled\t0\trefused\t0\twitnesses\ttwo');
});

test('the fixups a loader would apply come through as two readers listed them', async () => {
  // Three PE images, three answers. `reloc.dll` is clang plus `lld-link` with four address-taken
  // objects in `.data`, which is why its linker had to record anything at all; `lab.dll` is the .NET
  // compiler's PE32, so it shows the other optional-header base and the padding slot that fixes up
  // nothing; `exp.dll` has no directory, and says so with one line.
  // `scripts/make-reloc-fixtures.py` refuses to write the probe unless `llvm-readobj
  // --coff-basereloc` and `pefile` agree entry by entry, and the type names below are the numbers
  // those two put beside in these files rather than a table recalled.
  const probe = JSON.parse(await readFile('test/fixtures/reloc.probe.json', 'utf8'));
  assert.deepEqual(probe.type_names, { 0: 'ABSOLUTE', 3: 'HIGHLOW', 10: 'DIR64' }, 'a pairing moved');
  for (const file of ['reloc.dll', 'lab.dll', 'exp.dll']) {
    const want = probe.files[file].rows;
    const bytes = new Uint8Array(await readFile(`test/fixtures/${file}`));
    assert.equal(bytes.length, probe.files[file].bytes, `${file} is not what the probe read`);
    const seen = report(bytes);
    assert.equal(seen.rc, 0, `${file} has to be an object`);
    assert.equal(ex.reloc_count(), want.length, `${file}: a different number of fixup rows`);
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(text('reloc_at', index), want[index], `${file} row ${index} moved`);
    }
  }
  // The `.data` word at `0x3000` is a pointer because the directory says so, and the position the
  // loader writes at is in the file - which is the whole point of reading it.
  assert.equal(probe.files['reloc.dll'].rows[2],
    'fixup\t0x3000\ttype\t10\tname\tDIR64\toff\t2048\tsection\t.data');
  assert.match(probe.files['lab.dll'].rows[3], /^fixup\t0x2000\ttype\t0\tname\tABSOLUTE\t/);
  assert.equal(probe.files['exp.dll'].rows.length, 1, 'an absent directory is one line');
  assert.match(probe.files['exp.dll'].rows[0], /\toff\t-1\tsection\tnone\tblocks\t0\b/);
  // A PE-only answer: an ELF and a COFF object keep their fixups in relocation records, which are a
  // different list in a different format, so the panel comes back empty rather than with the rows the
  // image read a moment before left behind.
  report(new Uint8Array(await readFile('test/fixtures/lab.elf')));
  assert.equal(ex.reloc_count(), 1, 'an ELF answers with its own record tables');
  assert.match(text('reloc_at', 0), /^relocs	kind	dyn	tables	0	entries	0	/);
  // A third object file, and the case where only one reader names a type: binutils prints UNKNOWN
  // for every aarch64 relocation, so the numbers are listed and the names are withheld.
  report(new Uint8Array(await readFile('test/fixtures/labarm.so')));
  assert.equal(ex.reloc_count(), 12, 'an aarch64 object answered a different number of rows');
  assert.match(text('reloc_at', 4), /	type	1025	name	R_AARCH64_GLOB_DAT	sym	data_at	/);
  report(new Uint8Array(await readFile('test/fixtures/answer.obj')));
  assert.equal(ex.reloc_count(), 0, 'and a COFF object has neither shape');
});

test('the resource tree the witnesses recorded is what the built module reports', async () => {
  // scripts/make-resource-fixtures.py builds res.dll with csc and rcres.dll with rc + windres + gcc,
  // then refuses to write `resource.probe.json` unless a python walk of the bytes, `llvm-readobj
  // --coff-resources` and Windows' own loader agree on every type, name, language, size and body byte.
  // This is that probe against the module as CI built it - the deployed build, not a local compile.
  const probe = JSON.parse(await readFile('test/fixtures/resource.probe.json', 'utf8'));
  for (const name of ['res.dll', 'rcres.dll']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.resource_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the witnesses said ${want.length}`);
    for (let index = 0; index < total; index += 1) {
      assert.equal(text('resource_at', index), want[index], `${name} row ${index}`);
    }
  }
  // A PE-only tree: an ELF has no resource directory, and a COFF object has no data directories at all,
  // so both come back empty rather than with the rows the image read a moment before left behind.
  for (const name of ['lab.elf', 'answer.obj']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.resource_count(), 0, `${name} answered with a resource tree`);
  }
});

test('the version block the API agrees with is read out of the file, not asked for by name', async () => {
  // scripts/make-version-fixtures.py parses res.dll's VS_VERSIONINFO tree and then asks Windows,
  // through GetFileVersionInfoW and VerQueryValueW, about every key the tree lists - which is how
  // `Assembly Version`, a key no standard list carries, is in the probe at all. The fixed block's
  // thirteen words, the language pairs and each string had to match before the file was written.
  const probe = JSON.parse(await readFile('test/fixtures/version.probe.json', 'utf8'));
  for (const name of ['res.dll', 'rcres.dll']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.version_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the two readers said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('version_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
  }
  // One key the loader would never be asked for, and the strings that are a single space in the file
  // stay a single space rather than being reported as empty.
  report(new Uint8Array(await readFile('test/fixtures/res.dll')));
  const rows = Array.from({ length: ex.version_count() }, (_, index) => text('version_at', index));
  assert.ok(rows.includes('string	Assembly Version	0.0.0.0'), rows.join(' | '));
  // Two of the three free-text fields are a single space in this file. The count is taken from the
  // probe rather than typed in here - a guessed number in an assertion is how this test failed in CI,
  // where there is no local build of the module to catch it first.
  const blank = (one) => one.endsWith('\t ');
  const wanted = probe["res.dll"].rows.filter(blank).length;
  assert.ok(wanted > 0, 'the probe has no space-only value, so this proves nothing');
  assert.equal(rows.filter(blank).length, wanted, 'a value was dropped, not printed as spelled');
  for (const name of ['lab.elf', 'answer.obj']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.version_count(), 0, `${name} answered with a version block`);
  }
});

test('the entries an ELF hands its loader are what readelf and llvm-readobj listed', async () => {
  // scripts/make-dynamic-fixtures.py walks PT_DYNAMIC in Python and then asks binutils' `readelf -dW`
  // and LLVM's `--dynamic-table` about the same bytes. An entry is not written to the probe unless all
  // three agree on its order, tag number and value, and unless the two readers spell that tag the same
  // word and spell a value's word the same way - so what is asserted below is those programs' listing
  // of these files, including which one stores each entry in 8 bytes rather than 16.
  const probe = JSON.parse(await readFile('test/fixtures/dynamic.probe.json', 'utf8'));
  const cell = (row, key) => {
    const parts = row.split('\t');
    return parts[parts.indexOf(key) + 1];
  };
  const widths = new Set();
  for (const name of Object.keys(probe).sort()) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.dynamic_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the two readers said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('dynamic_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
    if (want.length > 0) widths.add(cell(want[0], 'width'));
  }
  // Both record widths have to turn up among the files, or the narrow one proves nothing about the stride.
  assert.ok(widths.has('8') && widths.has('16'), `widths seen: ${Array.from(widths).join(', ')}`);
  // One file is long enough to be cut, and a cut list still has to be counted whole: the totals row is
  // the file's own number, not the number of rows the panel was allowed to show.
  const long = Object.keys(probe).filter((one) => probe[one].rows.some((row) => row.startsWith('cut\t')));
  assert.equal(long.length, 1, `expected exactly one capped fixture, saw ${long.join(', ')}`);
  report(new Uint8Array(await readFile(`test/fixtures/${long[0]}`)));
  const rows = Array.from({ length: ex.dynamic_count() }, (_, index) => text('dynamic_at', index));
  const stated = Number(cell(rows[0], 'entries'));
  assert.ok(stated > rows.filter((one) => one.startsWith('entry\t')).length,
    `${long[0]}: ${stated} entries stated, ${rows.length} rows listed`);
  // A PE names what it needs through a data directory of its own and a static executable has no
  // PT_DYNAMIC at all, so neither grows a list here - `lab.elf` already answered zero above.
  for (const name of ['res.dll', 'answer.obj']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.dynamic_count(), 0, `${name} answered with a dynamic section`);
  }
});

test('the debug directory both readers parsed is the one the module reports', async () => {
  // scripts/make-debug-fixtures.py links dbg.exe with clang -g -gcodeview and lld-link /debug, then
  // asks `llvm-readobj --coff-debug-directory` and pefile about it. An entry reaches the probe only if
  // the byte walk, LLVM and pefile agree on its type number, time stamp, version pair, size and both
  // locations - and, for a body that starts RSDS, on the signature, the GUID, the age and the path.
  // Nothing is guessed about the GUID's byte order either: the row holds the digits both readers spell.
  const probe = JSON.parse(await readFile('test/fixtures/debug.probe.json', 'utf8'));
  const cell = (row, key) => {
    const parts = row.split('	');
    return parts[parts.indexOf(key) + 1];
  };
  for (const name of Object.keys(probe).sort()) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.debug_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the two readers said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('debug_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
  }
  // Two shapes of CodeView path have to be present for this to mean anything: a name, and the empty
  // string a link leaves when no PDB was ever asked for.
  const all = Object.values(probe).flatMap((one) => one.rows).filter((row) => row.startsWith('cv	'));
  assert.ok(all.some((row) => row.endsWith('	path	')), 'no empty-path case in the probe');
  assert.ok(all.some((row) => /	path	\S/.test(row)), 'no named-path case in the probe');
  // The offset the reader derived from the entry's RVA is where the signature has to actually be, and
  // it is printed beside the offset the entry states for itself - which is the pairing a symbol lookup
  // lives or dies by, so it is checked against the bytes rather than taken on trust.
  const bytes = new Uint8Array(await readFile('test/fixtures/dbg.exe'));
  report(bytes);
  const rows = Array.from({ length: ex.debug_count() }, (_, index) => text('debug_at', index));
  const entry = rows.find((row) => row.startsWith('entry	'));
  const shape = rows.find((row) => row.startsWith('cv	'));
  const at = Number(cell(entry, 'body'));
  assert.equal(at, Number(cell(entry, 'ptr')), `${entry} puts the body in two different places`);
  const head = String.fromCharCode(...bytes.subarray(at, at + 4));
  assert.equal(head, cell(shape, 'sig'), `${shape} is not at offset ${at}`);
  // A COFF object carries .debug$S sections and no directory, and an ELF has no such thing at all.
  for (const name of ['answer.obj', 'lab.elf', 'nodbg.exe']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.debug_count(), 0, `${name} answered with a debug directory`);
  }
});

test('the version tables both listings read are the ones the module reports', async () => {
  // scripts/make-symver-fixtures.py links libver.so and libver32.so from one object and one two-node
  // version script, then links libuse.so against the first so that the needs side is a real link
  // rather than an edited byte. A row reaches the probe only when the byte walk, `readelf -VW` and
  // `llvm-readobj --version-info` agree on every index, hash, flag, name and count, and when
  // DT_VERDEFNUM and DT_VERNEEDNUM match the chains actually walked.
  const probe = JSON.parse(await readFile('test/fixtures/symver.probe.json', 'utf8'));
  const cell = (row, key) => {
    const parts = row.split('	');
    return parts[parts.indexOf(key) + 1];
  };
  const classes = new Set();
  for (const name of Object.keys(probe).sort()) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.symver_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the two readers said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('symver_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
    if (want.length > 0) classes.add(cell(want[0], 'bits'));
  }
  // Both classes have to be among the files, or the 32-bit one proves nothing about the widths.
  assert.ok(classes.has('32') && classes.has('64'), `classes seen: ${Array.from(classes).join(', ')}`);
  // A symbol index that names something has to be named by one of the tables in the same file, and the
  // two reserved indices name nothing - binutils calls them *local* and *global*, LLVM says nothing.
  for (const name of ['libver.so', 'libuse.so']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const rows = Array.from({ length: ex.symver_count() }, (_, index) => text('symver_at', index));
    const tables = new Map();
    for (const row of rows.filter((one) => one.startsWith('def	') || one.startsWith('need	'))) {
      tables.set(cell(row, 'index'), cell(row, 'name'));
    }
    for (const row of rows.filter((one) => one.startsWith('symbol	'))) {
      const index = cell(row, 'index');
      const reached = cell(row, 'name');
      if (reached === '-') {
        assert.ok(!tables.has(index) || index === '0' || index === '1', `${name}: ${row} names nothing anyway`);
        continue;
      }
      assert.equal(tables.get(index), reached, `${name}: ${row} invents a name`);
    }
  }
  // Nothing here is a version table: a shared object built without a version script, a static
  // executable, and a PE, which has no such convention at all.
  for (const name of ['lab.so', 'lab.elf', 'res.dll']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.symver_count(), 0, `${name} answered with version tables`);
  }
});

test('the thread-local table the loader walks is the one the module reports', async () => {
  // scripts/make-tls-fixtures.py builds tls.dll from a source with seventy callbacks and plain.dll from
  // one with none, then writes a row only where five readings agree: its own walk, `llvm-readobj
  // --coff-tls-directory`, pefile's `DIRECTORY_ENTRY_TLS`, the base-relocation list - which enumerates
  // the array without reading it - and Windows itself running the callbacks and reporting their order.
  const probe = JSON.parse(await readFile('test/fixtures/tls.probe.json', 'utf8'));
  const cell = (row, key) => {
    const parts = row.split('	');
    return parts[parts.indexOf(key) + 1];
  };
  for (const name of Object.keys(probe).sort()) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.tls_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the five readings said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('tls_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
    // Every address the file states is given three ways, and the three have to be the same number: a
    // reader that subtracted the image base twice, or not at all, agrees with itself here only by accident.
    if (want.length === 0) {
      continue;
    }
    const base = Number(BigInt(cell(want[0], 'base')));
    for (const row of want.filter((one) => one.startsWith('field	') || one.startsWith('callback	'))) {
      assert.equal(Number(BigInt(cell(row, 'value'))) - base, Number(BigInt(cell(row, 'rva'))),
        `${name}: ${row} does not subtract the base once`);
    }
    // The count in the totals row is the file's own enumeration, not the number of rows the panel was
    // allowed to show, so a cut list has to state the whole of it.
    const listed = want.filter((one) => one.startsWith('callback	')).length;
    const stated = Number(cell(want[0], 'callbacks'));
    assert.ok(listed <= stated, `${name}: ${listed} rows for ${stated} callbacks`);
    if (stated > listed) {
      const cut = want[want.length - 1];
      assert.ok(cut.startsWith('cut	'), `${name}: a capped list with no cut row`);
      assert.equal(cell(cut, 'callbacks'), String(stated), `${name}: the cut row counts something else`);
    }
  }
  // The interesting difference between the two files is what an analyser may not conclude: a DLL built
  // from a source that never mentions `_Thread_local` still has a table, because its runtime supplies
  // one - and its two callbacks come back with the higher address first, which is the array's order and
  // not a sort.
  report(new Uint8Array(await readFile('test/fixtures/plain.dll')));
  const thin = Array.from({ length: ex.tls_count() }, (_, index) => text('tls_at', index));
  const bodies = thin.filter((one) => one.startsWith('callback	'));
  assert.equal(bodies.length, 2, 'the table the runtime supplies is not there');
  assert.ok(Number(BigInt(cell(bodies[0], 'rva'))) > Number(BigInt(cell(bodies[1], 'rva'))),
    'the array came back sorted');
  assert.ok(bodies.every((one) => cell(one, 'name') === '-'), 'a callback the file exports was named');
  // An ELF keeps its thread-local bookkeeping in program headers, a COFF object has no data directories
  // at all, and `res.dll` is a PE32 image - the width no fixture here reaches.
  for (const name of ['lab.so', 'lab32.so', 'answer.obj', 'res.dll']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.tls_count(), 0, `${name} answered with a PE's TLS directory`);
  }
});

test('the notes both listings read are the ones the module reports', async () => {
  // scripts/make-note-fixtures.py compiles the same four lines of C as an object, as an image linked
  // with -fcf-protection=full and a build ID, and as one with branch tracking alone, then adds a file
  // carrying a note written by hand in assembly. A row reaches the probe only where the byte walk,
  // `readelf -nW` and `llvm-readobj --notes` agree on owner, descriptor length, type word and payload.
  const probe = JSON.parse(await readFile('test/fixtures/note.probe.json', 'utf8'));
  const cell = (row, key) => {
    const parts = row.split('	');
    return parts[parts.indexOf(key) + 1];
  };
  const routes = new Set();
  for (const name of Object.keys(probe).sort()) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    const want = probe[name].rows;
    const total = ex.note_count();
    assert.equal(total, want.length, `${name}: ${total} rows, the two listings said ${want.length}`);
    const got = Array.from({ length: total }, (_, index) => text('note_at', index));
    for (let index = 0; index < want.length; index += 1) {
      assert.equal(got[index], want[index], `${name} row ${index}`);
    }
    if (want.length === 0) {
      continue;
    }
    routes.add(cell(want[0], 'walked'));
    // The rows a file carries are the notes it carries: one row per note, plus one per record inside a
    // property note, and the totals row counts the notes rather than the rows.
    const notes = want.filter((one) => one.startsWith('note	')).length;
    assert.equal(Number(cell(want[0], 'entries')), notes, `${name}: the totals row counts something else`);
    assert.ok(notes <= want.length - 1, `${name}: fewer notes than rows`);
  }
  // Both routes have to turn up: an image is read through its note segments and a relocatable object,
  // which has no program headers at all, through its note sections.
  assert.ok(routes.has('segment') && routes.has('section'), `routes seen: ${Array.from(routes).join(', ')}`);
  // A note whose padding a reader got wrong would move every later note, so the hand-written pair is
  // checked against the GNU note that follows it: five bytes of descriptor, then a two-byte name.
  report(new Uint8Array(await readFile('test/fixtures/notelab.elf')));
  const rows = Array.from({ length: ex.note_count() }, (_, index) => text('note_at', index));
  const listed = rows.filter((one) => one.startsWith('note	'));
  assert.equal(listed.length, 3, 'the hand-written notes did not survive the walk');
  assert.equal(cell(listed[0], 'descsz'), '5', 'a five-byte descriptor lost its padding');
  assert.equal(cell(listed[1], 'namesz'), '2', 'the second note was not where the rounding puts it');
  assert.equal(cell(listed[2], 'word'), 'NT_GNU_PROPERTY_TYPE_0', 'the note after them moved');
  // A PE carries no ELF notes, and an ELF built without any answers with nothing either.
  for (const name of ['res.dll', 'answer.obj', 'lab.elf', 'tls.dll']) {
    report(new Uint8Array(await readFile(`test/fixtures/${name}`)));
    assert.equal(ex.note_count(), 0, `${name} answered with notes it does not have`);
  }
});
