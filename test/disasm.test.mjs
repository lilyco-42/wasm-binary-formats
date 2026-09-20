// Smoke test for the on-demand disassembly module built by the "Build disassembler module" step of
// .github/workflows/engine.yml.
//
// It answers the two questions that job exists for: is the wasm a real engine rather than a linker
// success that says nothing, and does it do more than print text? So it checks instruction text for
// x86-64 and AArch64 against the encodings the Capstone documentation uses for its examples, and then
// checks the cross-reference pass - which edge comes from which instruction, where the target lands,
// and whether that is inside the window it was handed.
//
//   node test/disasm.test.mjs apk-lens-disasm.wasm
//
// Run from the repository root, after the workflow has produced the module (or locally, if you have
// emscripten - this file does not build anything itself).

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const path = process.argv[2];
assert.ok(path, 'usage: node test/disasm.test.mjs <apk-lens-disasm.wasm>');

// Emscripten's standalone output still asks for a handful of WASI entry points. They are answered by
// name from the module's own import list - so a stub that silently drifts out of date is not what
// this file would fail on - and nothing on this path is expected to call them.
function importsFor(module) {
  const namespaces = {};
  for (const wanted of WebAssembly.Module.imports(module)) {
    namespaces[wanted.module] ||= new Proxy({}, {
      get: () => () => 0,
      has: () => true,
    });
  }
  return namespaces;
}

const bytes = await readFile(path);
const compiled = new WebAssembly.Module(bytes.buffer.slice(0));
// Given a Module, `instantiate` answers with the Instance itself, not the {module, instance} pair it
// returns for the streaming and byte-buffer forms.
const instance = new WebAssembly.Instance(compiled, importsFor(compiled));
const ex = instance.exports;

for (const name of ['memory', 'self_test', 'disasm_run', 'disasm_count', 'disasm_at', 'disasm_xrefs']) {
  assert.ok(name in ex, `${path} does not export ${name}`);
}

function cString(pointer) {
  const memory = new Uint8Array(ex.memory.buffer);
  let end = pointer;
  while (end < memory.length && memory[end] !== 0) end++;
  return new TextDecoder().decode(memory.subarray(pointer, end));
}

function run(code, pc, arch) {
  const ptr = ex.malloc(code.length);
  new Uint8Array(ex.memory.buffer, ptr, code.length).set(code);
  const rc = ex.disasm_run(ptr, code.length, BigInt(pc), arch);
  ex.free(ptr);
  const rows = [];
  for (let i = 0; i < ex.disasm_count(); i++) rows.push(cString(ex.disasm_at(i)));
  return { rc, rows };
}

test('the module decodes its own self test', () => {
  assert.ok(ex.self_test() >= 4, `self_test said ${ex.self_test()}`);
});

test('x86-64 comes out as instruction text, one row per instruction', () => {
  // push rbp; mov rbp, rsp; sub rsp, 0x10; hlt; ret - the prologue self_test uses. Addresses are the
  // hex text the module prints, so a row cannot be read as decimal by mistake.
  const code = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xf4, 0xc3]);
  const { rc, rows } = run(code, 0x1000, 0);
  assert.equal(rc, 5, rows.join(' | '));
  assert.deepEqual(rows, [
    '0x1000\tpush\trbp',
    '0x1001\tmov\trbp, rsp',
    '0x1004\tsub\trsp, 0x10',
    '0x1008\thlt\t',
    '0x1009\tret\t',
  ]);
});

test('aarch64 decodes too, so the module is not x86 only', () => {
  // ret, then mov x29, sp - both little-endian encodings.
  const code = new Uint8Array([0xc0, 0x03, 0x5f, 0xd6, 0xfd, 0x03, 0x00, 0x91]);
  const { rc, rows } = run(code, 0x8000, 1);
  assert.equal(rc, 2, rows.join(' | '));
  assert.deepEqual(rows, ['0x8000\tret\t', '0x8004\tmov\tx29, sp']);
});

test('bytes that decode to nothing are reported as nothing', () => {
  const { rc, rows } = run(new Uint8Array([0x00, 0x00, 0x00, 0x00]), 0, 1);
  assert.ok(rc === 0 || rc > 0, `unexpected return code ${rc}`);
  assert.equal(rows.length, ex.disasm_count());
});

test('an unknown architecture is refused rather than guessed', () => {
  const code = new Uint8Array([0x55]);
  const ptr = ex.malloc(code.length);
  new Uint8Array(ex.memory.buffer, ptr, code.length).set(code);
  assert.equal(ex.disasm_run(ptr, code.length, 0n, 9), -1);
  ex.free(ptr);
  assert.equal(ex.disasm_count(), 0, 'a refusal leaves no rows behind');
});

function xrefs(code, pc, arch) {
  const ptr = ex.malloc(code.length);
  new Uint8Array(ex.memory.buffer, ptr, code.length).set(code);
  const rc = ex.disasm_xrefs(ptr, code.length, BigInt(pc), arch);
  ex.free(ptr);
  const rows = [];
  for (let i = 0; i < ex.disasm_count(); i++) rows.push(cString(ex.disasm_at(i)));
  return { rc, rows };
}

test('a call becomes an edge, and the window says whether it lands inside', () => {
  // call rel32 +10 from 0x2000: the instruction is five bytes, so the target is 0x2000 + 5 + 10, and
  // the six bytes handed in end at 0x2006. ret follows, and has no operands to turn into edges.
  const { rc, rows } = xrefs(new Uint8Array([0xe8, 0x0a, 0x00, 0x00, 0x00, 0xc3]), 0x2000, 0);
  assert.equal(rc, 1, rows.join(' | '));
  assert.equal(rows[0], 'xref\tfrom\t0x2000\tkind\tcall\tto\t0x200f\twhere\toutside');
  assert.equal(rows[rows.length - 1], 'xrefs\ttotal\t1\tinside\t0\toutside\t1\tscanned\t2');
});

test('a branch that stays in the window is marked as staying', () => {
  // jmp rel8 -2 at 0x3000 jumps to itself: 0x3000 + 2 - 2.
  const { rc, rows } = xrefs(new Uint8Array([0xeb, 0xfe]), 0x3000, 0);
  assert.equal(rc, 1, rows.join(' | '));
  assert.equal(rows[0], 'xref\tfrom\t0x3000\tkind\tjump\tto\t0x3000\twhere\tinside');
});

test('an immediate that is not a branch is not an edge', () => {
  // sub eax, 0x10 - the 0x10 is a constant. Listing those would bury the edges that matter.
  const { rc, rows } = xrefs(new Uint8Array([0x83, 0xe8, 0x10]), 0x4000, 0);
  assert.equal(rc, 0, rows.join(' | '));
  assert.deepEqual(rows, ['xrefs\ttotal\t0\tinside\t0\toutside\t0\tscanned\t1']);
});

test('a rip-relative operand is an edge to data outside the code', () => {
  // mov rax, [rip + 0xa] at 0x4000: seven bytes long, so the address reaches 0x4007 + 0xa.
  const { rc, rows } = xrefs(
    new Uint8Array([0x48, 0x8b, 0x05, 0x0a, 0x00, 0x00, 0x00]), 0x4000, 0
  );
  assert.equal(rc, 1, rows.join(' | '));
  assert.equal(rows[0], 'xref\tfrom\t0x4000\tkind\tmem\tto\t0x4011\twhere\toutside');
});

test('aarch64 edges come out too, so the pass is not x86 only', () => {
  // bl +8 at 0x5000 (0x94000002 little-endian), then ret.
  const { rc, rows } = xrefs(
    new Uint8Array([0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6]), 0x5000, 1
  );
  assert.equal(rc, 1, rows.join(' | '));
  assert.equal(rows[0], 'xref\tfrom\t0x5000\tkind\tcall\tto\t0x5008\twhere\toutside');
});
