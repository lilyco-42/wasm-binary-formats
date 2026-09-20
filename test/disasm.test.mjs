// Smoke test for the on-demand disassembly module built by .github/workflows/disasm.yml.
//
// It answers the only question that job exists for: is the wasm a real engine, or a linker success
// that says nothing? So it checks printed instruction text, not just that the module instantiates -
// x86-64 and AArch64 both, against the encodings the Capstone documentation uses for its examples.
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

// A standalone-wasm module may still ask for a few host symbols; anything it asks for is answered by
// a no-op so that the import list itself is not what this test fails on.
const stub = new Proxy({}, {
  get: () => () => 0,
  has: () => true,
});

const bytes = await readFile(path);
const { instance } = await WebAssembly.instantiate(bytes.buffer.slice(0), stub);
const ex = instance.exports;

for (const name of ['memory', 'self_test', 'disasm_run', 'disasm_count', 'disasm_at']) {
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
  // push rbp; mov rbp, rsp; sub rsp, 0x10; hlt; ret - the prologue self_test uses.
  const code = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xf4, 0xc3]);
  const { rc, rows } = run(code, 0x1000, 0);
  assert.equal(rc, 5, rows.join(' | '));
  assert.equal(rows[0], '4096\tpush\trbp', rows.join(' | '));
  assert.equal(rows[1], '4097\tmov\trbp, rsp');
  assert.equal(rows[2], '4100\tsub\trsp, 0x10');
  assert.equal(rows[3], '4104\thlt\t');
  assert.equal(rows[4], '4105\tret\t');
});

test('aarch64 decodes too, so the module is not x86 only', () => {
  // ret, then mov x29, sp - both little-endian encodings.
  const code = new Uint8Array([0xc0, 0x03, 0x5f, 0xd6, 0xfd, 0x03, 0x00, 0x91]);
  const { rc, rows } = run(code, 0x8000, 1);
  assert.equal(rc, 2, rows.join(' | '));
  assert.match(rows[0], /^32768\tret\t/, rows.join(' | '));
  assert.match(rows[1], /\tmov\tx29, sp$/, rows.join(' | '));
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
