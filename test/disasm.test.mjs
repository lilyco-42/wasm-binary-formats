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

for (const name of ['memory', 'self_test', 'disasm_run', 'disasm_count', 'disasm_at', 'disasm_xrefs',
           'disasm_funcs', 'disasm_cfg']) {
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

function funcs(code, pc, arch) {
  const ptr = ex.malloc(code.length);
  new Uint8Array(ex.memory.buffer, ptr, code.length).set(code);
  const rc = ex.disasm_funcs(ptr, code.length, BigInt(pc), arch);
  ex.free(ptr);
  const rows = [];
  for (let i = 0; i < ex.disasm_count(); i++) rows.push(cString(ex.disasm_at(i)));
  return { rc, rows };
}

function cfg(code, pc, arch) {
  const ptr = ex.malloc(code.length);
  new Uint8Array(ex.memory.buffer, ptr, code.length).set(code);
  const rc = ex.disasm_cfg(ptr, code.length, BigInt(pc), arch);
  ex.free(ptr);
  const rows = [];
  for (let i = 0; i < ex.disasm_count(); i++) rows.push(cString(ex.disasm_at(i)));
  return { rc, rows };
}

test('a conditional branch gives a block two successors, which no linear walk can find', () => {
  // jne +2 at 0x3000 targets the ret at 0x3004, so the nop at 0x3002 is reached only by falling through
  // and the block that ends at 0x3002 closes because 0x3004 is a leader: three blocks, three arrows.
  const { rc, rows } = cfg(new Uint8Array([0x75, 0x02, 0x90, 0xc3]), 0x3000, 0);
  assert.equal(rc, 3, rows.join(' | '));
  assert.equal(rows[0], 'edge\t0\tfrom\t0x3000\tto\t0x3004\tkind\ttaken\tback\tno');
  assert.equal(rows[1], 'edge\t1\tfrom\t0x3000\tto\t0x3002\tkind\tfall\tback\tno');
  assert.equal(rows[2], 'edge\t2\tfrom\t0x3002\tto\t0x3004\tkind\tfall\tback\tno');
  assert.equal(rows[3], 'degree\t0\tpreds\t0\tsuccs\t2\tentry\tyes');
  assert.equal(rows[5], 'degree\t2\tpreds\t2\tsuccs\t0\tentry\tno');
  assert.equal(rows[rows.length - 1], 'cfg\tblocks\t3\tedges\t3\tfall\t2\ttaken\t1\tcall\t0\tback\t0\tunreached\t0');
});

test('a jump to itself is the back edge, and a call out of the window is only a fallthrough', () => {
  // jmp rel8 -2 at 0x3000 jumps to its own address, so the one edge points at or below its source.
  const loop = cfg(new Uint8Array([0xeb, 0xfe]), 0x3000, 0);
  assert.equal(loop.rc, 1, loop.rows.join(' | '));
  assert.equal(loop.rows[0], 'edge\t0\tfrom\t0x3000\tto\t0x3000\tkind\ttaken\tback\tyes');
  assert.ok(loop.rows[loop.rows.length - 1].includes('\tback\t1\t'), loop.rows.join(' | '));

  // call rel32 +10 at 0x2000 leaves the six bytes in hand, so there is no call arrow - the block still
  // falls through to the ret, which is what makes the window's graph a line rather than a loop.
  const out = cfg(new Uint8Array([0xe8, 0x0a, 0x00, 0x00, 0x00, 0xc3]), 0x2000, 0);
  assert.equal(out.rc, 1, out.rows.join(' | '));
  assert.equal(out.rows[0], 'edge\t0\tfrom\t0x2000\tto\t0x2005\tkind\tfall\tback\tno');
  assert.ok(out.rows[out.rows.length - 1].endsWith('\tunreached\t0'), out.rows.join(' | '));
});

test('the graph of a compiled loop matches the listing objdump printed for the same bytes', async () => {
  // `scripts/make-cfg-fixture.py` compiles a C function with a guard, a loop and a three-way branch, then
  // reads it back with objdump and writes the block and edge lists here. The addresses and every branch
  // target are objdump's; the grouping into blocks is this module's rule, stated in the script, and the
  // degrees are arithmetic over the edges. What the two agree on is therefore not "two implementations
  // say the same graph" but "the module computes the graph the listing implies" - which is the honest reach
  // of a fixture written by the same lab that reads it, and the reason the row is spelled out here.
  const probe = JSON.parse(await readFile('test/fixtures/flow.probe.json', 'utf8'));
  const code = Uint8Array.from(probe.text_hex.match(/../g).map((each) => parseInt(each, 16)));
  assert.equal(code.length, probe.text_bytes, "the window does not match the probe's own hex");
  const { rc, rows } = cfg(code, 0, 0);
  const expected = [...probe.edges, ...probe.degrees, probe.summary];
  assert.equal(rc, probe.edges.length, rows.join(' | '));
  assert.deepEqual(rows, expected, rows.join('\n'));

  // Two facts the byte listing alone does not give you, pinned separately so a regression cannot pass by
  // both sides changing together: the loop comes back, and the alignment padding is unreachable.
  const summary = rows[rows.length - 1];
  assert.match(summary, /\tback\t4\t/, summary);
  assert.match(summary, /\tunreached\t1$/, summary);
  assert.ok(rows.some((row) => row.startsWith('edge') && row.includes('to\t0x22') && row.includes('back\tyes')),
    `the loop's back edge is gone: ${rows[7]}`);
});

test('a call out of the window is one function and two blocks', () => {
  // call rel32 +10 at 0x2000 targets 0x200f, past the six bytes in hand, so nothing inside starts a
  // second function; the call still closes its block and the ret closes the next one.
  const { rc, rows } = funcs(new Uint8Array([0xe8, 0x0a, 0x00, 0x00, 0x00, 0xc3]), 0x2000, 0);
  assert.equal(rc, 1, rows.join(' | '));
  assert.deepEqual(rows, [
    'func\t0\tstart\t0x2000\tend\t0x2006\tinsns\t2\tblocks\t2\tcalls\t1\tjumps\t0\trets\t1',
    'block\t0\tfunc\t0\tstart\t0x2000\tend\t0x2005\tinsns\t1\tterm\tcall',
    'block\t1\tfunc\t0\tstart\t0x2005\tend\t0x2006\tinsns\t1\tterm\tret',
    'funcs\ttotal\t1\tblocks\t2\tleaders\t1\tinsns\t2\tentry\t0x2000\twindow\t6',
  ]);
});

test('a call that lands inside the window starts a second function', () => {
  // The displacement is zero, so the target is the address after the call - 0x2005, the ret - and a
  // linear scan has to treat it as an entry. That is what a linker-filled call looks like.
  const { rc, rows } = funcs(new Uint8Array([0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3]), 0x2000, 0);
  assert.equal(rc, 2, rows.join(' | '));
  assert.deepEqual(rows, [
    'func\t0\tstart\t0x2000\tend\t0x2005\tinsns\t1\tblocks\t1\tcalls\t1\tjumps\t0\trets\t0',
    'func\t1\tstart\t0x2005\tend\t0x2006\tinsns\t1\tblocks\t1\tcalls\t0\tjumps\t0\trets\t1',
    'block\t0\tfunc\t0\tstart\t0x2000\tend\t0x2005\tinsns\t1\tterm\tcall',
    'block\t1\tfunc\t1\tstart\t0x2005\tend\t0x2006\tinsns\t1\tterm\tret',
    'funcs\ttotal\t2\tblocks\t2\tleaders\t2\tinsns\t2\tentry\t0x2000\twindow\t6',
  ]);
});

test('a conditional branch closes a block without ending the function', () => {
  // je +1 at 0x3000: the instruction is two bytes, so the target is 0x3002 + 1 - the ret, three bytes
  // in. The hlt between them is not a terminator, but it sits before a leader, so its block ends there
  // with `term none` and the function still runs from 0x3000 to 0x3004.
  const { rc, rows } = funcs(new Uint8Array([0x74, 0x01, 0xf4, 0xc3]), 0x3000, 0);
  assert.equal(rc, 1, rows.join(' | '));
  assert.deepEqual(rows, [
    'func\t0\tstart\t0x3000\tend\t0x3004\tinsns\t3\tblocks\t3\tcalls\t0\tjumps\t1\trets\t1',
    'block\t0\tfunc\t0\tstart\t0x3000\tend\t0x3002\tinsns\t1\tterm\tjump',
    'block\t1\tfunc\t0\tstart\t0x3002\tend\t0x3003\tinsns\t1\tterm\tnone',
    'block\t2\tfunc\t0\tstart\t0x3003\tend\t0x3004\tinsns\t1\tterm\tret',
    'funcs\ttotal\t1\tblocks\t3\tleaders\t2\tinsns\t3\tentry\t0x3000\twindow\t4',
  ]);
});

test('aarch64 blocks come out too, so the pass is not x86 only', () => {
  // bl +8 (0x94000002) at 0x5000 targets 0x5008, one past the eight bytes, then ret.
  const { rc, rows } = funcs(
    new Uint8Array([0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6]), 0x5000, 1
  );
  assert.equal(rc, 1, rows.join(' | '));
  assert.equal(rows[0], 'func\t0\tstart\t0x5000\tend\t0x5008\tinsns\t2\tblocks\t2\tcalls\t1\tjumps\t0\trets\t1');
  assert.equal(rows[1], 'block\t0\tfunc\t0\tstart\t0x5000\tend\t0x5004\tinsns\t1\tterm\tcall');
  assert.equal(rows[2], 'block\t1\tfunc\t0\tstart\t0x5004\tend\t0x5008\tinsns\t1\tterm\tret');
  assert.equal(rows[3], 'funcs\ttotal\t1\tblocks\t2\tleaders\t1\tinsns\t2\tentry\t0x5000\twindow\t8');
});

test('a jump to itself is one block that never leaves', () => {
  // jmp rel8 -2 at 0x3000 lands on its own address, so the block ends at the terminator and the only
  // leader is the entry: one function, one block, and no fallthrough claimed anywhere.
  const { rc, rows } = funcs(new Uint8Array([0xeb, 0xfe]), 0x3000, 0);
  assert.equal(rc, 1, rows.join(' | '));
  assert.deepEqual(rows, [
    'func\t0\tstart\t0x3000\tend\t0x3002\tinsns\t1\tblocks\t1\tcalls\t0\tjumps\t1\trets\t0',
    'block\t0\tfunc\t0\tstart\t0x3000\tend\t0x3002\tinsns\t1\tterm\tjump',
    'funcs\ttotal\t1\tblocks\t1\tleaders\t1\tinsns\t1\tentry\t0x3000\twindow\t2',
  ]);
});
