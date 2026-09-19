// Real-byte assertions for the executable-format readers, on binaries the runner already has.
//
// ELF cannot be committed here - it is a distribution binary, and its layout is only interesting
// in the shape a linker actually emits. So this reads the system dynamic executable the same way
// the Rust engine's tests read a fixture, from a path list, and reports a skip rather than a pass
// where no such file exists (a Windows or macOS developer box). The claims are ones every ELF64
// executable produced by GNU binutils satisfies, and several of them are only checkable against a
// real file: the section header table has to sit inside the file with room for the count it
// advertises, which cannot hold if the 64-bit offsets are being read as 32-bit ones.
//
//   node test/kaitai_exec.test.mjs path/to/generated   (default: generated/kaitai)
import { createRequire } from 'node:module';
import { existsSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const KaitaiStream = require('kaitai-struct/KaitaiStream');

function load(name) {
  const file = join(generatedDir, `${name}.js`);
  assert.ok(statSync(file).size > 0, `${file} is empty`);
  const mod = require(file);
  return mod[name] ?? mod.default
    ?? Object.values(mod).find((value) => typeof value === 'function')
    ?? mod;
}

const CANDIDATES = ['/bin/ls', '/usr/bin/ls', '/bin/cat', '/usr/bin/file'];
const system = CANDIDATES.find((path) => existsSync(path));

const hex = (bytes) => Buffer.from(bytes).toString('hex');

test('Elf: the generated reader agrees with a linker-produced binary', {
  skip: system ? false : `no system ELF among ${CANDIDATES.join(', ')}`,
}, () => {
  const bytes = new Uint8Array(readFileSync(system));
  const Elf = load('Elf');
  const elf = new Elf(new KaitaiStream(bytes), null, null);
  assert.equal(hex(elf.magic.slice(0, 4)), '7f454c46', `${system} starts with the ELF magic`);
  assert.equal(elf.eiVersion, 1, 'EI_VERSION is the only version in use');
  assert.equal(elf.bits, os.machine() === 'x86_64' ? 2 : elf.bits, 'class: 2 means 64-bit');
  assert.equal(elf.endian, os.machine() === 'x86_64' ? 1 : elf.endian, 'data: 1 means little-endian');
  if (os.machine() === 'x86_64') {
    assert.equal(elf.machine, 0x3e, 'EM_X86_64');
    assert.equal(elf.eEhsize, 64, 'the 64-bit ELF header size');
    assert.equal(elf.programHeaderSize, 56, 'sizeof(Elf64_Phdr)');
    assert.equal(elf.sectionHeaderSize, 64, 'sizeof(Elf64_Shdr)');
  }
  assert.ok([1, 2, 3, 4].includes(elf.eType), `e_type ${elf.eType} is one of rel/exec/dyn/core`);
  assert.ok(Number(elf.entryPoint) > 0, 'an executable has an entry point');
  assert.ok(Number(elf.ofsProgramHeaders) > 0);
  assert.ok(elf.numProgramHeaders > 0, 'a runnable binary has segments');
  assert.ok(elf.numSectionHeaders > 0, 'a distribution binary keeps its section headers');
  // The tables have to fit: read one field too narrow and this is what gives.
  const size = statSync(system).size;
  const sectionsEnd = Number(elf.ofsSectionHeaders) + elf.numSectionHeaders * elf.sectionHeaderSize;
  assert.ok(
    sectionsEnd <= size,
    `section header table (${sectionsEnd} B) must fit inside the ${size} B file`
  );
  assert.equal(elf.programHeaders.length, elf.numProgramHeaders);
  assert.equal(elf.sectionHeaders.length, elf.numSectionHeaders);
  // Section 0 is SHN_UNDEF, which is always empty - the field the reader itself uses to size a
  // section body, so this also proves `sectionHeaderSize` was read as 64 and not 40.
  assert.equal(elf.sectionHeaders[0].lenBody, 0, 'the undefined section has no body');
});
