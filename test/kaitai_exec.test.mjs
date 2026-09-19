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
  const size = statSync(system).size;
  // The reader's own magic check throws during construction, so reaching this line already proves
  // the first four bytes. The remaining names below are the members `Elf.js` in the pinned 0.11
  // generation actually assigns - the ident on the document object, everything after it on
  // `.header`, which is where the endianness and word-size switch lives.
  assert.equal(hex(elf.magic), '7f454c46', `${system} starts with the ELF magic`);
  assert.equal(elf.eiVersion, 1, 'EI_VERSION is the only version in use');
  assert.equal(hex(elf.pad), '00000000000000', 'the seven padding bytes of the ident are zero');
  const header = elf.header;
  assert.equal(header.eVersion, 1, 'e_version is EV_CURRENT');
  assert.ok([1, 2, 3, 4].includes(header.eType), `e_type ${header.eType} is rel/exec/dyn/core`);
  if (os.machine() === 'x86_64') {
    assert.equal(elf.bits, 2, 'ELFCLASS64');
    assert.equal(elf.endian, 1, 'ELFDATA2LSB');
    assert.equal(header.machine, 0x3e, 'EM_X86_64');
    assert.equal(header.eEhsize, 64, 'the 64-bit ELF header size');
    assert.equal(header.programHeaderSize, 56, 'sizeof(Elf64_Phdr)');
    assert.equal(header.sectionHeaderSize, 64, 'sizeof(Elf64_Shdr)');
  }
  assert.ok(Number(header.entryPoint) > 0, 'an executable has an entry point');
  assert.ok(Number(header.ofsProgramHeaders) > 0, 'a runnable binary has a program header table');
  assert.ok(header.numProgramHeaders > 0, `segments: ${header.numProgramHeaders}`);
  assert.ok(header.numSectionHeaders > 0, 'a distribution binary keeps its section headers');
  // The tables have to fit: read a 64-bit offset as 32 bits, or a count from the wrong slot, and
  // this is what gives - no assumption about where the arrays live is needed to say so.
  const programEnd = Number(header.ofsProgramHeaders)
    + header.numProgramHeaders * header.programHeaderSize;
  const sectionsEnd = Number(header.ofsSectionHeaders)
    + header.numSectionHeaders * header.sectionHeaderSize;
  assert.ok(
    programEnd <= size,
    `program header table ends at ${programEnd}, past the ${size} B file`
  );
  assert.ok(
    sectionsEnd <= size,
    `section header table ends at ${sectionsEnd}, past the ${size} B file`
  );
});
