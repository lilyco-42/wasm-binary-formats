/* On-demand disassembly module: the first IDA-class capability this page can honestly offer.
 *
 * Capstone (BSD-3) is the disassembler that a large share of open binary tooling sits on, so the
 * browser gets the same instruction text those tools print rather than a reimplementation from this
 * repository. The module is built only by CI, into its own file, and the page fetches it when a
 * visitor asks; the structural engine never contains any of it.
 *
 * The ABI mirrors the rest of the project: a run call that returns a count, one row per result, and
 * a self test the loader can call before it has any input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <capstone/capstone.h>

#define ROW_MAX 320
#define ROW_MAX_SEEN 512

static char rows[ROW_MAX_SEEN][ROW_MAX];
static int listed;

/* 0 = x86-64, 1 = AArch64, 2 = ARM Thumb. Those are the three the container readers here can already
 * locate a .text section for, which is the pair this module is meant to complete. */
static int pick(int arch, csh *out) {
  cs_mode mode = CS_MODE_LITTLE_ENDIAN;
  cs_arch which = CS_ARCH_X86;
  switch (arch) {
    case 1: which = CS_ARCH_ARM64; break;
    case 2: which = CS_ARCH_ARM; mode = CS_MODE_THUMB; break;
    case 0: which = CS_ARCH_X86; mode = CS_MODE_64; break;
    default: return -1;
  }
  if (cs_open(which, mode, out) != CS_ERR_OK) {
    return -1;
  }
  cs_option(*out, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
  return 0;
}

/* Disassemble `len` bytes at `pc`. Returns the instruction count, -1 for an unknown architecture and
 * -2 when Capstone itself refused. Bytes before `code` are never read. */
int disasm_run(const uint8_t *code, uint32_t len, uint64_t pc, int arch) {
  csh opened;
  cs_insn *insns = NULL;
  size_t count;

  listed = 0;
  if (code == NULL || len == 0) {
    return -1;
  }
  if (pick(arch, &opened) != 0) {
    return -1;
  }
  count = cs_disasm(opened, code, len, pc, 0, &insns);
  if (count == 0) {
    cs_close(&opened);
    return insns == NULL ? -2 : 0;
  }
  for (size_t i = 0; i < count && i < ROW_MAX_SEEN; i++) {
    /* The address goes out in hex, the way every listing tool shows it, because "1000" on its own
     * reads as decimal to anything downstream. */
    snprintf(rows[listed], ROW_MAX, "0x%llx\t%s\t%s",
             (unsigned long long)insns[i].address, insns[i].mnemonic, insns[i].op_str);
    listed++;
  }
  cs_free(insns, count);
  cs_close(&opened);
  return (int)count;
}

int disasm_count(void) { return listed; }

const char *disasm_at(int index) {
  if (index < 0 || index >= listed) {
    return "";
  }
  return rows[index];
}

/* A five-instruction x86-64 prologue whose text is fixed and checkable, so a loader can tell that a
 * real engine answered rather than a stub. */
int self_test(void) {
  static const uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x83,
                                 0xec, 0x10, 0xf4, 0xc3};
  int count = disasm_run(code, sizeof(code), 0x1000, 0);
  if (count < 3 || disasm_at(0) == NULL) {
    return -1;
  }
  if (strstr(disasm_at(0), "push") == NULL || strstr(disasm_at(1), "mov") == NULL) {
    return -2;
  }
  if (strstr(disasm_at(2), "sub") == NULL) {
    return -3;
  }
  return count;
}
