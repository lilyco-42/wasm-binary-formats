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

/* Cross-references: the second IDA-class module, and the one a plain listing cannot give.
 *
 * A target is taken from an immediate only when the instruction is a call or a jump - an immediate in
 * `cmp eax, 0x10` is a constant, not a reference, and listing those would bury the edges that matter -
 * and from a RIP-relative memory operand as well, because that is how x86-64 reaches its data. Each
 * edge says whether the target falls inside the window that was handed in or outside it, which is the
 * difference between a call into the same section and a reference to something elsewhere in the image.
 *
 * The operand structs differ per architecture, so collection is the only part that branches; the rows
 * are written once.
 */
typedef struct {
  uint64_t target;
  const char *kind;
} ref;

static int has_group(const cs_insn *in, unsigned want) {
  if (in->detail == NULL) {
    return 0;
  }
  for (unsigned i = 0; i < in->detail->groups_count; i++) {
    if (in->detail->groups[i] == want) {
      return 1;
    }
  }
  return 0;
}

static int collect(const cs_insn *in, int arch, ref *out, int cap) {
  int found = 0;
  int call;
  int jump;
  const char *kind;

  if (in->detail == NULL) {
    return 0;
  }
  call = has_group(in, CS_GRP_CALL);
  jump = has_group(in, CS_GRP_JUMP);
  kind = call ? "call" : (jump ? "jump" : NULL);

  if (arch == 0) {
    const cs_x86 *x = &in->detail->x86;
    for (unsigned i = 0; i < x->op_count && found < cap; i++) {
      const cs_x86_op *op = &x->operands[i];
      if (op->type == X86_OP_IMM && kind != NULL) {
        out[found].target = (uint64_t)(int64_t)op->imm;
        out[found].kind = kind;
        found++;
      } else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
        /* RIP-relative: the base is the address *after* this instruction. */
        out[found].target = (uint64_t)((int64_t)(in->address + in->size) + op->mem.disp);
        out[found].kind = "mem";
        found++;
      }
    }
    return found;
  }

  if (arch == 1) {
    const cs_arm64 *a = &in->detail->arm64;
    for (unsigned i = 0; i < a->op_count && found < cap; i++) {
      const cs_arm64_op *op = &a->operands[i];
      if (op->type == ARM64_OP_IMM && kind != NULL) {
        out[found].target = (uint64_t)(int64_t)op->imm;
        out[found].kind = kind;
        found++;
      }
    }
    return found;
  }

  const cs_arm *a = &in->detail->arm;
  for (unsigned i = 0; i < a->op_count && found < cap; i++) {
    const cs_arm_op *op = &a->operands[i];
    if (op->type == ARM_OP_IMM && kind != NULL) {
      out[found].target = (uint64_t)(int64_t)op->imm;
      out[found].kind = kind;
      found++;
    }
  }
  return found;
}

static int open_detail(int arch, csh *out) {
  if (pick(arch, out) != 0) {
    return -1;
  }
  cs_option(*out, CS_OPT_DETAIL, CS_OPT_ON);
  return 0;
}

/* Returns the number of edges found, -1 for an unknown architecture and -2 when Capstone refused.
 * The rows it leaves behind are the edges plus one summary line, read with disasm_count/disasm_at. */
int disasm_xrefs(const uint8_t *code, uint32_t len, uint64_t pc, int arch) {
  csh handle;
  cs_insn *insns = NULL;
  size_t count;
  int edges = 0;
  int inside = 0;
  int outside = 0;
  int cut = 0;

  listed = 0;
  if (code == NULL || len == 0) {
    return -1;
  }
  if (open_detail(arch, &handle) != 0) {
    return -1;
  }
  count = cs_disasm(handle, code, len, pc, 0, &insns);
  if (count == 0) {
    cs_close(&handle);
    return insns == NULL ? -2 : 0;
  }

  for (size_t i = 0; i < count; i++) {
    ref found[8];
    int refs = collect(&insns[i], arch, found, 8);
    for (int j = 0; j < refs; j++) {
      int in_window = found[j].target >= pc && found[j].target < pc + (uint64_t)len;
      if (in_window) {
        inside++;
      } else {
        outside++;
      }
      edges++;
      if (listed < ROW_MAX_SEEN - 1) {
        snprintf(rows[listed], ROW_MAX, "xref\tfrom\t0x%llx\tkind\t%s\tto\t0x%llx\twhere\t%s",
                 (unsigned long long)insns[i].address, found[j].kind,
                 (unsigned long long)found[j].target, in_window ? "inside" : "outside");
        listed++;
      } else {
        cut = 1;
      }
    }
  }
  if (cut) {
    snprintf(rows[listed], ROW_MAX, "cut\txrefs\t%d", edges);
    listed++;
  }
  snprintf(rows[listed], ROW_MAX, "xrefs\ttotal\t%d\tinside\t%d\toutside\t%d\tscanned\t%zu",
           edges, inside, outside, count);
  listed++;

  cs_free(insns, count);
  cs_close(&handle);
  return edges;
}

/* Basic blocks and function boundaries - the third pass, and the reason the two above keep detail
 * enabled. A block is a maximal straight-line run that ends in a call, a jump or a return, or that
 * stops just before an address some control transfer in this window points at; a function starts at the
 * entry address and at every address a *call* in the window points at, and runs to the next such start.
 * Both rules are printed as rows rather than left as a graph the caller cannot see.
 *
 * One limit deserves naming: a call's displacement is resolved by Capstone to the target the raw bytes
 * state, so inside an object file - where a linker has not yet filled it in - the "function" starts on
 * the instruction after the call. `objdump -d` splits at symbol names instead, which an object keeps in
 * its symbol table and a window of bytes does not have. */
#define MAX_TARGETS 1024
#define MAX_BLOCKS 512
#define MAX_FUNCS 256

static uint64_t targets[MAX_TARGETS];
static int target_count;
static uint64_t starts[MAX_TARGETS];
static int start_count;
static int leaders_cut;
static uint64_t block_from[MAX_BLOCKS];
static uint64_t block_to[MAX_BLOCKS];
static int block_insns[MAX_BLOCKS];
static const char *block_term[MAX_BLOCKS];
static int block_count;
static int blocks_cut;

static int known(uint64_t *list, int n, uint64_t want) {
  for (int i = 0; i < n; i++) {
    if (list[i] == want) {
      return 1;
    }
  }
  return 0;
}

static void remember(uint64_t *list, int *n, int cap, uint64_t want, int *cut) {
  if (known(list, *n, want)) {
    return;
  }
  if (*n < cap) {
    list[(*n)++] = want;
    return;
  }
  *cut = 1;
}

static int cmp_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a;
  uint64_t y = *(const uint64_t *)b;
  return x < y ? -1 : (x > y ? 1 : 0);
}

/* "call", "jump" or "ret" for an instruction that ends a block, NULL otherwise. Only Capstone's groups
 * are consulted, so the three words carry the same meaning for x86-64, AArch64 and Thumb. */
static const char *terminator(const cs_insn *in) {
  if (has_group(in, CS_GRP_CALL)) {
    return "call";
  }
  if (has_group(in, CS_GRP_RET)) {
    return "ret";
  }
  if (has_group(in, CS_GRP_JUMP)) {
    return "jump";
  }
  return NULL;
}

/* Returns the number of functions found, -1 for an unknown architecture and -2 when Capstone refused
 * to decode anything. The rows it leaves behind are one summary, then `func` rows, then `block` rows. */
int disasm_funcs(const uint8_t *code, uint32_t len, uint64_t pc, int arch) {
  csh handle;
  cs_insn *insns = NULL;
  size_t count;
  uint64_t stop;
  int funcs = 0;
  int cut = 0;
  uint64_t run_from = pc;

  listed = 0;
  target_count = 0;
  start_count = 0;
  leaders_cut = 0;
  block_count = 0;
  blocks_cut = 0;
  if (code == NULL || len == 0) {
    return -1;
  }
  if (open_detail(arch, &handle) != 0) {
    return -1;
  }
  count = cs_disasm(handle, code, len, pc, 0, &insns);
  if (count == 0) {
    cs_close(&handle);
    return insns == NULL ? -2 : 0;
  }
  stop = pc + (uint64_t)len;
  remember(targets, &target_count, MAX_TARGETS, pc, &leaders_cut);
  remember(starts, &start_count, MAX_TARGETS, pc, &leaders_cut);

  for (size_t i = 0; i < count; i++) {
    ref found[8];
    int refs = collect(&insns[i], arch, found, 8);
    for (int j = 0; j < refs; j++) {
      if (strcmp(found[j].kind, "mem") == 0) {
        continue;
      }
      if (found[j].target < pc || found[j].target >= stop) {
        continue;
      }
      remember(targets, &target_count, MAX_TARGETS, found[j].target, &leaders_cut);
      if (strcmp(found[j].kind, "call") == 0) {
        remember(starts, &start_count, MAX_TARGETS, found[j].target, &leaders_cut);
      }
    }
  }
  qsort(starts, (size_t)start_count, sizeof(uint64_t), cmp_u64);

  for (size_t i = 0, run = 0; i < count; i++) {
    const cs_insn *in = &insns[i];
    const char *term = terminator(in);
    uint64_t next = in->address + (uint64_t)in->size;
    int closed = term != NULL || i + 1 == count ||
                 (i + 1 < count && known(targets, target_count, insns[i + 1].address));

    if (run == 0) {
      run_from = in->address;
    }
    run++;
    if (!closed) {
      continue;
    }
    if (block_count < MAX_BLOCKS) {
      block_from[block_count] = run_from;
      block_to[block_count] = next;
      block_insns[block_count] = (int)run;
      block_term[block_count] = term == NULL ? "none" : term;
      block_count++;
    } else {
      blocks_cut = 1;
    }
    run = 0;
  }

  for (int k = 0; k < start_count; k++) {
    uint64_t from = starts[k];
    uint64_t to = (k + 1 < start_count) ? starts[k + 1]
                                        : insns[count - 1].address + (uint64_t)insns[count - 1].size;
    int inside = 0;
    int inner = 0;
    int calls = 0;
    int jumps = 0;
    int rets = 0;

    for (size_t i = 0; i < count; i++) {
      const char *term;
      if (insns[i].address < from || insns[i].address >= to) {
        continue;
      }
      inside++;
      term = terminator(&insns[i]);
      if (term == NULL) {
        continue;
      }
      if (strcmp(term, "call") == 0) {
        calls++;
      } else if (strcmp(term, "jump") == 0) {
        jumps++;
      } else {
        rets++;
      }
    }
    for (int b = 0; b < block_count; b++) {
      if (block_from[b] >= from && block_from[b] < to) {
        inner++;
      }
    }
    if (funcs < MAX_FUNCS) {
      snprintf(rows[listed], ROW_MAX,
               "func\t%d\tstart\t0x%llx\tend\t0x%llx\tinsns\t%d\tblocks\t%d\tcalls\t%d\tjumps\t%d\trets\t%d",
               funcs, (unsigned long long)from, (unsigned long long)to, inside, inner, calls, jumps,
               rets);
      listed++;
    } else {
      cut = 1;
    }
    funcs++;
  }

  for (int b = 0; b < block_count; b++) {
    int owner = 0;
    for (int k = 0; k < start_count; k++) {
      if (starts[k] <= block_from[b]) {
        owner = k;
      }
    }
    snprintf(rows[listed], ROW_MAX,
             "block\t%d\tfunc\t%d\tstart\t0x%llx\tend\t0x%llx\tinsns\t%d\tterm\t%s",
             b, owner, (unsigned long long)block_from[b], (unsigned long long)block_to[b],
             block_insns[b], block_term[b]);
    listed++;
  }
  if (cut || blocks_cut || leaders_cut) {
    snprintf(rows[listed], ROW_MAX, "cut\tfuncs\t%d\tblocks\t%d\tleaders\t%d", funcs, block_count,
             target_count);
    listed++;
  }
  snprintf(rows[listed], ROW_MAX,
           "funcs\ttotal\t%d\tblocks\t%d\tleaders\t%d\tinsns\t%zu\tentry\t0x%llx\twindow\t%u",
           funcs, block_count, target_count, count, (unsigned long long)pc, (unsigned)len);
  listed++;

  cs_free(insns, count);
  cs_close(&handle);
  return funcs;
}

/* A five-instruction x86-64 prologue whose text is fixed and checkable, so a loader can tell that a
 * real engine answered rather than a stub. The second half asks the cross-reference pass to find the
 * call in `e8 0a 00 00 00` and to place its target outside the six bytes it was given - the xref path
 * is a different code path, and a build that decodes text but not edges is not a pass. The third half
 * asks for blocks and functions, which is a third code path again: `call` then `ret` is two blocks in
 * one function, and the only function whose start the bytes themselves state. */
int self_test(void) {
  static const uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x83,
                                 0xec, 0x10, 0xf4, 0xc3};
  static const uint8_t call[] = {0xe8, 0x0a, 0x00, 0x00, 0x00, 0xc3};
  int count = disasm_run(code, sizeof(code), 0x1000, 0);
  int edges;
  int funcs;

  if (count < 3 || disasm_at(0) == NULL) {
    return -1;
  }
  if (strstr(disasm_at(0), "push") == NULL || strstr(disasm_at(1), "mov") == NULL) {
    return -2;
  }
  if (strstr(disasm_at(2), "sub") == NULL) {
    return -3;
  }
  edges = disasm_xrefs(call, sizeof(call), 0x2000, 0);
  if (edges < 1 || strstr(rows[0], "call") == NULL) {
    return -4;
  }
  if (strstr(rows[0], "outside") == NULL) {
    return -5;
  }
  funcs = disasm_funcs(call, sizeof(call), 0x2000, 0);
  if (funcs != 1 || strstr(rows[0], "func\t0") == NULL || strstr(rows[0], "start\t0x2000") == NULL) {
    return -6;
  }
  if (strstr(rows[1], "block\t0") == NULL || strstr(rows[1], "term\tcall") == NULL) {
    return -7;
  }
  if (strstr(rows[2], "block\t1") == NULL || strstr(rows[2], "term\tret") == NULL) {
    return -8;
  }
  return count;
}
