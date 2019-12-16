ASAN_GLOBAL_DS = "__asan_global_ds"
ASAN_VERSION_CHECK = "__asan_version_mismatch_check_v6"
ASAN_INIT_FN = "asan.module_ctor"
ASAN_DEINIT_FN = "asan.module_dtor"

ASAN_LIB_INIT = "__asan_init_v4"

ASAN_MEM_EXIT = ".LC_ASAN_EX"
ASAN_MEM_ENTER = ".LC_ASAN_ENTER"

MODULE_INIT = [
    "    .align    16, 0x90",
    "# BB#0:",
    "    pushq    %rax",
    ".Ltmp11:",
    "    callq    {}@PLT".format(ASAN_LIB_INIT),
    "    popq    %rax",
    "    retq",
]

MODULE_DEINIT = [
    "    .align    16, 0x90",
    "# BB#0:",
    "    pushq    %rax",
    ".Ltmp12:",
    "    popq    %rax",
    "    retq",
]

MEM_LOAD_COMMON = [
    "\tleaq {lexp}, {clob1}",
    "\tmovq $0xffffe00000000000, {tgt}",
    "\tleaq ({tgt}, {clob1}), {tgt}",
    "\tsarq $3, {tgt}",
    "\tmovzbl ({tgt}), {tgt_32}",
    "\ttestb {tgt_8}, {tgt_8}",
    "\tje {0}_{{addr}}".format(ASAN_MEM_EXIT),
]

MEM_LOAD_SZ = [
    "\tshll $8, {tgt_32}",
    "\tmovb {clob1_8}, {tgt_8}",
    "\trorl $8, {tgt_32}",
    "\tandb $7, {clob1_8}",
    "\taddb ${acsz_1}, {clob1_8}",
    "\tcmpb {tgt_8}, {clob1_8}",
    "\tjl {0}_{{addr}}".format(ASAN_MEM_EXIT),
    "\troll $8, {tgt_32}",
    "\tmovb {tgt_8}, {clob1_8}",
]

ASAN_REPORT = [
    "{save_regs}",
    "\tmovq {clob1}, %rdi",
    "\tcallq __asan_report_{acctype}{acsz}_noabort",
    "{restore_regs}",
]

MEM_REG_SAVE = [
    # Save Regs
    "\tpushq {reg}",
]

MEM_REG_REG_SAVE_RESTORE = [
    "\tmov {src}, {dst}",
]

MEM_FLAG_SAVE = [
    "\tpushf",
]

MEM_FLAG_SAVE_OPT = [
    # Save Flags
    "\tlahf",
    "\tseto %al",
    "\tpushq %rax",
]

MEM_FLAG_RESTORE = [
    "\tpopf",
]

MEM_FLAG_RESTORE_OPT = [
    # Restore Flags
    "\tpopq %rax",
    "\tadd $0x7f, %al",
    "\tsahf",
]

MEM_EXIT_LABEL = [
    "{0}_{{addr}}:".format(ASAN_MEM_EXIT),
]

MEM_REG_RESTORE = [
    # Restore Regs
    "\tpopq {reg}",
]

STACK_POISON_BASE = [
    "\tleaq {pbase}, {reg1}",
    "\tshrq $3, {reg1}",
    "\tmovq $0xdffffc0000000000, {reg2}",
]

STACK_POISON_SLOT = "\tmovb $0xff, ({reg1}, {reg2})"
STACK_UNPOISON_SLOT = "\tmovb $0x0, ({reg1}, {reg2})"
STACK_ENTER_LBL = ".LC_ASAN_STACK_ENTER_{addr}"
STACK_EXIT_LBL = ".LC_ASAN_STACK_EXIT_{addr}"

CANARY_CHECK = "%gs:0x28"
LEAF_STACK_ADJUST = "leaq -256(%rsp), %rsp"
LEAF_STACK_UNADJUST = "\tleaq 256(%rsp), %rsp"

LONGJMP_UNPOISON = [
    "\tpushq %r8",
    "\tpushq {reg}",
    "\tleaq 16(%rsp), %rsp",
    "\tmov 0x30(%rdi), %r8",
    "\tror $0x11, %r8",
    "\txor %fs:0x30, %r8",
    ".ASAN_LONGJMP_{addr}:",
    "\tmovq %r8, {reg}",
    "\tshrq $3, {reg}",
    "\tmovb $0, {off}({reg})",
    "\tsubq $8, %r8",
    "\tcmp %r8, %rsp",
    "\tjne .ASAN_LONGJMP_{addr}",
    "\tleaq -16(%rsp), %rsp",
    "\tpopq {reg}",
    "\tpopq %r8",
]
