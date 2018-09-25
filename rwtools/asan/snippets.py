ASAN_GLOBAL_DS = "__asan_global_ds"
ASAN_VERSION_CHECK = "__asan_version_mismatch_check_v6"
ASAN_INIT_FN = "asan.module_ctor"
ASAN_DEINIT_FN = "asan.module_dtor"

ASAN_MEM_EXIT = ".LC_ASAN_EX"
ASAN_MEM_ENTER = ".LC_ASAN_ENTER"

MODULE_INIT = [
    "    .align    16, 0x90",
    "# BB#0:",
    "    pushq    %rax",
    ".Ltmp11:",
    "    callq    __asan_init@PLT",
    "    callq    %s@PLT" % (ASAN_VERSION_CHECK),
    "    leaq    {0}(%rip), %rdi".format(ASAN_GLOBAL_DS),
    "    movl    $3, %eax",
    "    movl    %eax, %esi",
    "    callq    __asan_register_globals@PLT",
    "    popq    %rax",
    "    retq",
]

MODULE_DEINIT = [
    "    .align    16, 0x90",
    "# BB#0:",
    "    pushq    %rax",
    ".Ltmp12:",
    "    leaq    {0}(%rip), %rdi".format(ASAN_GLOBAL_DS),
    "    movl    $3, %eax",
    "    movl    %eax, %esi",
    "    callq    __asan_unregister_globals@PLT",
    "    popq    %rax",
    "    retq",
]

MEM_LOAD_COMMON = [
    "\tleaq %(lexp)s, %(clob1)s",
    "\tmovq %(clob1)s, %(tgt)s",
    "\tshrq $3, %(tgt)s",
    "\tmovb 2147450880(%(tgt)s), %(tgt_8)s",
    "\ttestb %(tgt_8)s, %(tgt_8)s",
    "\tje {0}_%(addr)x".format(ASAN_MEM_EXIT),
]

MEM_LOAD_SZ = [
    #"movl %(clob1)s, %(clob2)s",
    "\tandl $7, %(clob1_32)s",
    "\taddl $%(acsz_1)d, %(clob1_32)s",
    "\tmovsbl %(tgt_8)s, %(tgt_32)s",
    "\tcmpl %(tgt_32)s, %(clob1_32)s",
    "\tjl {0}_%(addr)x".format(ASAN_MEM_EXIT),
    "\tcallq __asan_report_load%(acsz)d@PLT",
]

MEM_REG_SAVE = [
    "\tpushq %(clob1)s",
    "\tpushq %(tgt)s",
]

MEM_REG_RESTORE = [
    "{0}_%(addr)x:".format(ASAN_MEM_EXIT),
    "\tpopq %(tgt)s",
    "\tpopq %(clob1)s",
]

STACK_POISON_BASE = [
    "\tpushq {clob1}",
    "\tleaq {pbase}, {clob1}",
    "\tshrq $3, {clob1}",
]

STACK_POISON_SLOT = "\tmovl $0xffffffff, {off}({clob1})"
STACK_UNPOISON_SLOT = "\tmovl $0x0, {off}({clob1})"

CANARY_CHECK = "%fs:0x28"
