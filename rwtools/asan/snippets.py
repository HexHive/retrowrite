
ASAN_GLOBAL_DS = "__asan_global_ds"
ASAN_VERSION_CHECK = "__asan_version_mismatch_check_v6"
ASAN_INIT_FN = "asan.module_ctor"
ASAN_DEINIT_FN = "asan.module_dtor"

ASAN_MEM_EXIT = ".LC_ASAN_EX"
ASAN_MEM_ENTER = ".LC_ASAN_ENTER"

MODULE_INIT = [
    "    .align    16, 0x90",
    "    .type    %s,@function" % (ASAN_INIT_FN),
    "%s:" % (ASAN_INIT_FN),
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
    ".Lfunc_end3:",
    "    .size    %s, .Lfunc_end3-%s" % (ASAN_INIT_FN, ASAN_INIT_FN),
]

MODULE_DEINIT = [
    "    .align    16, 0x90",
    "    .type    %s,@function" % (ASAN_DEINIT_FN),
    "%s:" % (ASAN_DEINIT_FN),
    "# BB#0:",
    "    pushq    %rax",
    ".Ltmp12:",
    "    leaq    {0}(%rip), %rdi".format(ASAN_GLOBAL_DS),
    "    movl    $3, %eax",
    "    movl    %eax, %esi",
    "    callq    __asan_unregister_globals@PLT",
    "    popq    %rax",
    "    retq",
    ".Lfunc_end4:",
    "    .size    %s, .Lfunc_end4-%s" % (ASAN_DEINIT_FN, ASAN_DEINIT_FN),
]

MEM_LOAD_COMMON = [
    "leaq %(lexp)s, %(clob1)s",
    "movq %(clob1)s, %(tgt)s",
    "shrq $3, %(tgt)s",
    "movb 2147450880(%(tgt)s), %(tgt_8)s",
    "testb %(tgt_8)s, %(tgt_8)s",
    "je {0}_%(addr)x".format(ASAN_MEM_EXIT),
]

MEM_LOAD_SZ = [
    #"movl %(clob1)s, %(clob2)s",
    "andl $7, %(clob1_32)s",
    "addl $%(acsz_1)d, %(clob1_32)s",
    "movsbl %(tgt_8)s, %(tgt_32)s",
    "cmpl %(tgt_32)s, %(clob1_32)s",
    "jl {0}_%(addr)x".format(ASAN_MEM_EXIT),
    "callq __asan_report_load%(acsz)d@PLT",
]

MEM_REG_SAVE = [
    "pushq %(clob1)s",
    "pushq %(tgt)s",
]

MEM_REG_RESTORE = [
    "{0}_%(addr)x:".format(ASAN_MEM_EXIT),
    "popq %(tgt)s",
    "popq %(clob1)s",
]
