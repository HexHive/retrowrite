ASAN_GLOBAL_DS = "__asan_global_ds"
ASAN_VERSION_CHECK = "__asan_version_mismatch_check_v6"
ASAN_INIT_FN = "asan.module_ctor"
ASAN_DEINIT_FN = "asan.module_dtor"

# TODO: If you're using Debian, this becomes __assan_init
# TODO: Switch these modifiers automatically
# ASAN_LIB_INIT = "__asan_init_v4"
ASAN_LIB_INIT = "__asan_init"

ASAN_MEM_EXIT = ".LC_ASAN_EX"
ASAN_MEM_ENTER = ".LC_ASAN_ENTER"

ASAN_BASE = "	mov {rbase}, 0x1000000000"


MEM_LOAD_1 = """
	lsr	{r1}, {lexp}, 3
	ldrsb	{r2}, [{rbase}, {r1}]
	cbz	{r2}, .LC_ASAN_EX_{addr}
	and	{r1}, {lexp}, 7
	cmp	{r1}, {r2}
	b.lt	.LC_ASAN_EX_{addr}
"""

MEM_LOAD_2 = """
	lsr	{r1}, {lexp}, 3
	ldrsb	{r2}, [{rbase}, {r1}]
	cbz	{r2}, .LC_ASAN_EX_{addr}
	and	{r1}, {lexp}, 7
	add	{r1}, {r1}, 1
	cmp	{r1}, {r2}
	b.lt	.LC_ASAN_EX_{addr}
"""

MEM_LOAD_4 = """
	lsr	{r1}, {lexp}, 3
	ldrsb	{r2}, [{rbase}, {r1}]
	cbz	{r2}, .LC_ASAN_EX_{addr}
	and	{r1}, {lexp}, 7
	add	{r1}, {r1}, 3
	cmp	{r1}, {r2}
	b.lt	.LC_ASAN_EX_{addr}
"""

MEM_LOAD_8 = """
	lsr		{r1}, {lexp}, 3
	ldrsb		{r2_32}, [{rbase}, {r1}]
	cbz		{r2_32}, .LC_ASAN_EX_{addr}
"""

MEM_LOAD_16 = """
	lsr		{r1}, {lexp}, 3
	ldrsh		{r2_32}, [{rbase}, {r1}]
	cbz		{r2_32}, .LC_ASAN_EX_{addr}
"""


MEM_EXIT_LABEL = ".LC_ASAN_EX_{addr}:"


ASAN_REPORT = """
	mov      x0, {lexp}
	bl       __asan_report_{acctype}{acsz}_noabort
"""

LEXP_SHIFT = """
	lsl	{To}, {shift_reg}, {amnt}
	add {Res}, {From}, {To} {sxtw}
"""

LEXP_ADD = "\tadd {To}, {From}, {amnt}"
LEXP_MOVZ = "\tmovz {To}, {amnt}"


# this is for leaf functions, where the 
# system V ABI lets them use 128 bytes of stack without pushes
# we need to work around that by adjusting the stack pointer
LEAF_STACK_ADJUST = "\tsub sp, sp, 256"
LEAF_STACK_UNADJUST = "\tadd sp, sp, 256"

# Even if for a single register, we still need to keep the sp
# aligned to 16 bytes
STACK_REG_SAVE = "\tstr {0}, [sp, -16]!",  #pre-increment 
STACK_REG_LOAD = "\tldr {0}, [sp], 16",    #post-increment

STACK_PAIR_REG_SAVE = "\tstp {0}, {1}, [sp, -16]!",  #pre-increment
STACK_PAIR_REG_LOAD = "\tldp {0}, {1}, [sp], 16",    #post-increment

# STACKFRAME_PAIR_REG_SAVE = """
    # stp {0}, {1}, [x29, 0x500]
    # stp {2}, {3}, [x29, 0x1010]
# """

# STACKFRAME_PAIR_REG_LOAD = """
    # ldp {0}, {1}, [x29, 0x1000]
    # ldp {2}, {3}, [x29, 0x1010]
# """


# MEM_REG_SAVE = [
    # # Save Regs
    # "\tpushq {reg}",
# ]

# MEM_REG_REG_SAVE_RESTORE = [
    # "\tmov {src}, {dst}",
# ]

# MEM_FLAG_SAVE = [
    # "\tpushf",
# ]

# MEM_FLAG_SAVE_OPT = [
    # # Save Flags
    # "\tlahf",
    # "\tseto %al",
    # "\tpushq %rax",
# ]

# MEM_FLAG_RESTORE = [
    # "\tpopf",
# ]

# MEM_FLAG_RESTORE_OPT = [
    # # Restore Flags
    # "\tpopq %rax",
    # "\tadd $0x7f, %al",
    # "\tsahf",
# ]


# MEM_REG_RESTORE = [
    # # Restore Regs
    # "\tpopq {reg}",
# ]

# STACK_POISON_BASE = [
    # "\tleaq {pbase}, {reg}",
    # "\tshrq $3, {reg}",
# ]

# STACK_POISON_SLOT = "\tmovb $0xff, {off}({reg})"
# STACK_UNPOISON_SLOT = "\tmovb $0x0, {off}({reg})"
# STACK_ENTER_LBL = ".ASAN_STACK_ENTER_{addr}"
# STACK_EXIT_LBL = ".ASAN_STACK_EXIT_{addr}"

# CANARY_CHECK = "%fs:0x28"
# LEAF_STACK_ADJUST = "leaq -256(%rsp), %rsp"
# LEAF_STACK_UNADJUST = "\tleaq 256(%rsp), %rsp"

# LONGJMP_UNPOISON = [
    # "\tpushq %r8",
    # "\tpushq {reg}",
    # "\tleaq 16(%rsp), %rsp",
    # "\tmov 0x30(%rdi), %r8",
    # "\tror $0x11, %r8",
    # "\txor %fs:0x30, %r8",
    # ".ASAN_LONGJMP_{addr}:",
    # "\tmovq %r8, {reg}",
    # "\tshrq $3, {reg}",
    # "\tmovb $0, {off}({reg})",
    # "\tsubq $8, %r8",
    # "\tcmp %r8, %rsp",
    # "\tjne .ASAN_LONGJMP_{addr}",
    # "\tleaq -16(%rsp), %rsp",
    # "\tpopq {reg}",
    # "\tpopq %r8",
# ]

# MODULE_INIT = [
    # "    .align    16, 0x90",
    # "# BB#0:",
    # "    pushq    %rax",
    # ".Ltmp11:",
    # "    callq    {}@PLT".format(ASAN_LIB_INIT),
    # "    popq    %rax",
    # "    retq",
# ]

# MODULE_DEINIT = [
    # "    .align    16, 0x90",
    # "# BB#0:",
    # "    pushq    %rax",
    # ".Ltmp12:",
    # "    popq    %rax",
    # "    retq",
# ]
