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



### WARNING:
# the following snippets were copy-pasted from gcc -fsanitize=address, _without_ optimization,
# so there is probably a faster/shorter alternative!

MEM_LOAD_1 = """                                                      
    mov	    {clob1}, {lexp}
    lsr	    {clob2}, {clob1}, 3
    mov	    {tgt}, 68719476736
    add	    {tgt}, {clob2}, {tgt}
    ldrsb   {tgt_32}, [{tgt}]
    cmp	    {tgt_32}, 0
    cset    {clob2_32}, ne
    and	    {clob2_32}, {clob2_32}, 255
    and	    {clob3}, {clob1}, 7
    sxtb    {clob3_32}, {clob3_32}
    cmp	    {clob3_32}, {tgt_32}
    cset    {tgt_32}, ge
    and	    {tgt_32}, {tgt_32}, 255
    and	    {tgt_32}, {clob2_32}, {tgt_32}
    and	    {tgt_32}, {tgt_32}, 255
    cmp	    {tgt_32}, 0
    beq	    .LC_ASAN_EX_{addr}
"""                                                             
                                        
                                                                                 
MEM_LOAD_2 = """                                                      
    mov	    {clob1}, {lexp}
    lsr	    {clob2}, {clob1}, 3
    mov	    {tgt}, 68719476736
    add	    {tgt}, {clob2}, {tgt}
    ldrsb   {tgt_32}, [{tgt}]
    cmp	    {tgt_32}, 0
    cset    {clob2_32}, ne
    and	    {clob2_32}, {clob2_32}, 255
    and	    {clob3}, {clob1}, 7
    sxtb    {clob3_32}, {clob3_32}
    add     {clob3_32}, {clob3_32}, 1
    sxtb    {clob3_32}, {clob3_32}
    cmp	    {clob3_32}, {tgt_32}
    cset    {tgt_32}, ge
    and	    {tgt_32}, {tgt_32}, 255
    and	    {tgt_32}, {clob2_32}, {tgt_32}
    and	    {tgt_32}, {tgt_32}, 255
    cmp	    {tgt_32}, 0
    beq	    .LC_ASAN_EX_{addr}
"""                                                             

MEM_LOAD_4 = """                                                      
    mov	    {clob1}, {lexp}
    lsr	    {clob2}, {clob1}, 3
    mov	    {tgt}, 68719476736
    add	    {tgt}, {clob2}, {tgt}
    ldrsb   {tgt_32}, [{tgt}]
    cmp	    {tgt_32}, 0
    cset    {clob2_32}, ne
    and	    {clob2_32}, {clob2_32}, 255
    and	    {clob3}, {clob1}, 7
    sxtb    {clob3_32}, {clob3_32}
    add     {clob3_32}, {clob3_32}, 3
    sxtb    {clob3_32}, {clob3_32}
    cmp	    {clob3_32}, {tgt_32}
    cset    {tgt_32}, ge
    and	    {tgt_32}, {tgt_32}, 255
    and	    {tgt_32}, {clob2_32}, {tgt_32}
    and	    {tgt_32}, {tgt_32}, 255
    cmp	    {tgt_32}, 0
    beq	    .LC_ASAN_EX_{addr}
"""                                                             
	
MEM_LOAD_8 = """
    mov     {clob1}, {lexp}
    lsr     {clob2}, {clob1}, 3
    mov     {tgt}, 68719476736
    add     {tgt}, {clob2}, {tgt}
    ldrsb   {tgt_32}, [{tgt}]
    cmp	    {tgt_32}, 0
    beq	    .LC_ASAN_EX_{addr}
"""

MEM_LOAD_16 = """
    mov	    {clob1}, {lexp}
    lsr	    {clob2}, {clob1}, 3
    mov	    {tgt}, 68719476736
    add	    {tgt}, {clob2}, {tgt}
    ldrsh   {tgt_32}, [{tgt}]
    cmp	    {tgt_32}, 0
    beq	    .LC_ASAN_EX_{addr}
"""

	
	

ASAN_REPORT = """
    mov      x0, {clob1}
    bl       __asan_report_{acctype}{acsz}_noabort
"""

LEXP_SHIFT = """
    lsl	{To}, {shift_reg}, {amnt}
    add {To}, {To}, {From}
"""

LEXP_ADD = "\tadd {To}, {From}, {amnt}"




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

MEM_EXIT_LABEL = ".LC_ASAN_EX_{addr}:"

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
