from archinfo import ArchAArch64
from collections import defaultdict
from librw_arm64.container import (DataCell, InstrumentedInstruction, Section,
                             Function)
from librw_arm64.util.logging import *
from librw_arm64.container import INSTR_SIZE
from librw_arm64.util.arm_util import get_reg_size_arm, get_access_size_arm, is_reg_32bits, get_64bits_reg, non_clobbered_registers
import random
import os


skipped_functions = ["call_weak_fn", "__libc_csu_init", "_init", "register_tm_clones"]


class Instrument():

    def __init__(self, rewriter):
        self.rewriter = rewriter

        # Get the register map
        aarch64 = ArchAArch64()
        self.regmap = defaultdict(lambda: defaultdict(dict))
        for reg in aarch64.register_list:
            if reg.general_purpose:
                self.regmap[reg.name] = reg.subregisters[0][0]



    def get_mem_instrumentation(self, instruction, idx, free):
        enter_lbl = "COUNTER_%x" % (instruction.address)

        instrumentation = trampoline_fmt_arm.format(random=random.randint(0, MAP_SIZE))
        comment = "{}: {}".format(str(instruction), str(free))

        return InstrumentedInstruction(instrumentation, enter_lbl, comment)

    def instrument_persistent(self, addr):
        # we need to call __afl_persistent_instrumentation instead of main
        # so we hijack the _start
        start_func = None
        for faddr, fn in self.rewriter.container.functions.items():
            if fn.name == "_start":
                start_func = fn
        for idx, instruction in enumerate(start_func.cache):
            # passing main as first argument 
            if "ldr x0, [x0" in str(instruction):
                instruction.mnemonic = "// " + instruction.mnemonic
                prev_instruction = fn.cache[idx-1] 
                prev_instruction.mnemonic = "// " + prev_instruction.mnemonic
                instrumentation = "adrp x0, __afl_persistent_instrumentation\nadd x0, x0, :lo12:__afl_persistent_instrumentation"
                instruction.instrument_after(InstrumentedInstruction(instrumentation))


    def do_instrument(self):

        for faddr, fn in self.rewriter.container.functions.items():
            if fn.name in skipped_functions: continue
            if fn.name == "main":
                # we call afl_maybe_log the first time just after the main
                # preamble so that the forkserver is started as soon as possible
                # but not before main
                fn.cache[2].instrument_before(self.get_mem_instrumentation(fn.cache[2], idx, free_registers))
            for idx, instruction in enumerate(fn.cache):

                if instruction.mnemonic.startswith("b") and idx+1 < len(fn.cache):
                    next_instruction = fn.cache[idx+1] # we need to instrument the instruction after the branch
                    if "invalid" in str(next_instruction): continue
                    free_registers = fn.analysis['free_registers'][idx+1] if fn.analysis else None
                    iinstr = self.get_mem_instrumentation(next_instruction, idx+1, free_registers)
                    next_instruction.instrument_before(iinstr)

        payload = main_payload_arm.format(FORKSRV_FD=FORKSRV_FD, FORKSRV_FD_1=FORKSRV_FD_1, AFL_STATUS_FLAGS=(FORKSRV_OPT_ENABLED | FS_OPT_MAPSIZE | get_map_size(MAP_SIZE)))
        afl_sec = Section(".afl_sec", 0x200000, 0, None)
        afl_sec.cache.append(DataCell.instrumented(payload, 0))

        persistent_addr = os.getenv("AFL_PERSISTENT_ADDR", default=None)
        if persistent_addr is not None:
            self.instrument_persistent(persistent_addr)
            persistent_payload = persistent_instrumentation.format(persistent_function=persistent_addr, PERSISTENT_SIGNATURE=PERSISTENT_SIGNATURE)
            persistent_cycles = os.getenv("AFL_PERSISTENT_CYCLES", default=1000)
            persistent_payload_loop = persistent_loop.format(PERSISTENT_CYCLES=persistent_cycles, PREV_LOC_MEMSET_SIZE=PREV_LOC_MEMSET_SIZE, SIGSTOP_NUM=SIGSTOP_NUM, MAP_SIZE=MAP_SIZE)
            afl_sec.cache.append(DataCell.instrumented(persistent_payload, 0))
            afl_sec.cache.append(DataCell.instrumented(persistent_payload_loop, 0))

        self.rewriter.container.add_data_section(afl_sec)





def get_map_size(x):
    return (x <= 1 or ((x - 1) << 1))

FORKSRV_FD = 198
FORKSRV_FD_1 = 199
MAP_SIZE = (1 << 16)

# afl/include/types.h
FORKSRV_OPT_ENABLED = 0x80000001
FS_OPT_ENABLED = 0x80000001
FS_OPT_MAPSIZE = 0x40000000
FS_OPT_SNAPSHOT = 0x20000000
FS_OPT_AUTODICT = 0x10000000
FS_OPT_SHDMEM_FUZZ = 0x01000000
FS_OPT_OLD_AFLPP_WORKAROUND = 0x0f000000

PERSISTENT_SIGNATURE = "##SIG_AFL_PERSISTENT##"
PERSISTENT_CYCLES = 1000
NGRAMS_SIZE_MAX = 16
PREV_LOC_MEMSET_SIZE = NGRAMS_SIZE_MAX * 2
SIGSTOP_NUM = 19



### TODO possible optimization:
# as of now the first call to __afl_maybe_log
# starts the forkserver. The first instance in is 
# call_weak_fn, which is maybe too early. 
# We might want to call afl_maybe_log as the first instruction 
# of main instead

inline_fmt_arm = """

stp x0, x1, [sp, #-16]!
stp x2, x3, [sp, #-16]!
stp x4, x5, [sp, #-16]!
stp x7, x9, [sp, #-16]!
mrs x7, nzcv

ldr x0, =__afl_setup_failure
ldr x0, [x0]
cmp x0, #0
bne __afl_return

ldr x0, =__afl_area_ptr
ldr x0, [x0]
cmp x0, #0
bne .call_afl_store_{x}

bl __afl_setup
b .__afl_end_{x}

.call_afl_store_{x}:
mov x9, {random}
bl __afl_store
b .__afl_end_{x}

//msr nzcv, x7
//ldp x7, x9, [sp], #16
//ldp x4, x5, [sp], #16
//ldp x2, x3, [sp], #16
//ldp x0, x1, [sp], #16
.__afl_end_{x}:
"""

trampoline_fmt_arm = """
// afl trampoline
stp x0, lr, [sp, #-16]!
mov x0, {random}
bl __afl_maybe_log
ldp x0, lr, [sp], #16
"""



main_payload_arm = """
myarea:
.quad __afl_area_ptr
myprev_loc:
.quad __afl_prev_loc


.section afl_payload, "ax", @progbits
// afl main payload
.type __afl_maybe_log, @function
.globl __afl_maybe_log
__afl_maybe_log:
stp x1, x2, [sp, #-16]!
stp x3, x9, [sp, #-16]!
stp x5, x6, [sp, #-16]!
stp x7, lr, [sp, #-16]!
mrs x7, nzcv
// mrs x7, CPSR

mov x9, x0
//ldr x0, =__afl_setup_failure

//ldr x0, =__afl_area_ptr
adr x0, myarea
ldr x0, [x0]
ldr x0, [x0]
cmp x0, #0
bne __afl_return



.type __afl_store, @function
.globl __afl_store
__afl_store:
//ldr x0, =__afl_area_ptr
adrp x0, myarea
add x0, x0, :lo12:myarea
ldr x0, [x0]
ldr x0, [x0]
//ldr x1, =__afl_prev_loc
adrp x1, myprev_loc
add x1, x1, :lo12:myprev_loc
ldr x1, [x1]
ldr x2, [x1]
eor x2, x2, x9
ldrb w3, [x0, x2]
add x3, x3, #1
strb w3, [x0, x2]
// mov x0, x9, asr#1 
asr x9, x9, #1
mov x0, x9
str x0, [x1]


.type __afl_return, @function
.globl __afl_return
__afl_return:
// msr APSR_nzcvq, x7
msr nzcv, x7
ldp x7, lr, [sp], #16
ldp x5, x6, [sp], #16
ldp x3, x9, [sp], #16
ldp x1, x2, [sp], #16
ret
// end
"""







persistent_loop = """

.format_string:
    .string \"output: 0x%lx\\n\"

.align 4
.type __afl_persistent_loop, @function
.globl __afl_persistent_loop
__afl_persistent_loop:

stp x1, x2, [sp, #-16]!
stp x3, x9, [sp, #-16]!
stp x5, x6, [sp, #-16]!
stp x7, lr, [sp, #-16]!
mrs x7, nzcv

// if (first_pass)
adr x2, .first_pass
ldr x1, [x2]
cmp x1, 0
b.eq .not_first_pass

    // cycle_count = 1000;
    mov x1, {PERSISTENT_CYCLES}
    adr x3, .cycle_count
    str x1, [x3]

    mov x1, 0
    str x1, [x2]


    // memset(__afl_area_ptr, 0, map_size);
    adr x0, __afl_area_ptr
    ldr x0, [x0]
    mov x1, 0
    adr x2, .map_size
    ldr x2, [x2]
    bl memset


    // __afl_area_ptr[0] = 1;
    ldr x0, =__afl_area_ptr
    ldr x0, [x0]
    mov x1, 1
    str x1, [x0]

    // remove this
    adr x0, .format_string
    ldr x1, =__afl_prev_loc
    ldr x1, [x1]
    bl printf

    // memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));
    //ldr x0, =__afl_prev_loc
    //ldr x0, [x0]
    //mov x1, 0
    //mov x2, {PREV_LOC_MEMSET_SIZE}
    //bl memset

    // remove this
    adr x0, .format_string
    ldr x1, =__afl_area_ptr
    ldr x1, [x1]
    bl printf

    mov x0, 1
    b .return

.not_first_pass:

    // if (--cycle_count)
    adr x3, .cycle_count
    ldr x1, [x3]
    sub x1, x1, 1
    str x1, [x3]
    cmp x1, 0
    b.eq .loop_done

    // remove this
    adr x0, .format_string
    ldr x1, =__afl_prev_loc
    ldr x1, [x1]
    bl printf

    // raise(SIGSTOP);
    mov x0, {SIGSTOP_NUM}
    bl raise

    // __afl_area_ptr[0] = 1;
    ldr x0, =__afl_area_ptr
    ldr x0, [x0]
    mov x1, 1
    str x1, [x0]

    // memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));
    ldr x0, =__afl_prev_loc
    ldr x0, [x0]
    mov x1, 0
    mov x2, {PREV_LOC_MEMSET_SIZE}
    bl memset

    mov x0, 1
    b .return

.loop_done:
    // __afl_area_ptr = __afl_area_ptr_dummy
    ldr x1, =__afl_area_ptr 
    ldr x2, =__afl_area_ptr_dummy
    ldr x2, [x2]
    str x2, [x1]

    mov x0, 0
    b .return

.return:
msr nzcv, x7
ldp x7, lr, [sp], #16
ldp x5, x6, [sp], #16
ldp x3, x9, [sp], #16
ldp x1, x2, [sp], #16
ret

.first_pass:
.quad 1
.cycle_count:
.quad 0
.map_size:
.quad {MAP_SIZE}
"""


persistent_instrumentation = """
.string "{PERSISTENT_SIGNATURE}"
.align 4
.type __afl_persistent_instrumentation, @function
.globl __afl_persistent_instrumentation
__afl_persistent_instrumentation:

stp x1, x2, [sp, #-16]!
stp x3, x4, [sp, #-16]!
stp x5, x6, [sp, #-16]!
stp x7, x8, [sp, #-16]!
stp x9, x10, [sp, #-16]!
stp x11, x12, [sp, #-16]!
stp x13, x14, [sp, #-16]!
stp x15, x16, [sp, #-16]!
stp x17, x18, [sp, #-16]!
stp x19, x20, [sp, #-16]!
stp x21, x12, [sp, #-16]!
stp x23, x24, [sp, #-16]!
stp x25, x26, [sp, #-16]!
stp x27, x28, [sp, #-16]!
stp x29, x30, [sp, #-16]!
mrs x7, nzcv

bl __afl_maybe_log

loop:
    bl __afl_persistent_loop
    cmp x0, 0
    b.eq .end

    msr nzcv, x7
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x12, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x17, x18, [sp], #16
    ldp x15, x16, [sp], #16
    ldp x13, x14, [sp], #16
    ldp x11, x12, [sp], #16
    ldp x9, x10,  [sp], #16
    ldp x7, x8,   [sp], #16
    ldp x5, x6,   [sp], #16
    ldp x3, x4,   [sp], #16
    ldp x1, x2,   [sp], #16

    bl {persistent_function}

    b loop

.end:
    mov x0, 0
    bl exit
"""
