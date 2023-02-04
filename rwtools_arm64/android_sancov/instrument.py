from archinfo import ArchAArch64
from collections import defaultdict
from librw_arm64.container import (DataCell, InstrumentedInstruction, Section,
                             Function)
from librw_arm64.util.logging import *
from librw_arm64.container import INSTR_SIZE
from librw_arm64.util.arm_util import get_reg_size_arm, get_access_size_arm, is_reg_32bits, get_64bits_reg, non_clobbered_registers
import random
import os

class Instrument():
    def __init__(self, rewriter):
        self.rewriter = rewriter

    def get_mem_instrumentation(self, instruction, idx, free):
        enter_lbl = "COUNTER_%x" % (instruction.address)

        instrumentation = trampoline_fmt_arm.format(x=instruction.address)
        comment = "{}: {}".format(str(instruction), str(free))

        return InstrumentedInstruction(instrumentation, enter_lbl, comment)


    def do_instrument(self):

        for faddr, fn in self.rewriter.container.functions.items():
            for idx, instruction in enumerate(fn.cache):

                if (instruction.mnemonic.startswith("b.") or \
                    instruction.mnemonic.startswith("cb") or \
                    instruction.mnemonic.startswith("cs") or \
                    instruction.mnemonic.startswith("cc") or \
                    instruction.mnemonic.startswith("cin") or \
                    instruction.mnemonic.startswith("cneg") or \
                    instruction.mnemonic.startswith("tb")) and idx+1 < len(fn.cache):
                    next_instruction = fn.cache[idx+1] # we need to instrument the instruction after the branch
                    if "invalid" in str(next_instruction): continue
                    free_registers = fn.analysis['free_registers'][idx+1] if fn.analysis else None
                    iinstr = self.get_mem_instrumentation(next_instruction, idx+1, free_registers)
                    next_instruction.instrument_before(iinstr)

        afl_sec = Section(".afl_sec", 0x200000, 0, None)
        afl_sec.cache.append(DataCell.instrumented(main_payload_arm, 0))

        self.rewriter.container.add_data_section(afl_sec)


trampoline_fmt_arm = """
stp x0, lr, [sp, #-16]!
stp x1, x2, [sp, #-16]!
stp x3, x4, [sp, #-16]!
stp x5, x6, [sp, #-16]!
stp x7, x8, [sp, #-16]!
stp x9, x10, [sp, #-16]!
stp x11, x12, [sp, #-16]!
stp x13, x14, [sp, #-16]!
stp x15, x16, [sp, #-16]!
mrs x7, nzcv
stp x7, x8, [sp, #-16]!


adrp x0, myfile
add x0, x0, :lo12:myfile
ldr x0, [x0]
cmp x0, 0
b.ne 8
bl setup_file

bl write_pc

ldp x7, x8, [sp], #16
msr nzcv, x7
ldp x15, x16, [sp], #16
ldp x13, x14, [sp], #16
ldp x11, x12, [sp], #16
ldp x9, x10, [sp], #16
ldp x7, x8, [sp], #16
ldp x5, x6, [sp], #16
ldp x3, x4, [sp], #16
ldp x1, x2, [sp], #16
ldp x0, lr, [sp], #16
"""



main_payload_arm = """
myname:
.ascii "coverage.log\\0"
myfile:
.quad 0

.section afl_payload, "ax", @progbits

write_pc:
    stp x8, lr, [sp, #-16]!
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!

    // load fd
    adrp x0, myfile
    add x0, x0, :lo12:myfile
    ldr x0, [x0]

    mov x1, sp // buffer
    mov x2, 8  // count
    mov x8, 64 // write
    svc 0x0 // syscall!

    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
    ldp x8, lr, [sp], #16
    ret

setup_file:
    stp x8, lr, [sp, #-16]!
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!

    mov x0, -100 // AT_FDCWD
    adrp x1, myname
    add x1, x1, :lo12:myname
    mov x2, 0101 // O_CREAT
    mov x3, 0777 // rwx
    mov x8, 56 // openat
    svc 0x80 // syscall!

    adrp x1, myfile
    add x1, x1, :lo12:myfile
    str x0, [x1]

    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
    ldp x8, lr, [sp], #16
    ret
"""
