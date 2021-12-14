from collections import defaultdict

from archinfo import ArchAMD64

from librw.kcontainer import InstrumentedInstruction

CALLER_SAVED_REGS = [
    'rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11',
]

CALLEE_SAVED_REGS = [
    'rbx', 'rbp', 'r12', 'r13', 'r14', 'r15',
]

def compute_register_spill(fn):
    free_regs_end = set(CALLEE_SAVED_REGS)

class Instrument():
    def __init__(self, rewriter):
        self.rewriter = rewriter

    def do_instrument(self):
        for fn in self.rewriter.container.iter_functions():
            fn.set_instrumented()

            for iidx, instr in enumerate(fn.cache):
                if instr.address in fn.bbstarts:
                    iinstr = []
                    # free_regs = fn.analysis['free_registers'][iidx]
                    # flags_are_free = 'rflags' in free_regs

                    # regs_to_save = [
                    #     r for r in CALLER_SAVED_REGS
                    #     if r not in free_regs
                    # ]
                    regs_to_save = CALLER_SAVED_REGS

                    # if not flags_are_free:
                    iinstr.append('\tpushfq')

                    for reg in regs_to_save:
                        iinstr.append('\tpushq %{}'.format(reg))

                    # Keep the stack pointer aligned
                    # used_stack_slots = regs_to_save if flags_are_free else regs_to_save + 1

                    # if (used_stack_offset % 2) != 0:
                    #     iinstr.append('\tsubq $8, %rsp')

                    iinstr.append('\tcallq __sanitizer_cov_trace_pc')

                    # if (used_stack_offset % 2) != 0:
                    #     iinstr.append('\taddq $8, %rsp')

                    for reg in regs_to_save[::-1]:
                        iinstr.append('\tpopq %{}'.format(reg))

                    # if not flags_are_free:
                    iinstr.append('\tpopfq')

                    if instr.address.offset == 0:
                        # this needs to go after the stack pointer adjustment
                        instr.instrument_after(InstrumentedInstruction('\n'.join(iinstr)))
                    else:
                        instr.instrument_before(InstrumentedInstruction('\n'.join(iinstr)))
