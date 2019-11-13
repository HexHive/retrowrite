from collections import defaultdict

from archinfo import ArchAMD64

from librw.container import InstrumentedInstruction

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

        # Get the register map
        amd64 = ArchAMD64()
        self.regmap = defaultdict(lambda: defaultdict(dict))
        for reg in amd64.register_list:
            if reg.general_purpose:
                for subr in reg.subregisters:
                    base = subr[1]
                    sz = subr[2] * 8
                    self.regmap[reg.name][base][sz] = subr[0]
                if reg.name in [
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
                    self.regmap[reg.name][0][32] = reg.name + "d"
                    self.regmap[reg.name][0][16] = reg.name + "w"
                    self.regmap[reg.name][0][8] = reg.name + "b"
                if reg.name == "rbp":
                    self.regmap[reg.name][0][32] = "ebp"
                    self.regmap[reg.name][0][16] = "bp"
                    self.regmap[reg.name][0][8] = "bpl"

    def do_instrument(self):
        for fn in self.rewriter.container.iter_functions():
            fn.set_instrumented()

            # print(fn.analysis)

            for instr in fn.cache:
                if instr.address in fn.bbstarts:
                    iinstr = []

                    # regs_to_save = [
                    #     r for r in CALLER_SAVED_REGS
                    #     if
                    #         'free_registers' not in fn.analysis or
                    #         instr.address not in fn.analysis['free_registers'] or
                    #         r not in fn.analysis['free_registers'][instr.address]
                    # ]
                    # Todo: make this more precise
                    regs_to_save = CALLER_SAVED_REGS

                    iinstr.append('pushfq')

                    for reg in regs_to_save:
                        iinstr.append('\tpushq %{}'.format(reg))

                    iinstr.append('\tcallq __sanitizer_cov_trace_pc')

                    for reg in regs_to_save[::-1]:
                        iinstr.append('\tpopq %{}'.format(reg))

                    iinstr.append('popfq')

                    if instr.address.offset == 0:
                        # this needs to go after the stack pointer adjustment
                        instr.instrument_after(InstrumentedInstruction('\n'.join(iinstr)))
                    else:
                        instr.instrument_before(InstrumentedInstruction('\n'.join(iinstr)))
