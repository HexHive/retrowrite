import copy
import math
from collections import defaultdict
import json
import random

from librw_x64.container import (DataCell, InstrumentedInstruction, DataSection, Function)

# this instrumentation obfuscates functions by randomizing the order of instructions



class Instrument():

    def __init__(self, rewriter):
        self.rewriter = rewriter


    def do_instrument(self):
        for faddr, fn in self.rewriter.container.functions.items():
            if len(fn.cache) < 4: continue
            for idx, instruction in enumerate(fn.cache):
                if idx < len(fn.cache) - 2:
                    next_instruction_addr = fn.cache[idx + 1].address
                    enter_lbl = "make_it_cursed_%x" % (instruction.address)

                    instrumentation = f"""
                    leaq -0x2000(%rsp), %rsp
                    call .LCR{next_instruction_addr:x}
                    """.strip()
                    comment = "{}: ".format(str(instruction))
                    instruction.instrument_after(InstrumentedInstruction(instrumentation, enter_lbl, comment))
                if idx > 0:
                    enter_lbl = "fix_stack_%x" % (instruction.address)
                    instrumentation = f"""
                    jmp .LCF{instruction.address:x}
                    .LCR{instruction.address:x}:
                    leaq 0x2008(%rsp), %rsp
                    .LCF{instruction.address:x}:
                    """.strip()
                    comment = "{}: ".format(str(instruction))
                    instruction.instrument_before(InstrumentedInstruction(instrumentation, enter_lbl, comment))

            # the stack should now be fixed
            # now we can randomize everything except the first and last instruction
            instructions = fn.cache[1:-1]
            random.shuffle(instructions)
            fn.cache[1:-1] = instructions





