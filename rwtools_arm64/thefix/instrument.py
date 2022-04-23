from archinfo import ArchAArch64
from collections import defaultdict
from librw_arm64.container import (DataCell, InstrumentedInstruction, Section,
                             Function)
from librw_arm64.util.logging import *
from librw_arm64.container import INSTR_SIZE
from librw_arm64.util.arm_util import get_reg_size_arm, get_access_size_arm, is_reg_32bits, get_64bits_reg, non_clobbered_registers


class Instrument():

    def __init__(self, rewriter):
        self.rewriter = rewriter

    def do_instrument(self):
        for faddr, fn in self.rewriter.container.functions.items():
            for idx, instruction in enumerate(fn.cache):
                if "bl"  == instruction.mnemonic:
                    iinstr = f"\tadrp x30, (.fake.elf_header + {hex(instruction.address + 4)})"
                    iinstr += f"\n\tadd x30, x30, {hex((instruction.address+4) & 0xfff)}"
                    # iinstr += "\n\tadd x30, x30, 4"
                    # iinstr = f"\tmovz x30, (.fake.elf_header + {hex(instruction.address + 4)})"
                    instruction.instrument_before(InstrumentedInstruction(iinstr, None, None))
                    instruction.mnemonic = "b"

                if "blr"  in instruction.mnemonic:
                    iinstr = f"\tadrp x30, (.fake.elf_header + {hex(instruction.address + 4)})"
                    iinstr += f"\n\tadd x30, x30, {hex((instruction.address+4) & 0xfff)}"
                    instruction.instrument_before(InstrumentedInstruction(iinstr, None, None))
                    instruction.mnemonic = "br"

