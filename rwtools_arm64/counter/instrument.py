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

        # Get the register map
        aarch64 = ArchAArch64()
        self.regmap = defaultdict(lambda: defaultdict(dict))
        for reg in aarch64.register_list:
            if reg.general_purpose:
                self.regmap[reg.name] = reg.subregisters[0][0]

    def count_two(self, instruction, idx, free):
        enter_lbl = "COUNTER2_%x" % (instruction.address)

        instrumentation = """
        stp x7, x8, [sp, -16]! // save x7, x8

        // build a pointer in x8 to .counted
        adrp x8, .counted2
        add x8, x8, :lo12:.counted2

        // add 1 to .counted2
        ldr x7, [x8]
        add x7, x7, 1
        str x7, [x8]

        ldp x7, x8, [sp], 16  // load back x7 and x8
        """
        comment = "{}: ".format(str(instruction))
        return InstrumentedInstruction(instrumentation, enter_lbl, comment)



    def count_one(self, instruction, idx, free):
        enter_lbl = "COUNTER_%x" % (instruction.address)

        instrumentation = """
        stp x7, x8, [sp, -16]! // save x7, x8

        // build a pointer in x8 to .counted
        adrp x8, .counted
        add x8, x8, :lo12:.counted

        // add 1 to .counted
        ldr x7, [x8]
        add x7, x7, 1
        str x7, [x8]

        ldp x7, x8, [sp], 16  // load back x7 and x8
        """
        comment = "{}: ".format(str(instruction))
        return InstrumentedInstruction(instrumentation, enter_lbl, comment)



    def do_instrument(self):
        for faddr, fn in self.rewriter.container.functions.items():
            for idx, instruction in enumerate(fn.cache):

                # if any("adrp" in str(x) for x in instruction.before):
                if "br"  in instruction.mnemonic:
                    iinstr = self.count_one(instruction, idx, None)
                    instruction.instrument_before(iinstr)

                if "blr"  in instruction.mnemonic:
                    iinstr = self.count_two(instruction, idx, None)
                    instruction.instrument_before(iinstr)

        ds = Section(".counter", 0x100000, 0, None, flags="aw")
        content = """
        .file: .string \"/tmp/countfile\"
        .perms: .string \"a\"
        .format: .string \"br: %lld\\nblr: %lld\\n\"
        .align 3
        .counted: .quad 0x0
        .counted2: .quad 0x0
        """
        ds.cache.append(DataCell.instrumented(content, 0))
        self.rewriter.container.add_data_section(ds)



        ds = Section(".finiamola", 0x200000, 0, None, flags="ax")
        ds.align = 0
        instrumentation = """
        // build a pointer to .perms
        adrp x1, .perms
        add x1, x1, :lo12:.perms

        // build a pointer to .file
        adrp x0, .file
        add x0, x0, :lo12:.file

        // call the libc fopen(.file, .perms)
        bl fopen

        // load .counted in x2
        adrp x2, .counted
        ldr x2, [x2, :lo12:.counted]
        // load .counted in x3
        adrp x3, .counted2
        ldr x3, [x3, :lo12:.counted2]

        // build a pointer to .format
        adrp x1, .format
        add x1, x1, :lo12:.format

        // fprintf( fopen("/tmp/countfile", "a+"), "%lld", counted);
        bl fprintf

        bl exit
        """
        ds.cache.append( DataCell.instrumented(instrumentation, 0))
        self.rewriter.container.add_data_section(ds)

        self.rewriter.container.datasections[".fini_array"].cache.append(DataCell.instrumented(".quad .finiamola", 0))
        f = self.rewriter.container.codesections[".fini"].functions[0]
        self.rewriter.container.functions[f].cache[0].instrument_before(InstrumentedInstruction(instrumentation, 0))

