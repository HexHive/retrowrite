import copy

import rwtools.asan.snippets as sp
from librw.container import DataCell, InstrumentedInstruction, DataSection


class Instrument():

    def __init__(self, rewriter):
        self.rewriter = rewriter

    def instrument_init_array(self):
        section = self.rewriter.container.sections[".init_array"]
        constructor = DataCell.instrumented(sp.ASAN_INIT_FN, 8)
        section.cache.append(constructor)

        if ".fini_array" not in self.rewriter.container.sections:
            finiarr = DataSection(".fini_array", 0, 0, "")
            self.rewriter.container.add_section(finiarr)

        fini = self.rewriter.container.sections[".fini_array"]
        destructor = DataCell.instrumented(sp.ASAN_DEINIT_FN, 8)
        fini.cache.append(destructor)

    def _access1(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)
        rest = copy.copy(sp.MEM_REG_RESTORE)
        save = copy.copy(sp.MEM_REG_SAVE)

        del ac1[2]

        return "\n".join(save + common + ac1 + rest)

    def _access2(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)
        rest = copy.copy(sp.MEM_REG_RESTORE)
        save = copy.copy(sp.MEM_REG_SAVE)

        ac1[2] = "incl %(clob1_32)s"

        return "\n".join(save + common + ac1 + rest)

    def _access4(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)
        rest = copy.copy(sp.MEM_REG_RESTORE)
        save = copy.copy(sp.MEM_REG_SAVE)

        return "\n".join(save + common + ac1 + rest)

    def _access8(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        rest = copy.copy(sp.MEM_REG_RESTORE)
        save = copy.copy(sp.MEM_REG_SAVE)

        common[3] = "cmpb $0, 2147450880(%(tgt)s)"
        common[4] = common[5]
        common[5] = sp.MEM_LOAD_SZ[-1]

        # rest = [rest[0], rest[1]]
        # save = [save[0]]

        return "\n".join(save + common + rest)

    def instrument_mem_accesses(self):
        for _, fn in self.rewriter.container.functions.items():
            inserts = list()
            for idx, instruction in enumerate(fn.cache):
                mem, midx = instruction.get_mem_access_op()
                # This is not a memory access
                if not mem:
                    continue
                acsz = instruction.cs.operands[midx].size
                if acsz == 1:
                    instrument = self._access1()
                elif acsz == 2:
                    instrument = self._access2()
                elif acsz == 4:
                    instrument = self._access4()
                elif acsz == 8:
                    instrument = self._access8()
                else:
                    print("[*] Maybe missed an access: %s" % (instruction))
                    continue

                args = dict()

                # XXX: Bug in capstone?
                if (instruction.mnemonic.startswith("shr")
                        or instruction.mnemonic.startswith("sar"):
                    midx = 1

                if midx == 0:
                    lexp = instruction.op_str.rsplit(",", 1)[0]
                else:
                    lexp = instruction.op_str.split(",", 1)[1]

                args["lexp"] = lexp
                args["acsz"] = acsz
                args["acsz_1"] = acsz - 1
                # TODO: Can we be more intelligent and not hardcode?
                args["clob1"] = "%rdi"
                args["clob1_32"] = "%edi"
                # args["clob2"] = "%rdx"
                args["tgt"] = "%rax"
                args["tgt_8"] = "%al"
                args["tgt_32"] = "%eax"
                args["addr"] = instruction.address

                enter_lbl = "%s_%x" % (sp.ASAN_MEM_ENTER, instruction.address)

                iinstr = InstrumentedInstruction(
                    instrument % (args), enter_lbl, str(instruction))

                # TODO: Replace original instruction for efficiency
                inserts.append((idx, iinstr))

            for idx, code in enumerate(inserts):
                fn.cache.insert(idx + code[0], code[1])

    def instrument_globals(self):
        pass

    def instrument_stack(self):
        pass

    def do_instrument(self):
        self.instrument_init_array()
        self.instrument_globals()
        self.instrument_stack()
        self.instrument_mem_accesses()
