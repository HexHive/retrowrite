"""
Implements analysis to look for free registers
"""

import copy
from collections import defaultdict

from archinfo import ArchAMD64, Register


class RegisterAnalysis(object):
    KEY = 'free_registers'

    def __init__(self):
        self.regmap = self._init_reg_pool()
        self.reg_pool = frozenset(self.regmap.keys())

        self.free_regs = defaultdict(set)
        self.used_regs = defaultdict(lambda: copy.copy(self.reg_pool))
        self.subregs = dict()

        self._init_subregisters()
        self.closure_list = self._init_closure_list()

        # Caller saved register list, These are registers that cannot be
        # clobbered and therefore are 'used'.
        self.used_regs['ret'] = set([
            "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            "rax", "rdx", "r10", "r11", "r8", "r9", "rcx", "rdi", "rsi"])
        self.used_regs['call'] = set([
            "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax"])

    def _init_reg_pool(self):
        # Possible extension: add xmm registers into the pool
        amd64 = ArchAMD64()
        regmap = dict()
        for reg in amd64.register_list:
            if reg.general_purpose:
                regmap[reg.name] = reg

        # Remove rip, rsp from regpool
        del regmap["rip"]
        del regmap["rsp"]

        # Add a fake register for rflags
        rflags = Register("rflags", 64)
        regmap["rflags"] = rflags

        return regmap

    def _init_closure_list(self):
        closure_list = defaultdict(lambda: ["", "", "", ""])

        for wrn, wr in self.regmap.items():
            subreg_list = list(enumerate(wr.subregisters))
            # 64-bit register rules
            for idx, subreg in subreg_list:
                closure_list[wrn][idx] = subreg[0]

            # 32-bit register rules
            reg32 = closure_list[wrn][0]
            if reg32:
                closure_list[reg32] = copy.copy(closure_list[wrn])
                closure_list[reg32][0] = wrn

            # 16-bit register rules
            reg16 = closure_list[wrn][1]
            if reg16:
                closure_list[reg16] = copy.copy(closure_list[wrn][2:])

            # 8l-bit register rules
            reg8l = closure_list[wrn][2]
            if reg8l:
                closure_list[reg8l] = []

            # 8h-bit register rules
            reg8h = closure_list[wrn][3]
            if reg8h:
                closure_list[reg8h] = []

        # Cleanup
        for k, items in closure_list.items():
            closure_list[k] = frozenset([x for x in items if x])

        return closure_list

    def _init_subregisters(self):
        for rn, reg in self.regmap.items():
            self.subregs[rn] = rn

            if reg.name in ["r8", "r9", "r10", "r11",
                            "r12", "r13", "r14", "r15"]:

                reg.subregisters = [
                    (reg.name + "d", 0, 4),
                    (reg.name + "w", 0, 2),
                    (reg.name + "b", 0, 1)]

            if reg.name == "rbp":
                reg.subregisters = [
                    ("ebp", 0, 4),
                    ("bp", 0, 2),
                    ("bpl", 0, 1)]

            for subr in reg.subregisters:
                self.subregs[subr[0]] = rn

    def compute_reg_set_closure(self, regl):
        regset = set(regl)
        for item in regl:
            clist = self.closure_list[item]
            regset.update(clist)
        return regset

    def full_register_of(self, regname):
        return self.subregs.get(regname, None)

    @staticmethod
    def analyze(container):
        for function in container.iter_functions():
            print(f'Analyzing {function.name}...')
            ra = RegisterAnalysis()
            ra.analyze_function(function)
            function.analysis[RegisterAnalysis.KEY] = ra.free_regs

    def analyze_function(self, function):
        change = True
        iter = 0
        while change and iter < 8192:
            change = False
            for idx, _ in enumerate(function.cache):
                change = change or self.analyze_instruction(function, idx)
            iter += 1
        self.finalize()

    def analyze_instruction(self, function, instruction_idx):
        current_instruction = function.cache[instruction_idx]
        nexts = function.next_of(instruction_idx)

        reguses = self.reg_pool.intersection(
            [self.full_register_of(x) for x in current_instruction.reg_reads()]
        )

        regwrites = self.compute_reg_set_closure(
            current_instruction.reg_writes()
        ).difference(reguses)

        for nexti in nexts:
            reguses = reguses.union(
                self.used_regs[nexti].difference(regwrites))

        reguses = self.compute_reg_set_closure(reguses)

        if reguses != self.used_regs[instruction_idx]:
            self.used_regs[instruction_idx] = reguses
            return True

        return False

    def debug(self, function):
        print("==== DEBUG")
        for instruction_idx, inst in enumerate(function.cache):
            print(inst, "Used:", sorted(self.used_regs[instruction_idx]))

    def finalize(self):
        for idx, ent in self.used_regs.items():
            self.free_regs[idx] = self.reg_pool.difference(ent)
