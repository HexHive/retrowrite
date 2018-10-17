"""
Implements analysis to look for free registers
"""

import copy
from collections import defaultdict

from archinfo import ArchAMD64


class RegisterAnalysis(object):

    def __init__(self):
        self.regmap = self._init_reg_pool()
        self.reg_pool = frozenset(self.regmap.keys())

        self.free_regs = defaultdict(set)
        self.used_regs = defaultdict(lambda: copy.copy(self.reg_pool))
        self.subregs = dict()

        self._init_subregisters()

        # Caller saved register list, These are registers that cannot be
        # clobbered and therefore are 'used'.
        self.used_regs['ret'] = set([
            "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            "rax", "rdx"])
        self.used_regs['call'] = set([
            "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            "rdi", "rsi", "rdx", "rcx", "r8", "r9"])

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

        return regmap

    def _init_subregisters(self):
        for rn, reg in self.regmap.items():
            self.subregs[rn] = rn
            for subr in reg.subregisters:
                self.subregs[subr[0]] = rn

    def full_register_of(self, regname):
        return self.subregs.get(regname, None)

    # TODO: Assert that the function is already symbolized.
    def analyze_function(self, function):
        change = True
        while change:
            change = False
            for idx, _ in enumerate(function.cache):
                change = change or self.analyze_instruction(function, idx)
        self.finalize()

    # Possible opt: intersect only in the end
    def analyze_instruction(self, function, instruction_idx):
        current_instruction = function.cache[instruction_idx]
        nexts = function.next_of(instruction_idx)

        reguses = self.reg_pool.intersection(
            [self.full_register_of(x) for x in current_instruction.reg_reads()]
        )

        regwrites = self.reg_pool.intersection(
            [self.full_register_of(x) for x in current_instruction.reg_writes()]
        ).difference(reguses)

        for nexti in nexts:
            useds = [
                self.full_register_of(x) for x in self.used_regs[nexti]
            ]
            reguses = reguses.union(
                self.reg_pool.intersection(useds).difference(regwrites))

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
