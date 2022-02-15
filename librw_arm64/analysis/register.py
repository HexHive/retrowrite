"""
Implements analysis to look for free registers
"""

import copy
import json
from collections import defaultdict

from archinfo import ArchAArch64, Register
from librw_arm64.util.logging import *
from librw_arm64.analysis.stackframe import StackFrameAnalysis


leaf_functions = {}
cached_reg_usage = {}

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


        # XXX: ARM
        # Caller saved register list, These are registers that cannot be
        # clobbered and therefore are 'used'.
        # self.used_regs['ret'] = set([
            # "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            # "rax", "rdx", "r10", "r11", "r8", "r9", "rcx", "rdi", "rsi"])
        # self.used_regs['call'] = set([
            # "rbx", "rsp", "rbp", "r12", "r13", "r14", "r15",
            # "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax"])

    def _init_reg_pool(self):
        # Possible extension: add xmm registers into the pool
        amd64 = ArchAArch64()
        regmap = dict()
        for reg in amd64.register_list:
            if reg.general_purpose:
                regmap[reg.name] = reg

        # Remove xsp, x30 (link register)
        del regmap["xsp"]
        del regmap["x30"]

        # Clobbered registers (reserved by caller, cannot overwrite)
        # PyRCODIO:
        # https://developer.arm.com/documentation/ihi0055/d
        # The callee saved registers being only x19...x30 IS A LIE
        # You actually cannot touch x18 too
        # I'm not sure about x16 and x17, removing them to be safe
        for i in range(16, 30):
            del regmap["x" + str(i)]

        # Add a fake register for rflags
        # XXX: why?
        # rflags = Register("rflags", 64)
        # regmap["rflags"] = rflags

        return regmap

    def _init_closure_list(self):
        closure_list = defaultdict(lambda: [""])

        # copied from x86, in reality not really needed
        for wrn, wr in self.regmap.items():
            subreg_list = list(enumerate(wr.subregisters))
            for idx, subreg in subreg_list:
                closure_list[wrn][idx] = subreg[0]

            reg32 = closure_list[wrn][0]
            if reg32:
                closure_list[reg32] = []

        # Cleanup
        for k, items in closure_list.items():
            closure_list[k] = frozenset([x for x in items if x])

        return closure_list

    def _init_subregisters(self):
        for rn, reg in self.regmap.items():
            self.subregs[rn] = rn

            # XXX: Not needed by ARM? (archinfo correctly gives subregisters
            # x0, x1, ..., x30
            # if reg.name in ["x" + str(i) for i in range(0, 31)]: 
                # reg.subregisters = [
                    # (reg.name + "d", 0, 4),
                    # (reg.name + "w", 0, 2),
                    # (reg.name + "b", 0, 1)]

            # if reg.name == "rbp":
                # reg.subregisters = [
                    # ("ebp", 0, 4),
                    # ("bp", 0, 2),
                    # ("bpl", 0, 1)]

            for subr in reg.subregisters:
                self.subregs[subr[0]] = rn

    def full_register_of(self, regname):
        return self.subregs.get(regname, None)



    @staticmethod
    def analyze(container):
        global leaf_functions # XXX ugly global, fix it
        class DecimalEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, set):
                    return list(o)
                else:
                    return super(DecimalEncoder, self).default(o)
        info("Starting free registers analysis...")

        for addr, function in container.functions.items():
            if function.analysis.get(StackFrameAnalysis.KEY_IS_LEAF, False):
                leaf_functions[addr] = True

        for addr, function in container.functions.items():
            ra = RegisterAnalysis()
            # ".part." -> gcc breaks ABI by not saving caller registers
            # "et_.*", "invlist_iternext" -> I don't remember, honestly
            # "df_reg.*" -> gcc breaks ABI by not saving caller registers
            # "vectorizable_type_promotion" -> this function contained a trampoline
            if not ".part." in function.name and not "invlist_iternext" in function.name and \
                    not "et_" in function.name and\
                    not "df_reg" in function.name and \
                    not "vectorizable_type_promotion" in function.name: 
                debug("Analyzing function " + function.name)
                ra.analyze_function(container, function)
            function.analysis[RegisterAnalysis.KEY] = ra.free_regs

    def analyze_function(self, container, function):
        global cached_reg_usage
        changed = True
        cached_reg_usage = {}

        i = 0
        while changed:
            changed = False
            i += 1
            if i % 10 == 0: debug(i)
            queue = []
            for idx, nexts in function.nexts.items():
                no_of_nexts = sum(isinstance(x, int) for x in nexts) 
                if no_of_nexts == 0:
                    queue += [idx]

            # breadth first search on the cfg
            visited = [False]*function.sz
            while len(queue):
                idx = queue.pop(0)


                visited[idx] = True
                changed = self.analyze_instruction(container, function, idx) or changed

                nexts = list(filter(lambda x: isinstance(x, int), function.nexts[idx]))
                # for n in nexts:
                    # print("first next:", function.cache[n], visited[n])
                # if not all([visited[x] for x in nexts]):
                    # print(function.name, idx)
                    # queue += [idx]
                    # continue

                prev_instrs = list(filter(lambda x: isinstance(x, int), function.prevs[idx]))
                for idxs in prev_instrs:
                    if not visited[idxs]:
                        queue += [idxs]

            self.finalize()


        # old algorithm, ignore

        # change = True
        # iter = 0
        # while change and iter < 8192:
            # change = False
            # for idx in range(len(function.cache)-1, -1, -1): 
                # if self.analyze_instruction(function, idx):
                    # change = True
            # iter += 1

    def get_reg_usage(self, container, function, instruction_idx):
        if instruction_idx in cached_reg_usage:
            return cached_reg_usage[instruction_idx]

        current_instruction = function.cache[instruction_idx]
        reguses = set([x.replace("w","x") for x in current_instruction.reg_reads_common()])
        regwrites = set([x.replace("w","x") for x in current_instruction.reg_writes_common()])

        cached_reg_usage[instruction_idx] = (reguses, regwrites)
        return reguses, regwrites


    def analyze_instruction(self, container, function, instruction_idx):
        current_instruction = function.cache[instruction_idx]
        nexts = function.nexts[instruction_idx]

        reguses, regwrites = self.get_reg_usage(container, function, instruction_idx)


        # if there is a call to a leaf function, do not
        # assume you can use registers, as sometime they do not respect the ABI
        if current_instruction.mnemonic == "bl":
            target = current_instruction.cs.operands[-1].imm
            if target in leaf_functions:
                regwrites = set()
        # if it's not a call but a jump that leaves the function,
        # we assume it's a trampoline and go to the next instruction.
        # elif current_instruction.cf_leaves_fn: 
            # nexts += [instruction_idx + 1]




        regwrites = regwrites.difference(reguses)

        # I present to you, the following:
        # a whole big bunch of capstone bugs :)
        if current_instruction.mnemonic.startswith("cmp") \
        or current_instruction.mnemonic.startswith("tst") \
        or current_instruction.mnemonic.startswith("cmn"):
            reguses = reguses.union(regwrites)

        for nexti in nexts:
            if nexti not in self.used_regs: continue
            # print("next   ", function.cache[nexti].cs, self.used_regs[nexti])
            reguses = reguses.union(
                self.used_regs[nexti].difference(regwrites))

        # print(current_instruction.cs, reguses, regwrites)

        # if all([nexti in self.used_regs for nexti in nexts]):
            # for nexti in nexts:
                # reguses = reguses.union(
                    # self.used_regs[nexti].difference(regwrites))


        if self.used_regs[instruction_idx] != reguses:
            self.used_regs[instruction_idx] = reguses
            return True
        return False


    # def analyze_function(self, function):
        # change = False
        # change = True
        # iter = 0
        # while change and iter < 8192:
            # change = False
            # for idx, _ in enumerate(function.cache):
                # change = change or self.analyze_instruction(function, idx)
            # iter += 1
        # self.finalize()

    # def analyze_instruction(self, function, instruction_idx):
        # current_instruction = function.cache[instruction_idx]
        # nexts = function.next_of(instruction_idx)

        # reguses = self.reg_pool.intersection(
            # [self.full_register_of(x) for x in current_instruction.reg_reads_common()]
        # )

        # regwrites = self.reg_pool.intersection(current_instruction.reg_writes_common()).difference(reguses)

        # if current_instruction.mnemonic.startswith("cmp") \
        # or current_instruction.mnemonic.startswith("tst"):
            # reguses = reguses.union(regwrites)

        # for nexti in nexts:
            # if nexti not in self.used_regs: continue
            # reguses = reguses.union(
                # self.used_regs[nexti].difference(regwrites))

        # reguses = self.compute_reg_set_closure(reguses)

        # if reguses != self.used_regs[instruction_idx]:
            # self.used_regs[instruction_idx] = reguses
            # return True

        # return False


    def debug(self, function):
        print("==== DEBUG")
        for instruction_idx, inst in enumerate(function.cache):
            print(inst, "Used:", sorted(self.used_regs[instruction_idx]))

    def finalize(self):
        for idx, ent in self.used_regs.items():
            # self.free_regs[idx] = []
            self.free_regs[idx] = self.reg_pool.difference(ent)
