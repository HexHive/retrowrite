import copy
import math
from collections import defaultdict
import json

from archinfo import ArchAArch64

from capstone.x86_const import X86_REG_RSP
from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_RET, CS_OP_REG, CS_OP_MEM

from . import snippets as sp
from librw_arm64.container import (DataCell, InstrumentedInstruction, DataSection,
                             Function)
from librw_arm64.analysis.stackframe import StackFrameAnalysis
from librw_arm64.util.logging import *
from librw_arm64.container import INSTR_SIZE
from librw_arm64.util.arm_util import get_reg_size_arm, get_access_size_arm, is_reg_32bits, get_64bits_reg, non_clobbered_registers

ASAN_SHADOW_OFF = 68719476736 # 0x1000000000

ASAN_GLOBAL_DS_BASE = 0x3000000000000000
ASAN_INIT_LOC = 0x1000000000000000
ASAN_DEINIT_LOC = 0x2000000000000000



class Instrument():
    CANARY_ANALYSIS_KEY = 'stack_canary_expression'

    def __init__(self, rewriter, stackrz_sz=32, globalrz_sz=64):
        self.rewriter = rewriter
        self.stackrz_sz = stackrz_sz
        self.globalrz_sz = globalrz_sz
        self.global_count = 0

        # Get the register map
        aarch64 = ArchAArch64()
        self.regmap = defaultdict(lambda: defaultdict(dict))
        for reg in aarch64.register_list:
            if reg.general_purpose:
                self.regmap[reg.name] = reg.subregisters[0][0]

        # Some stats
        self.mem_instrumentation_stats = defaultdict(list)

        # Skip instrumentation: Set of offsets (addresses) to skip memcheck
        # instrumentation for.
        self.skip_instrument = set()

    def _get_subreg32(self, regname):
        if is_reg_32bits(regname): return regname
        return self.regmap[regname]

    def instrument_init_array(self):
        #XXX: yet todo
        section = self.rewriter.container.sections[".init_array"]
        constructor = DataCell.instrumented(".quad {}".format(sp.ASAN_INIT_FN),
                                            8)
        section.cache.append(constructor)

        if ".fini_array" not in self.rewriter.container.sections:
            finiarr = DataSection(".fini_array", 0, 0, "")
            self.rewriter.container.add_section(finiarr)

        fini = self.rewriter.container.sections[".fini_array"]
        destructor = DataCell.instrumented(
            ".quad {}".format(sp.ASAN_DEINIT_FN), 8)
        fini.cache.append(destructor)

        initfn = Function(sp.ASAN_INIT_FN, ASAN_INIT_LOC, 0, "")
        initfn.set_instrumented()
        initcode = InstrumentedInstruction(
            '\n'.join(sp.MODULE_INIT).format(global_count=self.global_count),
            None, None)
        initfn.cache.append(initcode)
        self.rewriter.container.add_function(initfn)

        finifn = Function(sp.ASAN_DEINIT_FN, ASAN_DEINIT_LOC, 0, "")
        finifn.set_instrumented()
        finicode = InstrumentedInstruction(
            '\n'.join(sp.MODULE_DEINIT).format(global_count=self.global_count),
            None, None)
        finifn.cache.append(finicode)
        self.rewriter.container.add_function(finifn)

    def get_mem_instrumentation(self, acsz, instruction, midx, free, is_leaf, bool_load, rbase_reg):
        if "sp" in instruction.reg_reads() or "sp" in instruction.reg_writes():
            debug("we do not instrument push/pop for now")
            return InstrumentedInstruction("# not instrumented - push/pop")
        if "x29" in instruction.reg_reads() or "x29" in instruction.reg_writes():
            debug("we do not instrument stack frames for now")
            return InstrumentedInstruction("# not instrumented - stackframe push/pop")
        if "x28" in instruction.reg_reads() or "x28" in instruction.reg_writes():
            debug("we do not instrument stack frames for now")
            return InstrumentedInstruction("# not instrumented - stackframe push/pop")
        #XXX: this should skip only other ASAN instrumentation, not any instrumentation in general
        if len(instruction.before) > 0 or len(instruction.after) > 0 or\
            (instruction.mnemonic == "ldr" and "=" in instruction.op_str):
            return InstrumentedInstruction("# Already instrumented - skipping bASAN")

        # we prefer high registers, less likely to go wrong
        affinity = ["x" + str(i) for i in range(17, -1, -1)]
        # do not use registers used by the very same instruction!
        for reg in instruction.reg_reads():
            reg64 = get_64bits_reg(reg) if is_reg_32bits(reg) else reg
            if reg64 in affinity:
                affinity.remove(reg64)


        free_regs = sorted(
            list(free),
            key=lambda x: affinity.index(x) if x in affinity else len(affinity))

        # do not use registers used for batching
        if rbase_reg and rbase_reg in free_regs:
            print(affinity)
            print(rbase_reg)
            free_regs.remove(rbase_reg)

        codecache = list()
        save = list()
        restore = list()
        fix_lexp = list()
        save_rflags = "unopt"
        save_rax = True
        push_cnt = 0

        # XXX: for access sizes 8 and 16:
        # we need one register less
        num_regs_used = 5
        asan_regs = free_regs[:num_regs_used] # we need 4 free registers
        if len(asan_regs) < num_regs_used: # if there aren't enough we save them on the stack
            non_free = [reg for reg in affinity if reg not in asan_regs]
            to_save_regs = non_free[:num_regs_used - len(asan_regs)]
            i = 0
            for i in range(0, len(to_save_regs)-1, 2): # first save them in pairs (faster)
                save.append(copy.copy(sp.STACK_PAIR_REG_SAVE)[0].format(*to_save_regs[i:i+2]))
                restore.insert(0, copy.copy(sp.STACK_PAIR_REG_LOAD)[0].format(*to_save_regs[i:i+2]))
            if len(to_save_regs) % 2 == 1: # if there is a single one left
                save.append(copy.copy(sp.STACK_REG_SAVE)[0].format(to_save_regs[-1]))
                restore.insert(0, copy.copy(sp.STACK_REG_LOAD)[0].format(to_save_regs[-1]))
            asan_regs += to_save_regs
            push_cnt += len(to_save_regs)

        save_condition_reg = True
        if save_condition_reg: # XXX: should check whether we actually need this or not
            save.append("\tmrs {0}, nzcv".format(asan_regs[4]))
            restore.insert(0, "\tmsr nzcv, {0}".format(asan_regs[4]))

        mem, mem_op_idx = instruction.get_mem_access_op()
        mem_op = instruction.cs.operands[mem_op_idx]

        cs = instruction.cs

        lexp = asan_regs[0] # the first free register

        # ldr x0, [x1, x2, LSL#3]
        if mem_op.shift.value != 0:
            amnt = mem_op.shift.value
            to, sxtw = asan_regs[0], ""
            shift_reg = cs.reg_name(mem.index)
            if is_reg_32bits(shift_reg): to,sxtw = self._get_subreg32(asan_regs[0]), ", sxtw"
            fix_lexp += [sp.LEXP_SHIFT.format(To=to, Res=asan_regs[0], From=cs.reg_name(mem.base), amnt=amnt, shift_reg=shift_reg, sxtw=sxtw)]
        # ldr x0, [x1, x2]
        elif mem.index != 0:
            reg_index = cs.reg_name(mem.index)
            if is_reg_32bits(reg_index):
                reg_index += ", sxtw"  # quick hack
            fix_lexp += [sp.LEXP_ADD.format(To=asan_regs[0], From=cs.reg_name(mem.base), amnt=reg_index)]
        # ldr x0, [x1, #12]
        elif mem.disp != 0:
            if mem.disp > (1 << 12): # aarch64 limitation
                fix_lexp += [sp.LEXP_MOVZ.format(To=asan_regs[0], amnt=mem.disp)]
                fix_lexp += [sp.LEXP_ADD.format(To=asan_regs[0], From=cs.reg_name(mem.base), amnt=asan_regs[0])]
            else:
                fix_lexp += [sp.LEXP_ADD.format(To=asan_regs[0], From=cs.reg_name(mem.base), amnt=mem.disp)]
        # ldr x0, [x1]
        if mem.disp == 0 and mem.index == 0 and mem_op.shift.value == 0:
            lexp = cs.reg_name(mem.base)

        if "rflags" in free:
            save_rflags = False
            free.remove("rflags")

        if "rax" in free:
            save_rax = False

        if is_leaf:
            save.insert(0, sp.LEAF_STACK_ADJUST)
            restore.append(sp.LEAF_STACK_UNADJUST)


        if push_cnt > 0 and '%rsp' in lexp:
            # In this case we have a stack-relative load but the value of the stack
            # pointer has changed because we pushed some registers to the stack
            # to save them. Adjust the displacement of the access to take this
            # into account
            # XXX ARM:
            save.append("leaq {}(%rsp), %rsp".format(push_cnt * 8))
            restore.insert(0, "leaq -{}(%rsp), %rsp".format(push_cnt * 8))

        memcheck = ""

        if not rbase_reg: # we could not batch the ASAN base
            memcheck += copy.copy(sp.ASAN_BASE)

        if acsz == 1:
            memcheck += copy.copy(sp.MEM_LOAD_1)
        elif acsz == 2:
            memcheck += copy.copy(sp.MEM_LOAD_2)
        elif acsz == 4:
            memcheck += copy.copy(sp.MEM_LOAD_4)
        elif acsz == 8:
            memcheck += copy.copy(sp.MEM_LOAD_8)
        elif acsz == 16:
            memcheck += copy.copy(sp.MEM_LOAD_16)
        else:
            assert False, "Reached unreachable code!"

        memcheck += copy.copy(sp.ASAN_REPORT)

        codecache.extend(save)
        if len(fix_lexp): 
            codecache.append('\n'.join(fix_lexp))
        codecache.append(memcheck)
        codecache.append(sp.MEM_EXIT_LABEL)
        # codecache.append(
            # copy.copy(sp.MEM_EXIT_LABEL)[0].format(addr=instruction.address))
        codecache.extend(restore)


        args = dict()
        args["lexp"] = lexp
        args["acsz"] = acsz

        args["r1"] = asan_regs[1]
        args["r1_32"] = self._get_subreg32(asan_regs[1])
        args["r2"] = asan_regs[2]
        args["r2_32"] = self._get_subreg32(asan_regs[2])
        args["rbase"] = rbase_reg if rbase_reg else asan_regs[3]


        args["addr"] = instruction.address
        enter_lbl = "%s_%x" % (sp.ASAN_MEM_ENTER, instruction.address)

        args['acctype'] = 'load' if bool_load else 'store'

        codecache = '\n'.join(codecache)
        comment = "{}: {}".format(str(instruction), str(free))


        return codecache.format(**args)


    def instrument_mem_accesses(self):
        jumps_instrumentation = list()
        for _, fn in self.rewriter.container.functions.items():
            # if any([s in fn.name for s in ["alloc", "signal_is_trapped", "free", "gimplify"]]):
                # info(f"Skipping instrumentation on function {fn.name} to avoid custom heap implementations")
                # continue
            if not len(fn.cache): continue
            is_leaf = fn.analysis.get(StackFrameAnalysis.KEY_IS_LEAF, False)

            # First, we analyze basic blocks, to check if we can batch instrumentation
            for e, addr in enumerate(sorted(fn.bbstarts)):
                bb_start = addr
                bb_end = sorted(fn.bbstarts)[e+1] - INSTR_SIZE if e+1 < len(fn.bbstarts) else fn.cache[-1].address

                if bb_start not in fn.addr_to_idx:
                    critical(f"basic block error: {hex(addr)} not in function {fn.name}, starting at {hex(fn.cache[0].address)}, ending at {hex(fn.cache[-1].address)}")
                    continue
                if bb_end not in fn.addr_to_idx:
                    critical(f"basic block error: {hex(bb_end)} not in function {fn.name}, starting at {hex(fn.cache[0].address)}, ending at {hex(fn.cache[-1].address)}")
                    continue

                first_instruction = fn.cache[fn.addr_to_idx[bb_start]]
                last_instruction = fn.cache[fn.addr_to_idx[bb_end]]

                to_instrument = []
                regs = set(non_clobbered_registers)
                regs.remove("x0") # cannot overwrite return value

                # compute the free regs of this basic block
                for addr in range(bb_start, bb_end + INSTR_SIZE, INSTR_SIZE):
                    idx = fn.addr_to_idx[addr]
                    free_registers = fn.analysis['free_registers'][idx]
                    if fn.cache[idx].mnemonic.startswith("bl"): # XXX: WTFFFFFF
                        regs = set()
                    regs = regs.intersection(free_registers)

                # compute which instructions we are going to instrument (to_instrument)
                for addr in range(bb_start, bb_end + INSTR_SIZE, INSTR_SIZE):
                    idx = fn.addr_to_idx[addr]
                    instruction = fn.cache[idx]

                    if isinstance(instruction, InstrumentedInstruction) or \
                       instruction.address in self.skip_instrument:
                        continue

                    mem, midx = instruction.get_mem_access_op()
                    if not mem: # This is not a memory access
                        continue

                    # XXX: not supporting SIMD instructions for now (ld1, st3 ...)
                    if instruction.cs.reg_name(instruction.cs.operands[0].reg)[0] == 'v':
                        debug(f"Skipping BAsan instrumentation on SIMD instr {instruction.cs}")
                        continue

                    # look at start of get_mem_instrumentation()
                    if any([x in instruction.reg_reads() + instruction.reg_writes() for x in ["sp", "x29", "x28"]]):
                        continue

                    free_registers = fn.analysis['free_registers'][idx]
                    acsz, bool_load = get_access_size_arm(instruction.cs)

                    if acsz not in [1, 2, 4, 8, 16]:
                        critical(f"[*] Missed an access: {instruction} -- {acsz}")
                        continue

                    self.mem_instrumentation_stats[fn.start].append(idx)
                    to_instrument += [(acsz, instruction, midx, free_registers, is_leaf, bool_load)]

                # if len(regs) and len(to_instrument) > 1:
                    # rbase_reg = sorted(regs)[-1]
                    # first_instruction.instrument_before(InstrumentedInstruction(f"mov {rbase_reg}, 0x1000000000"))
                # else:
                    # rbase_reg = None
                rbase_reg = None

                # now we actually instrument the selected instructions
                for acsz, instruction, midx, free_registers, is_leaf, bool_load in to_instrument:
                    debug(f"{instruction} --- acsz: {acsz}, load: {bool_load}")
                    iinstr = self.get_mem_instrumentation(
                        acsz, instruction, midx, free_registers, is_leaf, bool_load, rbase_reg)
                    jumps_instrumentation += [f".I{hex(instruction.address)[2:]}:"]
                    jumps_instrumentation += [iinstr]
                    jumps_instrumentation += [f"b .LC{hex(instruction.address)[2:]} + 4"]
                    instruction.instrument_before(InstrumentedInstruction(f"b .I{hex(instruction.address)[2:]}"))


                debug(f"{hex(bb_start)}, {hex(bb_end)}")
                debug(f"{regs}")
        return "\n".join(jumps_instrumentation)







    def do_instrument(self):
        #self.instrument_globals()
        instrumentation = self.instrument_mem_accesses()

        ds = DataSection(".jumps", 0x100000, 0, None, flags="ax")
        # content = """
        # .file: .string \"/tmp/countfile\"
        # .perms: .string \"w\"
        # .format: .string \"%lld\\n\"
        # .align 3
        # .counted: .quad 0x0
        # """
        ds.cache.append(DataCell.instrumented(instrumentation, 0))
        self.rewriter.container.add_section(ds)

    def dump_stats(self):
        count = 0
        free_reg_sz = defaultdict(lambda: 0)
        free_reg_cnt = defaultdict(lambda: 0)
        rflags_stats = [0, 0, 0, 0]

        for addr, sites in self.mem_instrumentation_stats.items():
            count += len(sites)
            fn = self.rewriter.container.functions[addr]
            for site in sites:

                if site in fn.analysis['free_registers']:
                    regs = fn.analysis['free_registers'][site]
                else:
                    regs = []

                if "rflags" in regs:
                    free_reg_sz[len(regs) - 1] += 1
                else:
                    free_reg_sz[len(regs)] += 1

                for reg in regs:
                    free_reg_cnt[reg] += 1

                if "rflags" in regs:
                    rflags_stats[0] += 1
                elif len(regs) == 0:
                    rflags_stats[1] += 1
                elif "rax" in regs:
                    rflags_stats[2] += 1
                elif len(regs) > 0:
                    rflags_stats[3] += 1

        rflags_stats[0] = count - rflags_stats[0]

        debug("[*] Instrumented: {} locations".format(count))
        regs_cnt = [f"{nregs} free regs: {cnt}" for nregs,cnt in free_reg_cnt.items()]
        debug("Free register stats:\n" + "\n".join(sorted(regs_cnt)))

        nregs_cnt = [f"{cnt} free regs: {free_reg_sz[cnt]}" for cnt in range(len(free_reg_cnt))]
        debug("Free register count:\n" + "\n".join(nregs_cnt))
        debug(json.dumps(free_reg_cnt))
        debug(
            "rflags live: {}, rflags + 0 regs: {}, rflags + rax: {},".format(
                rflags_stats[0], rflags_stats[1], rflags_stats[2]),
            "rflags + >= 1 reg: {}".format(rflags_stats[3]))


class GlobalMetaData():
    ENT_SZ = 56

    def __init__(self, location, sz, sz_with_rz, name, mod_name,
                 has_dynamic_init):
        self.location = location
        self.sz = sz
        self.sz_with_rz = sz_with_rz
        self.name = name
        self.mod_name = mod_name
        self.has_dynamic_init = has_dynamic_init

        self.pad_up = 0
        self.pad_down = 0

    def __str__(self):
        results = [
            ".quad {}".format(self.location),
            ".quad {}".format(self.sz),
            ".quad {}".format(self.sz_with_rz),
            ".quad {}".format(self.name),
            ".quad {}".format(self.mod_name),
            ".quad {}".format(self.has_dynamic_init),
            ".quad {}".format(0),
        ]

        return "\n".join(results)

    def to_instrumented(self):
        results = [
            ".quad {}".format(self.location),
            ".quad {}".format(self.sz),
            ".quad {}".format(self.sz_with_rz),
            ".quad {}".format(self.name),
            ".quad {}".format(self.mod_name),
            ".quad {}".format(self.has_dynamic_init),
            ".quad {}".format(0),
        ]

        return list(map(lambda x: DataCell.instrumented(x, 8), results))
