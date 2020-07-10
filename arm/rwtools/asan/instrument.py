import copy
import math
from collections import defaultdict
import json

from archinfo import ArchAArch64

from capstone.x86_const import X86_REG_RSP
from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_RET, CS_OP_REG, CS_OP_MEM

from . import snippets as sp
from arm.librw.container import (DataCell, InstrumentedInstruction, DataSection,
                             Function)
from arm.librw.analysis.stackframe import StackFrameAnalysis
from arm.librw.util.logging import *
from arm.librw.util.arm_util import get_reg_size_arm, get_access_size_arm
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
        self.memcheck_sites = defaultdict(list)

        # Skip instrumentation: Set of offsets (addresses) to skip memcheck
        # instrumentation for.
        self.skip_instrument = set()

    def _get_subreg32(self, regname):
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

    def _access1(self):
        common = copy.copy(sp.MEM_LOAD_1)
        return common + sp.ASAN_REPORT

    def _access2(self):
        common = copy.copy(sp.MEM_LOAD_2)
        return common + sp.ASAN_REPORT

    def _access4(self):
        common = copy.copy(sp.MEM_LOAD_4)
        return common + sp.ASAN_REPORT

    def _access8(self):
        common = copy.copy(sp.MEM_LOAD_8)
        return common + sp.ASAN_REPORT

    def _access16(self):
        common = copy.copy(sp.MEM_LOAD_16)
        return common + sp.ASAN_REPORT

    def get_mem_instrumentation(self, acsz, instruction, midx, free, is_leaf, bool_load):
        if "sp" in instruction.reg_reads() and "sp" in instruction.reg_writes():
            debug("we do not instrument push/pop for now")
            return "# push/pop"


        # we prefer high registers, less likely to go wrong
        affinity = ["x" + str(i) for i in range(18, 0, -1)]
        free = sorted(
            list(free),
            key=lambda x: affinity.index(x) if x in affinity else len(affinity))


        codecache = list()
        save = list()
        restore = list()
        fix_lexp = list()
        save_rflags = "unopt"
        save_rax = True
        is_rep_stos = False

        asan_regs = []
        for i in range(4):
            if len(free) > i:
                asan_regs += [free[i]]
            else:
                print("Not enough free registers! Quitting...")
                exit(1)



        mem, mem_op_idx = instruction.get_mem_access_op()
        mem_op = instruction.cs.operands[mem_op_idx]

        cs = instruction.cs

        lexp = asan_regs[0] # the first free register

        # ldr x0, [x1, x2, LSL#3]
        if mem_op.shift.value != 0:
            amnt = mem_op.shift.value
            fix_lexp += [sp.LEXP_SHIFT.format(To=asan_regs[0], From=cs.reg_name(mem.base), amnt=amnt, shift_reg=cs.reg_name(mem.index))]
        # ldr x0, [x1, x2]
        elif mem.index != 0:
            fix_lexp += [sp.LEXP_ADD.format(To=asan_regs[0], From=cs.reg_name(mem.index), amnt=cs.reg_name(mem.base))]
        # ldr x0, [x1, #12]
        elif mem.disp != 0:
            fix_lexp += [sp.LEXP_ADD.format(To=asan_regs[0], From=cs.reg_name(mem.base), amnt=mem.disp)]
        # ldr x0, [x1]
        if mem.disp == 0 and mem.index == 0 and mem_op.shift.value == 0:
            lexp = cs.reg_name(mem.base)

        if "rflags" in free:
            save_rflags = False
            free.remove("rflags")

        if "rax" in free:
            save_rax = False

        # XXX:
        # if len(free) > 0:
            # r2 = [False, "%{}".format(free[0])]
            # if len(free) > 1:
                # r1 = [False, "%{}".format(free[1])]

            # if r2[1] == r1[1]:
                # r1 = [True, "x1"]

            # if save_rflags:
                # save_rflags = "opt"
                # save_rax = "rax" not in free

        # this has to do with red zones (kernel x64 does not have them)
        # https://github.com/torvalds/linux/blob/9f159ae07f07fc540290f219372
        push_cnt = 0
        if is_leaf and (any([r[0] for r in asan_regs]) or save_rflags):
            save.append(sp.LEAF_STACK_ADJUST)
            restore.append(sp.LEAF_STACK_UNADJUST)
            push_cnt += 32

        # XXX: saving registers!
        # for r in asan_regs:
            # if r[0]:
                # save.append(copy.copy(sp.MEM_REG_SAVE)[0].format(reg=r[1]))
                # restore.insert(0, copy.copy(sp.MEM_REG_RESTORE)[0].format(reg=r[1]))
                # push_cnt += 1


        # XXX:
        # XXX:
        # XXX:
        # if save_rflags == "unopt":
            # save.append(copy.copy(sp.MEM_FLAG_SAVE)[0])
            # restore.insert(0, copy.copy(sp.MEM_FLAG_RESTORE)[0])
            # push_cnt += 1
        # elif save_rflags == "opt":
            # push_cnt += 1
            # if save_rax:
                # save.append(copy.copy(
                    # sp.MEM_REG_REG_SAVE_RESTORE)[0].format(src="%rax",
                                                           # dst=r2[1]))
                # save.extend(copy.copy(
                    # sp.MEM_FLAG_SAVE_OPT))

                # save.append(copy.copy(
                    # sp.MEM_REG_REG_SAVE_RESTORE)[0].format(dst="%rax",
                                                           # src=r2[1]))

                # restore.insert(0, copy.copy(
                    # sp.MEM_REG_REG_SAVE_RESTORE)[0].format(dst="%rax",
                                                           # src=r2[1]))

                # restore = copy.copy(sp.MEM_FLAG_RESTORE_OPT) + restore

                # restore.insert(0, copy.copy(
                    # sp.MEM_REG_REG_SAVE_RESTORE)[0].format(src="%rax",
                                                           # dst=r2[1]))
            # else:
                # save.extend(copy.copy(
                    # sp.MEM_FLAG_SAVE_OPT))
                # restore = copy.copy(sp.MEM_FLAG_RESTORE_OPT) + restore

        if push_cnt > 0 and '%rsp' in lexp:
            # In this case we have a stack-relative load but the value of the stack
            # pointer has changed because we pushed some registers to the stack
            # to save them. Adjust the displacement of the access to take this
            # into account
            save.append("leaq {}(%rsp), %rsp".format(push_cnt * 8))
            restore.insert(0, "leaq -{}(%rsp), %rsp".format(push_cnt * 8))

        if acsz == 1:
            memcheck = self._access1()
        elif acsz == 2:
            memcheck = self._access2()
        elif acsz == 4:
            memcheck = self._access4()
        elif acsz == 8:
            memcheck = self._access8()
        elif acsz == 16:
            memcheck = self._access16()
        else:
            assert False, "Reached unreachable code!"

        debug(f"Memcheck {acsz}:\n" + memcheck)

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
        args["acsz_1"] = acsz - 1

        args["tgt"] = asan_regs[0]
        args["tgt_32"] = self._get_subreg32(asan_regs[0])
        args["clob1"] = asan_regs[1]
        args["clob1_32"] = self._get_subreg32(asan_regs[1])
        args["clob2"] = asan_regs[2]
        args["clob2_32"] = self._get_subreg32(asan_regs[2])
        args["clob3"] = asan_regs[3]
        args["clob3_32"] = self._get_subreg32(asan_regs[3])


        args["addr"] = instruction.address
        enter_lbl = "%s_%s" % (sp.ASAN_MEM_ENTER, instruction.address)

        args['acctype'] = 'load' if bool_load else 'store'

        codecache = '\n'.join(codecache)
        comment = "{}: {}".format(str(instruction), str(free))

        if is_rep_stos:
            copycache = copy.copy(codecache)
            extend_args_check = copy.copy(args)
            extend_args_check["lexp"] = "(%rdi, %rcx)"
            extend_args_check["addr"] = '{}_2'.format(instruction.address)
            copycache = copycache.format(**extend_args_check)
            original_exit = copy.copy(
                sp.MEM_EXIT_LABEL)[0].format(addr=instruction.address)

            new_exit = copy.copy(sp.MEM_EXIT_LABEL)[0].format(
                addr='{}_2'.format(instruction.address))
            copycache = copycache.replace(original_exit, new_exit)
            codecache = codecache + "\n" + copycache

        debug("Memcheck after:\n" + codecache.format(**args))

        return InstrumentedInstruction(codecache.format(**args),
                                       enter_lbl, comment)


    def instrument_mem_accesses(self):
        for _, fn in self.rewriter.container.functions.items():
            is_leaf = fn.analysis.get(StackFrameAnalysis.KEY_IS_LEAF, False)
            for idx, instruction in enumerate(fn.cache):
                # Do not instrument instrumented instructions
                if isinstance(instruction, InstrumentedInstruction):
                    continue
                # Do not instrument nops
                if instruction.mnemonic.startswith("nop"):
                    continue
                # Do not instrument lea
                if instruction.mnemonic.startswith("lea"):
                    continue
                if instruction.address in self.skip_instrument:
                    continue
                # Do not instrument stack canaries
                # XXX: if instruction.op_str.startswith(sp.CANARY_CHECK):
                    # XXX: continue

                # XXX: THIS IS A TODO for more accurate check.
                if instruction.mnemonic.startswith("rep stos"):
                    pass

                mem, midx = instruction.get_mem_access_op()
                # This is not a memory access
                if not mem:
                    continue

                acsz, bool_load = get_access_size_arm(instruction.cs)
                debug(f"{instruction} --- acsz: {acsz}, load: {bool_load}")

                if acsz not in [1, 2, 4, 8, 16]:
                    print("[*] Maybe missed an access: %s -- %d" %
                          (instruction, acsz))
                    continue

                if idx in fn.analysis['free_registers']:
                    free_registers = fn.analysis['free_registers'][idx]
                else:
                    print("[x] Missing free reglist in cache. Regenerate!")
                    free_registers = list()

                iinstr = self.get_mem_instrumentation(
                    acsz, instruction, midx, free_registers, is_leaf, bool_load)

                debug(f"now is {iinstr}")

                # Save some stats
                self.memcheck_sites[fn.start].append(idx)
                instruction.instrument_before(iinstr)

    def instrument_globals(self):
        gmap = list()
        for _, sec in self.rewriter.container.sections.items():
            location = sec.base
            appends = defaultdict(list)
            for idx, cell in enumerate(sec.cache):
                if cell.ignored or cell.is_instrumented:
                    continue

                if location in sec.named_globals:
                    self.global_count += 1
                    gobj = sec.named_globals[location][0]
                    asan_global_meta = self.new_global_metadata(gobj)
                    gmap.append(asan_global_meta)
                    # Need to add padding.
                    # Redzone below the global
                    appends[location + gobj["sz"]].append(
                        asan_global_meta.pad_down)

                location += cell.sz

            location = sec.base
            oldcache = copy.copy(sec.cache)

            for idx, cell in enumerate(oldcache):
                if cell.is_instrumented or cell.ignored:
                    continue
                if location in appends:
                    for pad in appends[location]:
                        instrumented = DataCell.instrumented(
                            ".zero {}".format(pad), pad)
                        cell.instrument_after(instrumented)
                location += cell.sz

        ds = DataSection(".data.asan", ASAN_GLOBAL_DS_BASE, 0, None)
        ds.cache.append(
            DataCell.instrumented("{}:".format(sp.ASAN_GLOBAL_DS), 0))
        for meta in gmap:
            ds.cache.extend(meta.to_instrumented())
        self.rewriter.container.add_section(ds)

    def new_global_metadata(self, gobj):
        location = gobj["label"]
        sz = gobj["sz"]
        if sz % self.globalrz_sz == 0:
            sz_with_rz = self.globalrz_sz + sz
        else:
            sz_with_rz = int(
                math.ceil(sz / self.globalrz_sz) * self.globalrz_sz)
        name = 0
        mod_name = 0
        has_dynamic_init = 0

        meta = GlobalMetaData(location, sz, sz_with_rz, name, mod_name,
                              has_dynamic_init)

        diff = sz_with_rz - sz
        meta.pad_up = 0
        meta.pad_down = diff

        return meta

    def poison_stack(self, args, need_save):
        instrumentation = list()

        # Save the register we're about to clobber
        if need_save:
            instrumentation.append(
                copy.copy(sp.MEM_REG_SAVE)[0])

        # Add instrumentation to poison
        instrumentation.extend(copy.copy(sp.STACK_POISON_BASE))

        args["off"] = ASAN_SHADOW_OFF
        instrumentation.append(
            copy.copy(sp.STACK_POISON_SLOT))

        # Restore clobbered register
        if need_save:
            instrumentation.append(
                copy.copy(sp.MEM_REG_RESTORE)[0])

        code_str = "\n".join(instrumentation).format(**args)
        return InstrumentedInstruction(
            code_str, sp.STACK_ENTER_LBL.format(**args), None)

    def unpoison_stack(self, args, need_save):
        instrumentation = list()

        # Save the register we're about to clobber
        if need_save:
            instrumentation.append(
                copy.copy(sp.MEM_REG_SAVE)[0])

        # Add instrumentation to poison
        instrumentation.extend(copy.copy(sp.STACK_POISON_BASE))

        args["off"] = ASAN_SHADOW_OFF
        instrumentation.append(
            copy.copy(sp.STACK_UNPOISON_SLOT))

        # Restore clobbered register
        if need_save:
            instrumentation.append(
                copy.copy(sp.MEM_REG_RESTORE)[0])

        code_str = "\n".join(instrumentation).format(**args)
        return InstrumentedInstruction(
            code_str, sp.STACK_EXIT_LBL.format(**args), None)

    def get_free_regs(self, fn, idx):

        if idx in fn.analysis['free_registers']:
            free = copy.copy(fn.analysis['free_registers'][idx])
        else:
            return []

        free = list(free)
        affinity = ["rdi", "rsi", "rcx", "rdx", "rbx", "r8", "r9", "r10",
                    "r11", "r12", "r13", "r14", "r15", "rax", "rbp"]

        free = sorted(
            list(free),
            key=lambda x: affinity.index(x) if x in affinity else len(affinity))

        if "rflags" in free:
            free.remove("rflags")

        return ["%"+x for x in free]

    def handle_longjmp(self, instruction):
        args = dict(
            reg="%r9",
            addr=instruction.address,
            off=ASAN_SHADOW_OFF)
        unpoison = ("\n".join(copy.copy(sp.LONGJMP_UNPOISON))).format(**args)
        instrument = InstrumentedInstruction(
            unpoison, None, None)
        instruction.instrument_before(instrument)

    def instrument_stack(self):

        #XXX: check the kernel version, it is a bit different


        # Detect stack canary and insert red zones only for functions with
        # stack canaries.
        # Need to unpoison the stack before any CF leaves this function, e.g.,
        # ret and jmp to a different function.
        need_red = list()
        for addr, fn in self.rewriter.container.functions.items():
            # Heuristic:
            # Check if there is a set to canary in the first 20 instructions.
            for idx, instruction in enumerate(fn.cache[:20]):
                if instruction.op_str.startswith(sp.CANARY_CHECK):
                    need_red.append((addr, idx))
                    break

        for addr, fn in self.rewriter.container.functions.items():
            for idx, instruction in enumerate(fn.cache):
                # XXX: ARM
                if instruction.mnemonic.startswith("callq"):
                    if instruction.op_str.startswith("__longjmp"):
                        self.handle_longjmp(instruction)

        for addr, cidx in need_red:
            fn = self.rewriter.container.functions[addr]
            print("[*] %s needs redzone stack" % (fn.name))
            is_poisoned = False
            inserts = list()

            for idx, instruction in enumerate(fn.cache):
                if not is_poisoned:
                    if idx != cidx:
                        continue

                    # This is now the canary load instruction.
                    # The next instruction moves the canary into the current
                    # stack frame, get the address.
                    nexti = fn.cache[idx + 1]
                    # XXX: ARM
                    if nexti.mnemonic != "movq":
                        continue

                    store_exp = nexti.op_str.split(",", 1)[1].strip()
                    fn.analysis[Instrument.CANARY_ANALYSIS_KEY] = store_exp
                    # Do not instrument this instruction as it will cause a
                    # violation.
                    self.skip_instrument.add(nexti.address)
                    # Do not instrument canary load from fs: as well.
                    self.skip_instrument.add(instruction.address)
                    # Poison the canary location.
                    pbase = store_exp

                    free_registers = self.get_free_regs(fn, idx)
                    need_save = True
                    #XXX: ARM
                    clob1 = "%rbx"
                    if len(free_registers) > 0:
                        clob1 = free_registers[0]
                        need_save = False

                    args = dict(
                        reg=clob1, pbase=pbase,
                        addr=instruction.address)

                    poisoni = self.poison_stack(args, need_save)
                    instruction.instrument_before(poisoni)
                    is_poisoned = True
                else:
                    # Look for all reads from the canary and unposion before read.
                    mem, midx = instruction.get_mem_access_op()
                    if not mem:
                        continue
                    # Check if the next instruction is a xor with the canary
                    nexti = fn.cache[idx + 1]
                    #XXX: ARM
                    if nexti.mnemonic != "xorq":
                        continue
                    # Check if we're xor'ing with the canary
                    op0 = nexti.op_str.split(",", 1)[0]
                    if op0 != "%fs:0x28":
                        continue
                    # Ok, now we're sure to be loading from the canary, unpoison.
                    canary_loc = instruction.op_str.split(",", 1)[0]
                    if fn.analysis[Instrument.CANARY_ANALYSIS_KEY] != canary_loc:
                        print("[x] Canary read different from canary write loc")

                    self.skip_instrument.add(instruction.address)
                    pbase = canary_loc

                    free_registers = self.get_free_regs(fn, idx)
                    need_save = True
                    #XXX: ARM
                    clob1 = "%rbx"
                    if len(free_registers) > 0:
                        clob1 = free_registers[0]
                        need_save = False

                    args = dict(
                        reg=clob1, pbase=pbase,
                        addr=instruction.address)

                    unpoisoni = self.unpoison_stack(args, need_save)
                    instruction.instrument_before(unpoisoni)

            for idx, code in enumerate(inserts):
                fn.cache.insert(idx + code[0], code[1])

    def do_instrument(self):
        #self.instrument_globals()
        self.instrument_mem_accesses()
        #XXX: ARM, fix those two functions
        # self.instrument_stack()
        # self.instrument_init_array()

    def dump_stats(self):
        count = 0
        free_reg_sz = list()
        free_reg_cnt = defaultdict(lambda: 0)
        rflags_stats = [0, 0, 0, 0]

        for addr, sites in self.memcheck_sites.items():
            count += len(sites)
            fn = self.rewriter.container.functions[addr]
            for site in sites:

                if site in fn.analysis['free_registers']:
                    regs = fn.analysis['free_registers'][site]
                else:
                    regs = []

                if "rflags" in regs:
                    free_reg_sz.append(len(regs) - 1)
                else:
                    free_reg_sz.append(len(regs))

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

        print("[*] Instrumented: {} locations".format(count))
        print("Stats:", free_reg_sz)
        print(json.dumps(free_reg_cnt))
        print(
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
