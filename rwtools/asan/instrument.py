import copy
import math
from collections import defaultdict
import numpy as np
import json

from archinfo import ArchAMD64

from capstone.x86_const import X86_REG_RSP
from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_RET

from . import snippets as sp
from librw.container import (DataCell, InstrumentedInstruction, DataSection,
                             Function)

ASAN_SHADOW_OFF = 2147450880
ASAN_GLOBAL_DS_BASE = 0x3000000000000000
ASAN_INIT_LOC = 0x1000000000000000
ASAN_DEINIT_LOC = 0x2000000000000000


class Instrument():
    def __init__(self, rewriter, stackrz_sz=32, globalrz_sz=64):
        self.rewriter = rewriter
        self.stackrz_sz = stackrz_sz
        self.globalrz_sz = globalrz_sz
        self.global_count = 0

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

        # Some stats
        self.memcheck_sites = defaultdict(list)

    def _get_subreg32(self, regname):
        return self.regmap[regname][0][32]

    def _get_subreg8l(self, regname):
        return self.regmap[regname][0][8]

    def _get_subreg8h(self, regname):
        return self.regmap[regname][1][8]

    def _get_subreg16(self, regname):
        return self.regmap[regname][0][16]

    def instrument_init_array(self):
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
        initcode = InstrumentedInstruction(
            '\n'.join(sp.MODULE_INIT).format(global_count=self.global_count),
            None, None)
        initfn.cache.append(initcode)
        self.rewriter.container.add_function(initfn)

        finifn = Function(sp.ASAN_DEINIT_FN, ASAN_DEINIT_LOC, 0, "")
        finicode = InstrumentedInstruction(
            '\n'.join(sp.MODULE_DEINIT).format(global_count=self.global_count),
            None, None)
        finifn.cache.append(finicode)
        self.rewriter.container.add_function(finifn)

    def _access1(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)

        del ac1[2]

        return "\n".join(common + ac1)

    def _access2(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)

        ac1[2] = "\tincl {clob1_32}"

        return "\n".join(common + ac1)

    def _access4(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)
        ac1 = copy.copy(sp.MEM_LOAD_SZ)

        return "\n".join(common + ac1)

    def _access8(self):
        common = copy.copy(sp.MEM_LOAD_COMMON)

        common[3] = "\tcmpb $0, 2147450880({tgt})"
        common[4] = common[5]
        common[5] = sp.MEM_LOAD_SZ[-1]

        # rest = [rest[0], rest[1]]
        # save = [save[0]]

        return "\n".join(common)

    def _access16(self):
        raise NotImplementedError

    def get_mem_instrumentation(self, acsz, instruction, midx, free):
        affinity = ["rdi", "rsi", "rcx", "rdx", "rbx", "r8", "r9", "r10",
                    "r11", "r12", "r13", "r14", "r15", "rax", "rbp"]

        free = sorted(
            list(free),
            key=lambda x: affinity.index(x) if x in affinity else len(affinity))

        codecache = list()
        save = list()
        restore = list()
        save_rflags = "unopt"
        save_rax = True
        r1 = [True, "%rdi"]
        r2 = [True, "%rsi"]

        if "rflags" in free:
            save_rflags = False
            free.remove("rflags")

        if "rax" in free:
            save_rax = False

        if len(free) > 0:
            r2 = [False, "%{}".format(free[0])]
            if len(free) > 1:
                r1 = [False, "%{}".format(free[1])]

            if save_rflags:
                save_rflags = "opt"
                save_rax = "rax" not in free

        if r1[0]:
            save.append(copy.copy(sp.MEM_REG_SAVE)[0].format(reg=r1[1]))
            restore.append(copy.copy(sp.MEM_REG_RESTORE)[0].format(reg=r1[1]))

        if r2[0]:
            save.append(copy.copy(sp.MEM_REG_SAVE)[0].format(reg=r2[1]))
            restore.insert(0, copy.copy(sp.MEM_REG_RESTORE)[0].format(reg=r2[1]))

        if save_rflags == "unopt":
            save.append(copy.copy(sp.MEM_FLAG_SAVE)[0])
            restore.insert(0, copy.copy(sp.MEM_FLAG_RESTORE)[0])
        elif save_rflags == "opt":
            if save_rax:
                save.append(copy.copy(
                    sp.MEM_REG_REG_SAVE_RESTORE)[0].format(src="%rax",
                                                           dst=r1[1]))
                save.extend(copy.copy(
                    sp.MEM_FLAG_SAVE_OPT))

                save.append(copy.copy(
                    sp.MEM_REG_REG_SAVE_RESTORE)[0].format(dst="%rax",
                                                           src=r1[1]))

                restore.insert(0, copy.copy(
                    sp.MEM_REG_REG_SAVE_RESTORE)[0].format(dst="%rax",
                                                           src=r1[1]))

                restore = copy.copy(sp.MEM_FLAG_RESTORE_OPT) + restore

                restore.insert(0, copy.copy(
                    sp.MEM_REG_REG_SAVE_RESTORE)[0].format(src="%rax",
                                                           dst=r1[1]))
            else:
                save.extend(copy.copy(
                    sp.MEM_FLAG_SAVE_OPT))
                restore = copy.copy(sp.MEM_FLAG_RESTORE_OPT) + restore

        if acsz == 1:
            memcheck = self._access1()
        elif acsz == 2:
            memcheck = self._access2()
        elif acsz == 4:
            memcheck = self._access4()
        elif acsz == 8:
            memcheck = self._access8()
        else:
            assert False, "Reached unreachable code!"

        codecache.extend(save)
        codecache.append(memcheck)
        codecache.append(
            copy.copy(sp.MEM_EXIT_LABEL)[0].format(addr=instruction.address))
        codecache.extend(restore)

        # XXX: Bug in capstone?
        if any([
            instruction.mnemonic.startswith(x) for x in
            ["sar", "shl", "shl", "stos", "shr", "rep stos"]
        ]):
            midx = 1

        if len(instruction.cs.operands) == 1:
            lexp = instruction.op_str
        elif len(instruction.cs.operands) > 2:
            print("[*] Found op len > 2: %s" % (instruction))
            lexp = instruction.op_str.split(",", 2)[1]
        elif midx == 0:
            lexp = instruction.op_str.rsplit(",", 1)[0]
        else:
            lexp = instruction.op_str.split(",", 1)[1]

        if lexp.startswith("*"):
            lexp = lexp[1:]

        args = dict()
        args["lexp"] = lexp
        args["acsz"] = acsz
        args["acsz_1"] = acsz - 1

        args["clob1"] = r1[1]
        args["clob1_32"] = "%{}".format(self._get_subreg32(r1[1][1:]))

        args["tgt"] = r2[1]
        args["tgt_32"] = "%{}".format(self._get_subreg32(r2[1][1:]))
        args["tgt_8"] = "%{}".format(self._get_subreg8l(r2[1][1:]))

        args["addr"] = instruction.address
        enter_lbl = "%s_%x" % (sp.ASAN_MEM_ENTER, instruction.address)

        codecache = '\n'.join(codecache)

        comment = "{}: {}".format(str(instruction), str(free))
        return InstrumentedInstruction(codecache.format(**args),
                                       enter_lbl, comment)

    def instrument_mem_accesses(self):
        #included = set()
        #excluded = set()
        #excluded_new = set()
        #debug_data = None

        #with open("debug/incl") as fd:
            #debug_data = json.load(fd)
            #for key in debug_data:
                #if key == "included":
                    #included.update(debug_data[key])
                #else:
                    #excluded.update(debug_data[key])

        #print("[*] Excluded: {}".format(len(excluded)))

        for _, fn in self.rewriter.container.functions.items():
            inserts = list()
            for idx, instruction in enumerate(fn.cache):
                if isinstance(instruction, InstrumentedInstruction):
                    continue

                # Do not instrument nops
                if instruction.mnemonic.startswith("nop"):
                    continue

                # Do not instrument lea
                if instruction.mnemonic.startswith("lea"):
                    continue

                #if instruction.address in excluded:
                    #continue

                # XXX: THIS IS A TODO.
                if instruction.mnemonic.startswith("rep stos"):
                    print("[*] Skipping: {}".format(instruction))
                    continue

                mem, midx = instruction.get_mem_access_op()
                # This is not a memory access
                if not mem:
                    continue

                acsz = instruction.cs.operands[midx].size

                if acsz not in [1, 2, 4, 8]:
                    print("[*] Maybe missed an access: %s -- %d" %
                          (instruction, acsz))
                    continue

                #if included and instruction.address not in included:
                    #continue

                #rand_skip = np.random.randint(2, size=1)
                #if rand_skip == 1:
                    #excluded_new.add(instruction.address)
                    #continue

                free_registers = fn.analysis['free_registers'][idx]

                iinstr = self.get_mem_instrumentation(
                    acsz, instruction, midx, free_registers)

                # Save some stats
                self.memcheck_sites[fn.start].append(idx)

                # TODO: Replace original instruction for efficiency
                inserts.append((idx, iinstr))

            for idx, code in enumerate(inserts):
                fn.cache.insert(idx + code[0], code[1])

        #print("[-] Excluded: {}".format(len(excluded_new)))
        #with open("debug/incl", "w") as fd:
            #key = len(debug_data)
            #debug_data[key] = list(excluded_new)
            #json.dump(debug_data, fd, indent=4)

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
                    #print("[*] Instrumenting: %s" % (gobj))
                    asan_global_meta = self.new_global_metadata(gobj)
                    gmap.append(asan_global_meta)
                    # Need to add padding.
                    # Redzone above the global
                    appends[location].append(asan_global_meta.pad_up)
                    # Redzone below the global
                    appends[location + gobj["sz"]].append(
                        asan_global_meta.pad_down)

                location += cell.sz

            location = sec.base
            oldcache = copy.copy(sec.cache)
            icount = 0

            for idx, cell in enumerate(oldcache):
                if cell.is_instrumented or cell.ignored:
                    continue
                if location in appends:
                    for pad in appends[location]:
                        instrumented = DataCell.instrumented(
                            ".zero {}".format(pad), pad)
                        sec.cache.insert(idx + icount, instrumented)
                        icount += 1
                location += cell.sz

        ds = DataSection(".data.asan", ASAN_GLOBAL_DS_BASE, 0, None)
        ds.cache.append(
            DataCell.instrumented("{}:".format(sp.ASAN_GLOBAL_DS), 0))
        #ds.add_global(ASAN_GLOBAL_DS_BASE,
        #self.global_count * GlobalMetaData.ENT_SZ)
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
        if diff % 2 > 0:
            meta.pad_up += 1
        meta.pad_up += int(diff / 2)
        meta.pad_down += int(diff / 2)

        return meta

    def poison_stack(self, poison_extent, args):
        assert poison_extent % 32 == 0
        instrumentation = copy.copy(sp.STACK_POISON_BASE)

        for idx in range(0, int(poison_extent / 32)):
            args["off"] = ASAN_SHADOW_OFF + idx
            instrumentation.append(
                copy.copy(sp.STACK_POISON_SLOT).format(**args))

        instrumentation.append("popq {clob1}")
        return "\n".join(instrumentation).format(**args)

    def unpoison_stack(self, poison_extent, args):
        assert poison_extent % 32 == 0
        instrumentation = copy.copy(sp.STACK_POISON_BASE)

        for idx in range(0, int(poison_extent / 32)):
            args["off"] = ASAN_SHADOW_OFF + idx
            instrumentation.append(
                copy.copy(sp.STACK_UNPOISON_SLOT).format(**args))

        instrumentation.append("popq {clob1}")
        return "\n".join(instrumentation).format(**args)

    def instrument_stack(self):
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
                    need_red.append(addr)
                    break

        for addr in need_red:
            fn = self.rewriter.container.functions[addr]
            print("[*] %s needs redzone stack" % (fn.name))
            is_poisoned = False
            inserts = list()
            for idx, instruction in enumerate(fn.cache):
                if not is_poisoned:
                    if instruction.mnemonic != "subq":
                        continue
                    if instruction.cs.operands[1].reg != X86_REG_RSP:
                        continue
                    if instruction.cs.operands[0].type != CS_OP_IMM:
                        continue

                    # Ok, now we have the instruction that sets up the stack
                    # "sub $<const>, %rsp"
                    # Instrument our redzone here.
                    redzone_sz = self.stackrz_sz
                    instruction = "sub ${0}, %rsp".format(redzone_sz)

                    args = dict(
                        clob1="%rbx", pbase="{0}(%rsp)".format(redzone_sz))

                    poisoni = self.poison_stack(redzone_sz, args)
                    poisoni = instruction + "\n" + poisoni
                    icode = InstrumentedInstruction(poisoni, None, None)
                    inserts.append((idx, icode))
                    is_poisoned = True
                else:
                    # Look for all returns and jmps that exit this function
                    # and unpoison the stack before them.
                    # **ASSUMPTION:** At exit, we assume the stack is balanced,
                    # i.e., rsp has the same value as it did when we entered.
                    escapes_fn = False
                    if (CS_GRP_JUMP not in instruction.cs.groups
                            and CS_GRP_RET not in instruction.cs.groups):
                        continue

                    if CS_GRP_JUMP in instruction.cs.groups:
                        if instruction.cs.operands[0].type == CS_OP_IMM:
                            target = instruction.cs.operands[0].type
                            if not fn.start <= target < fn.start + fn.sz:
                                escapes_fn = True
                    else:
                        escapes_fn = True

                    if not escapes_fn:
                        continue

                    redzone_sz = self.stackrz_sz
                    instruction = "add ${0}, %rsp".format(redzone_sz)
                    args = dict(
                        clob1="%rbx", pbase="{0}(%rsp)".format(redzone_sz))

                    unpoisoni = self.unpoison_stack(redzone_sz, args)
                    unpoisoni = unpoisoni + "\n" + instruction
                    icode = InstrumentedInstruction(unpoisoni, None, None)
                    inserts.append((idx, icode))

            for idx, code in enumerate(inserts):
                fn.cache.insert(idx + code[0], code[1])

    def do_instrument(self):
        #self.instrument_globals()
        #self.instrument_stack()
        self.instrument_mem_accesses()
        self.instrument_init_array()

    def dump_stats(self):
        count = 0
        free_reg_sz = list()
        free_reg_cnt = defaultdict(lambda: 0)
        rflags_stats = [0, 0, 0, 0]

        for addr, sites in self.memcheck_sites.items():
            count += len(sites)
            fn = self.rewriter.container.functions[addr]
            for site in sites:
                regs = fn.analysis['free_registers'][site]

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
        print(np.bincount(free_reg_sz))
        print(json.dumps(free_reg_cnt))
        print(
            "rflags live: {}, rflags + 0 regs: {}, rflags + rax: {},".format(
                rflags_stats[0], rflags_stats[1], rflags_stats[2]),
            "rflags + >= 1 reg: {}".format(rflags_stats[3]))


class GlobalMetaData():
    ENT_SZ = 48

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
        ]

        return list(map(lambda x: DataCell.instrumented(x, 8), results))
