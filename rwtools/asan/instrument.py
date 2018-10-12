import copy
import math
from collections import defaultdict

from capstone.x86_const import X86_REG_RSP
from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_RET

import rwtools.asan.snippets as sp
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

    def _access16(self):
        raise NotImplementedError

    def instrument_mem_accesses(self):
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

                # XXX: THIS IS A TODO.
                if instruction.mnemonic.startswith("rep stos"):
                    print("[*] Skipping: {}".format(instruction))
                    continue

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
                    print("[*] Maybe missed an access: %s -- %d" %
                          (instruction, acsz))
                    continue

                args = dict()

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

                iinstr = InstrumentedInstruction(instrument % (args),
                                                 enter_lbl, str(instruction))

                # TODO: Replace original instruction for efficiency
                inserts.append((idx, iinstr))

            for idx, code in enumerate(inserts):
                fn.cache.insert(idx + code[0], code[1])

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
