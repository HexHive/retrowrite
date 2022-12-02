import argparse
import copy
import itertools
import io
import struct
import os
from collections import defaultdict, deque, OrderedDict

from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_CALL, CS_OP_MEM, CS_OP_REG
from capstone.x86_const import X86_REG_RIP

from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.enums import ENUM_RELOC_TYPE_AARCH64
from elftools.dwarf.callframe import FDE, CIE, ZERO, instruction_name
from elftools.dwarf.constants import *
from elftools.dwarf.enums import *
from elftools.dwarf.structs import DWARFStructs
from elftools.common.utils import struct_parse
from elftools.construct import Struct

from librw_arm64.util.logging import *
from librw_arm64.util.arm_util import _is_jump_conditional, is_reg_32bits, get_64bits_reg, memory_replace, get_access_size_arm, get_reg_size_arm
from librw_arm64.container import InstrumentedInstruction, Jumptable, TRAITOR_SECS
from librw_arm64.emulation import Path, Expr

# this needs to be not more than 128 MB (2^ 27)
# right now it is 64 MB (2 ^ 26)
FAKE_ELF_BASE = 0x4000000




class Rewriter():

    # if False, redirect every indirect branch to the landing pad,
    # with some minor additional overhead (recommended)
    # if True, some medium data flow analysis is conducted to detect
    # and symbolize jump tables. It works quite well but it is not 
    # guaranteed to find everything, and might lead to crashes in rare edge cases.
    detect_and_symbolize_switch_tables = False

    # if False, use call emulation to support C++ exceptions and other 
    # stack unwinding mechanisms. (e.g. we change a call to a push+jmp)
    # if True, we try to parse and detect LSDA tables. It works quite well
    # but might lead to failures in rewriting in rare edge cases
    detect_and_symbolize_lsda_tables = False

    # this option is to substitute a call with a push+jmp
    # to make the return address appear on the landing pad
    # for C++ exceptions and Go GC recovery
    emulate_calls = True


    # tell capstone to give us more details on the disassembly
    # like which registers are being read/written to
    detailed_disasm = False

    # This will register a signal handler that will catch reads to executable-only pages
    # it will also include all text sections another time, read-only, preserving their original
    # contents that the handler can read from and restore the correct value to
    data_text_support = False

    # This option, relevant only when data_text_support is True, will make it so the last 
    # code section will have its ending page-aligned. This is to minimize the calls to the segfault
    # handler for "valid" reads such as to .rodata on the same page as an executable page
    optimize_dtsupport_layout = False
    
    # disable exception handling recovery altogether. Useful when .cfi directives
    # generate linking errors.
    no_exceptions = False

    GCC_FUNCTIONS = [ # functions added by the compiler. No use in rewriting them
        # "_start",
        # "__libc_start_main",
        # "__libc_csu_fini",
        # "__libc_csu_init",
        # "__lib_csu_fini",
        # "_init",
        # "__libc_init_first",
        # "_fini",
        # "_rtld_fini",
        # "_exit",
        # "__get_pc_think_bx",
        # "__do_global_dtors_aux",
        # "__gmon_start",
        # "frame_dummy",
        # "__do_global_ctors_aux",
        # "__register_frame_info",
        # "deregister_tm_clones",
        # "register_tm_clones",
        # "__do_global_dtors_aux",
        # "__frame_dummy_init_array_entry",
        # "__init_array_start",
        # "__do_global_dtors_aux_fini_array_entry",
        # "__init_array_end",
        # "__stack_chk_fail",
        # "__cxa_atexit",
        # "__cxa_finalize",
        # "call_weak_fn" #not really sure about this, but imho we should'nt touch it
    ]

    GCC_RELOCATIONS = [ # relocations added by the compiler. Do not touch em!
        "__gmon_start__",
        "_ITM_deregisterTMCloneTable",
        "_ITM_registerTMCloneTable"
    ]

    # these sections need to be completely regenerated from scratch
    IGNORE_SECTIONS = [
        ".dynsym",
        ".dynstr",
        ".dynamic",
        ".interp",
        ".rela.plt",
        ".rela.dyn",
        ".gnu_version",
        ".gnu.version",
        ".gnu_version_r",
        ".gnu.version_r",
        ".eh_frame_hdr",
        ".eh_frame",
    ]

    # thread-local storage sections. Need special handling.
    TLS_SECTIONS = [
        ".tbss"
    ]

    literal_saves = 0
    total_globals = 0
    total_text = 0
    impossible_text = 0
    trivial_text = 0
    total_deleted_from_got = 0


    # DATASECTIONS = [".rodata", ".data", ".bss", ".data.rel.ro", ".init_array"]
    # DATASECTIONS = [".got", ".fini_array",  ".rodata", ".data", ".bss", ".data.rel.ro", ".init_array"]
    # DATASECTIONS = [".got", ".rodata", ".data", ".bss", ".data.rel.ro", ".init_array"]
    # DATASECTIONS = [".tm_clone_table", ".got", ".rodata", ".data", ".bss", ".data.rel.ro", ".init_array", ".fini_array", ".got.plt"]
    DATASECTIONS = [".tm_clone_table", ".got", ".rodata", ".data", ".bss", ".data.rel.ro", ".init_array", ".fini_array", ".got.plt"]
    CODESECTIONS = [".text", ".init", ".fini", ".plt"]

    def __init__(self, container, outfile):
        #XXX: remove global
        self.container = container
        self.outfile = outfile

        for sec, section in self.container.datasections.items():
            section.load()

        info("Disassembling...")
        for _, function in self.container.functions.items():
            if function.name in Rewriter.GCC_FUNCTIONS:
                container.ignore_function_addrs += [function.start]
                continue
            function.disasm()

    def symbolize(self):
        info("Symbolizing...")
        symb = Symbolizer()
        if not Rewriter.no_exceptions:
            symb.recover_eh_frame(self.container, None)
        symb.symbolize_data_sections(self.container, None)
        symb.symbolize_text_section(self.container, None)

    def install_segfault_handler(self):
        with open(os.path.join(os.path.dirname(__file__), '../rwtools_arm64/data_in_text/segfault_handler.s')) as f:
            code = f.read()

        # TODO:
        # this needs to be rewritten without libc (e.g., using only syscalls)
        # so we can avoid instrumenting main
        # and we can just instrument _start
        main_func = None
        for symbol in self.container.symbols:
            if symbol.name == "main":
                location = symbol.entry['st_value']
                main_func = self.container.functions[location]
                break
        else:
            print("Cannot install segfault handler, due to missing main symbol")
            return

        # we instrument the second instruction
        # so that we re-use the stack allocation done by main
        main_func.cache[0].instrument_before(InstrumentedInstruction(code))

        
    def store_copy_of_original_text(self, fd):
        fd.write(".original_sections_preserved:\n")
        codesecs = list(self.container.codesections.values())
        for e,section in enumerate(codesecs):
            fd.write(f"original_{section.name[1:]}_preserved:" + "\n")
            data = section.bytes
            for i in range(0, len(data), 4): # since it's code, divisible by 4
                fd.write(f".word {hex(int.from_bytes(data[i:i+4], 'little'))}\n")
            if e < len(codesecs) - 1 and section.base + section.sz < codesecs[e+1].base:
                for i in range(section.base + section.sz, codesecs[e+1].base, 4):
                    fd.write(".word 0x0\n")

        fd.write(".original_sections_end:\n")

    def dump(self):

        # we fix stuff that gets broken by too much instrumentation added,
        # like 'tbz' short jumps and jump tables.
        # it is *very* important that no further instrumentation is added from now!
        total_jumps_fixed = 0
        for _,function in self.container.functions.items():
            function.update_instruction_count()
            function.fix_literal_pools()
            total_jumps_fixed += function.fix_shortjumps()
            function.update_instruction_count()
            function.fix_jmptbl_size(self.container)
            if Rewriter.emulate_calls or self.container.loader.is_go_binary():
                function.emulate_calls()

        if total_jumps_fixed:
            info(f"Fixed a total of {total_jumps_fixed} short jumps")


        # print(len(self.container.functions))
        # if self.container.loader.is_stripped() and len(self.container.codesections['.text'].functions) == 1:
        # text_section = self.container.loader.elffile.get_section_by_name(".text")
        # text_fun = self.container.functions[text_section["sh_addr"]]
        start = self.container.loader.elffile.header["e_entry"]
        text_fun = self.container.function_of_address(start)
        if text_fun: # libraries might not have an entry point
            text_fun.cache[(start - text_fun.start) // 4].before.insert(0, InstrumentedInstruction(".globl _start\n_start:"))

        fd = open(self.outfile, 'w')
        for sec, section in sorted(
                self.container.datasections.items(), key=lambda x: x[1].base):
            if not section.name in Rewriter.TLS_SECTIONS:
                fd.write("%s" % (section) + "\n")
            else:
                fd.write(f".section {section.name}, \"aT\", @nobits" + "\n")
                for i in range(section.sz // 8):
                    fd.write(".quad 0" + "\n")
                for i in range(section.sz % 8):
                    fd.write(".byte 0" + "\n")


        # support data interleaved with text
        if Rewriter.data_text_support:
            self.install_segfault_handler()
            self.store_copy_of_original_text(fd)


        for section in self.container.codesections.values():
            fd.write(f".section {section.name}" + "\n")
            if section.name == ".plt": continue
            # results.append(f".align {section.align}") # removed to better fit sections
            data = section.bytes
            last_addr = base = section.base
            for faddr in sorted(section.functions):
                function = self.container.functions[faddr]
                for addr in range(last_addr, faddr): # fill in space between functions.
                    fd.write(".LC%x: // filler between functions" % (addr) + "\n")
                    fd.write(f"\t .byte {hex(data[addr - base])}" + "\n")
                last_addr = faddr + function.sz
                if function.name in Rewriter.GCC_FUNCTIONS:
                    continue
                fd.write("%s" % (function) + "\n")
            for addr in range(last_addr, section.base+section.sz): # fill in space between last function and section end
                fd.write(".LC%x: // filler between functions" % (addr) + "\n")
                fd.write(f"\t .byte {hex(data[addr - base])}" + "\n")


        # LANDING PAD
        for section in self.container.codesections.values():
            fd.write(f".section .fake{section.name}, \"ax\", @progbits" + "\n")
            # results.append(".align 12") # removed to better fit sections
            fd.write(f".fake{section.name}_start:" + "\n")
            last_addr = section.base - 4


            # the first option is based on heuristics (detection of jumptables)
            # partial landing pad (only on function starts)
            if Rewriter.detect_and_symbolize_switch_tables and len(section.functions) > 1:
                for faddr in sorted(section.functions):
                    function = self.container.functions[faddr]
                    if function.name in Rewriter.GCC_FUNCTIONS:
                        continue
                    skip = function.start - last_addr - 4
                    if Rewriter.detect_and_symbolize_switch_tables:
                        # if we symbolize jump tables, we know that the targets that will
                        # land in the landing pad will only be indirect calls. So it does
                        # not make sense to have every possible instruction in the landing pad.
                        if skip > 0: fd.write(".skip 0x%x" % (skip) + "\n")
                    last_addr = function.start
                    fd.write("b .LC%x // %s" % (function.start, function.name) + "\n")
            # this option here is full landing pad
            # 100% safe but slightly higher overhead
            else: # stripped binary maybe
                if section.name == ".plt":
                    for i in range(0, section.sz, 4):
                        # the plt is autogenerated, so we don't have a label there
                        # we just use the .plt section symbol
                        fd.write("b .plt+%d " % (i) + "\n")
                else:
                    print(section.name, hex(section.sz))
                    for i in range(0, section.sz, 4):
                        addr = section.base + i
                        if Rewriter.emulate_calls:
                            if addr in section.functions:
                                fd.write(".cfi_startproc\n")
                            if addr in self.container.global_cfi_map:
                                fd.write("\n".join(self.container.global_cfi_map[addr]) + "\n")
                        fd.write("b .LC%x " % (addr) + "\n")
                        if Rewriter.emulate_calls:
                            if addr+4 in section.functions_ends:
                                fd.write(".cfi_endproc\n")
                continue


        # we need one fake section just to represent the copy of the base address of the binary
        fd.write(f".section .fake.elf_header, \"a\", @progbits" + "\n")

        # add weak symbols
        for symbol in self.container.symbols:
            if "@@" in symbol.name: continue
            if symbol['st_info']['bind'] == "STB_WEAK" or \
                    (symbol.secname == ".dynsym" and symbol['st_info']['type'] == "STT_OBJECT"):
                fd.write(".weak " + symbol.name + "\n")

        global FAKE_ELF_BASE
        if not self.container.loader.is_pie():
            FAKE_ELF_BASE = 0

        if Rewriter.data_text_support and Rewriter.optimize_dtsupport_layout:
            # if we want to support data inside text, some weird shenanigans
            # will happen with mprotect, due to general linker/loader brokennes
            # that put sections with different permissions on the same page
            codesecs = []
            for name, section in self.container.codesections.items():
                codesecs += [(section.base, section.base + section.sz, name)]
            codesecs = sorted(codesecs)
            info("Rebasing FAKE_ELF_BASE such that section {codesecs[-1][2]} ends at a page-aligned address")
            FAKE_ELF_BASE -= sorted(codesecs)[-1][1]

        # here we insert the list of the original addresses of the sections
        # so that we keep them the same during linking and reproduce the virtual layout
        fd.write(f"// SECTION: .fake.elf_header - {hex(FAKE_ELF_BASE)}" + "\n")
        def force_section_addr(name, base, fd, padding=0):
            fd.write(f"// SECTION: {name} - {hex(base)}" + "\n")

        for sec in self.container.datasections.values():
            if sec.name in TRAITOR_SECS:
                force_section_addr(".fake"+sec.name, FAKE_ELF_BASE + sec.base, fd)
            # if sec.name in XXX_TRAITOR_SECS:
                # force_section_addr(".o"+sec.name[2:], sec.base, fd)
        for sec in self.container.codesections.values():
            force_section_addr(".fake"+sec.name, FAKE_ELF_BASE + sec.base, fd)

        if not self.container.loader.is_pie():
            FAKE_ELF_BASE = 0x2000000
            for e, sec in enumerate(self.container.datasections.values()):
                if sec.name in Rewriter.TLS_SECTIONS: continue
                if sec.name in TRAITOR_SECS:
                    force_section_addr(sec.name, (FAKE_ELF_BASE + sec.base + 0x10000*e) & 0xffffffffffffff00, fd)
                else:
                    force_section_addr(sec.name, sec.base, fd) # all other sections exactly where they were
            for sec in self.container.codesections.values():
                if ".text" in sec.name:
                    force_section_addr(sec.name, 2*FAKE_ELF_BASE + sec.base, fd)
                elif ".plt" in sec.name:
                    force_section_addr(sec.name, (int(1.1*FAKE_ELF_BASE) & 0xffffffffffffff00) + sec.base, fd)
                else:
                    force_section_addr(sec.name, FAKE_ELF_BASE + sec.base, fd)
            fd.write(f"// SECTION: .dynamic - {hex(3*FAKE_ELF_BASE)}" + "\n")
            fd.write(f"// SECTION: .rela.plt - {hex(int(1.5*FAKE_ELF_BASE))}" + "\n")
            fd.write(f"// SECTION: .eh_frame - {hex(int(0.8*FAKE_ELF_BASE))}" + "\n") 
            fd.write(f"// SECTION: .gnu.hash - {hex(int(0.7*FAKE_ELF_BASE))}" + "\n")
            fd.write(f"// SECTION: .note.gnu.build-id - {hex(int(0.6*FAKE_ELF_BASE))}" + "\n")
            fd.write(f"// NOPIE" + "\n")

        # here we insert the list of dependencies of the elf,
        # that the linker will need to know about through lflags
        for dep in self.container.loader.dependencies:
            fd.write(f"// DEPENDENCY: {dep}" + "\n")

        fd.close()

        if Rewriter.literal_saves != Rewriter.total_globals:
            info(f"Saved {Rewriter.literal_saves} out of {Rewriter.total_globals} global accesses ({Rewriter.literal_saves / Rewriter.total_globals * 100}% )")
            info(f"Out of {Rewriter.total_text} code pointers, {Rewriter.impossible_text} cannot be saved (of which {Rewriter.impossible_text - Rewriter.trivial_text} are non-trivial, in total {(Rewriter.impossible_text - Rewriter.trivial_text) / Rewriter.total_globals * 100}%) ")
        info(f"Success: retrowritten assembly to {self.outfile}")


# old, needed section alignment
class Symbolizer():
    def __init__(self):
        self.bases = set()
        self.xrefs = defaultdict(list)
        self.symbolized = set()

    # TODO: Use named symbols instead of generic labels when possible.
    # TODO: Replace generic call labels with function names instead
    def symbolize_text_section(self, container, context):
        # Symbolize using relocation information.
        # for rel in container.relocations[".text"]:
        code_relocations = list(map(lambda x: container.relocations[x], Rewriter.CODESECTIONS))
        for rel in list(itertools.chain.from_iterable(code_relocations)):
            fn = container.function_of_address(rel['offset'])
            if not fn or fn.name in Rewriter.GCC_FUNCTIONS:
                continue

            inst = fn.instruction_of_address(rel['offset'])
            if not inst:
                continue

            # Fix up imports
            if "@" in rel['name']:
                suffix = ""
                if rel['st_value'] == 0:
                    suffix = "@PLT"

                # XXX: ARM
                if len(inst.cs.operands) == 1:
                    inst.op_str = "%s%s" % (rel['name'].split("@")[0], suffix)
                else:
                    # Figure out which argument needs to be
                    # converted to a symbol.
                    if suffix:
                        suffix = "@PLT"
                    mem_access, _ = inst.get_mem_access_op()
                    if not mem_access:
                        continue
                    value = hex(mem_access.disp)
                    inst.op_str = inst.op_str.replace(
                        value, "%s%s" % (rel['name'].split("@")[0], suffix))
            else:
                mem_access, _ = inst.get_mem_access_op()
                if not mem_access:
                    # These are probably calls?
                    continue

                # XXX: ARM
                if (rel['type'] in [
                        ENUM_RELOC_TYPE_x64["R_X86_64_PLT32"],
                        ENUM_RELOC_TYPE_x64["R_X86_64_PC32"]
                ]):

                    value = mem_access.disp
                    ripbase = inst.address + inst.sz
                    inst.op_str = inst.op_str.replace(
                        hex(value), ".LC%x" % (ripbase + value))
                    if ".rodata" in rel["name"]:
                        self.bases.add(ripbase + value)
                else:
                    print("[*] Possible incorrect handling of relocation!")
                    value = mem_access.disp
                    inst.op_str = inst.op_str.replace(
                        hex(value), ".LC%x" % (rel['st_value']))

            self.symbolized.add(inst.address)

        self.symbolize_cf_transfer(container, context)
        # Symbolize remaining memory accesses

        if Rewriter.detect_and_symbolize_switch_tables:
            self.symbolize_switch_tables(container, context) # not needed anymore due to jmptable landing
        self.symbolize_mem_accesses(container, context)



    def symbolize_cf_transfer(self, container, context=None):
        for _, function in container.functions.items():
            function.addr_to_idx = dict()
            for inst_idx, instruction in enumerate(function.cache):
                function.addr_to_idx[instruction.address] = inst_idx

            for inst_idx, instruction in enumerate(function.cache):
                is_call = instruction.cs.mnemonic in ["bl", "blr"]
                is_jmp = instruction.cs.mnemonic in ['tbz', 'tbnz', 'cbz', 'cbnz', 'b'] \
                        or instruction.mnemonic.startswith("b.")

                if not (is_jmp or is_call):
                    # https://idasuckless.github.io/the-brk-is-a-lie.html
                    if instruction.mnemonic == "brk":
                        function.nexts[inst_idx] = []
                    elif instruction.mnemonic.startswith('ret'):
                        function.nexts[inst_idx].append("ret")
                        instruction.cf_leaves_fn = True
                    # otherwise, if it's a normal istruction, just go to the next
                    else:
                        function.nexts[inst_idx].append(inst_idx + 1)
                    continue

                instruction.cf_leaves_fn = False

                if is_jmp and _is_jump_conditional(instruction.mnemonic):
                    if inst_idx + 1 < len(function.cache):
                        # Add natural flow edge
                        function.nexts[inst_idx].append(inst_idx + 1)
                    else:
                        # Out of function bounds, no idea what to do!
                        function.nexts[inst_idx].append("undef")
                elif is_call:
                    instruction.cf_leaves_fn = True
                    function.nexts[inst_idx].append("call")
                    if inst_idx + 1 < len(function.cache):
                        function.nexts[inst_idx].append(inst_idx + 1)
                    else:
                        # Out of function bounds, no idea what to do!
                        function.nexts[inst_idx].append("undef")

                target = 0
                if instruction.cs.mnemonic in ["br", "blr"]: # br x0
                    function.possible_switches += [instruction.address]
                else: 
                    target = int(instruction.cs.op_str.split('#')[-1], 16) # b #0xf20

                if target:
                    # Check if the target is in a code section.
                    # we exclude .plt as it means it's a call to an imported function
                    if any([container.is_in_section(x, target) for x in Rewriter.CODESECTIONS if x != ".plt"]):
                        function.bbstarts.add(target)
                        instruction.op_str = instruction.op_str.replace("#0x%x" % target, ".LC%x" % target)
                    elif target in container.plt:
                        name = container.plt[target]
                        instruction.op_str = "{}".format(name)
                        if any(exit in name for exit in ["abort", "exit"]): #XXX: fix this ugly hack
                            function.nexts[inst_idx] = []
                    else:
                        critical(str(instruction) + " - target outside code section!")
                        exit(1)
                        # gotent = container.is_target_gotplt(target)
                        # if gotent:
                            # found = False
                            # for relocation in container.relocations[".dyn"]:
                                # if gotent == relocation['offset']:
                                    # instruction.op_str = "{}@PLT".format(
                                        # relocation['name'])
                                    # found = True
                                    # break
                            # if not found:
                                # print("[x] Missed GOT entry!")
                        # else:
                            # print("[x] Missed call target: %x" % (target))

                    if is_jmp:
                        if target in function.addr_to_idx:
                            idx = function.addr_to_idx[target]
                            function.nexts[inst_idx].append(idx)
                        else:
                            instruction.cf_leaves_fn = True
                            function.nexts[inst_idx].append("undef")
                elif is_jmp:
                    function.nexts[inst_idx].append("undef")

        # after we're done, we prepare the prevs list
        self.reverse_nexts(container)

    def reverse_nexts(self, container):
        for _, function in container.functions.items():
            function.prevs = defaultdict(list)
            for idx, nexts in function.nexts.items():
                for nexti in nexts:
                    function.prevs[nexti] = function.prevs.get(nexti, [])
                    function.prevs[nexti].append(idx)

    def resolve_register_value(self, register, function, instr, max_steps=1e6):
        debug(f"Instructions leading up to {hex(instr.address)}")
        inst_idx = function.addr_to_idx[instr.address]
        reg_name = instr.cs.reg_name(register)
        visited = [False]*len(function.cache)
        paths = [Path(function, inst_idx, reg_pool=[reg_name], exprvalue=f"{reg_name}", visited=visited)]
        paths_finished = []
        while len(paths) > 0:
            p = paths[0]
            p.steps += 1
            prevs = function.prevs[p.inst_idx]

            # XXX: fix the ugly 'x' in p.expr hack
            if p.inst_idx == 0 or p.visited[p.inst_idx] or p.steps > max_steps or \
            len(prevs) == 0 or (len(p.reg_pool) == 0 and 'x' not in str(p.expr)):  # we got to the start of the function 
                paths_finished += [paths[0]]
                debug("finished path")
                del paths[0]
                continue

            p.visited[p.inst_idx] = True
            if len(prevs) > 1:
                debug(f"MULTIPLE prevs:  {[hex(function.cache[i].address) for i in prevs]}")
                #XXX: add other paths here
            p.inst_idx = prevs[0]
            instr = function.cache[p.inst_idx]
            regs_write = instr.reg_writes_common()
            # if any([reg in p.reg_pool for reg in regs_write]):

            new_paths = p.emulate(instr)

            if new_paths:
                for pp in new_paths:
                    paths += [pp]

        for p in paths_finished:
            p.expr.simplify()
            debug("FINAL " + str(p.expr))
            return p.expr

    def _memory_read(self, container, addr, size, signed=False):
        sec = container.section_of_address(addr)
        if sec.name != ".rodata": 
            debug(f"WARNING: changing value not in rodata but in {sec.name}")
        return sec.read_at(addr, size, signed)

    def _guess_cases_number(self, container, function, addr):
        max_instrs_before_switch = 30
        start_idx = function.addr_to_idx[addr]
        instr = function.cache[start_idx]
        found = -1
        reg_index = False
        class path:
            def __init__(self, steps=0, reg_index=False, found=-1, idx=start_idx):
                self.steps = steps
                self.reg_index = reg_index
                self.found = found
                self.inst_idx = idx

        paths = [path()]
        paths_finished = []
        while len(paths):
            p = paths[0]
            p.steps += 1
            prevs = function.prevs[p.inst_idx]
            if p.inst_idx == 0 or len(prevs) == 0 or p.steps > max_instrs_before_switch:
                paths_finished += [paths.pop(0)]
                continue
            debug(f"taking path at {hex(function.cache[p.inst_idx].address)}, total paths {len(paths)}")

            for i in prevs:
                debug(f"MULTIPLE prevs: {[hex(function.cache[i].address) for i in prevs]}")

            p.inst_idx = prevs[0]
            instr = function.cache[p.inst_idx]



            if instr.mnemonic.startswith("ldr") and not p.reg_index:
                mem, mem_op_idx = instr.get_mem_access_op()
                if mem.index: p.reg_index = mem.index
            if instr.mnemonic.startswith("cmp") and p.reg_index:
                if instr.cs.operands[0].reg == p.reg_index and \
                   instr.cs.operands[1].type == CS_OP_IMM:
                    p.found = instr.cs.operands[1].imm
                    # adjustments for differenct comparisons
                    # we try to look for the next jump and decide
                    for i in range(10):
                        next_instr = function.cache[p.inst_idx + i]
                        if not next_instr: 
                            break
                        is_jmp = CS_GRP_JUMP in next_instr.cs.groups
                        if is_jmp:
                            if next_instr.mnemonic in ["b.hi", "b.ls", "b.le"]:
                                p.found += 1
                            break
                    # if next_instr and next_instr.mnemonic in ["b.lt"]: p.found -= 1
                    paths_finished += [paths.pop(0)]
                    debug("found path " +  str(len(paths)))
                    continue
            if instr.mnemonic == "movz" and instr.cs.operands[0].reg == p.reg_index:
                # if the register is written with a constant value, we just ignore this path
                paths.pop(0)
                continue
            if instr.mnemonic == "mov" and instr.cs.operands[0].reg == p.reg_index:
                # if the register is substitued by another register, it might be the comparison
                # is done on the new one, so we start another path form scratch with that reg
                paths.pop(0)
                paths += [path(p.steps, instr.cs.operands[1].reg, -1, start_idx)]
                continue

            for prev in prevs[1:]:
                debug("adding path", hex(function.cache[prev].address), instr.cs.reg_name(p.reg_index))
                paths += [path(p.steps, p.reg_index, p.found, prev)]

        debug(f"number of cases: {[p.found for p in paths_finished]}")
        true_paths_finished = list(filter(lambda x: x.found != -1, paths_finished))
        if len(true_paths_finished) != len(paths_finished):
            critical(f"Some paths not concluded while guessing cases number for switch at {addr}!")
        if any([p.found != true_paths_finished[0].found for p in true_paths_finished]):
            return -1 # if there are inconsistencies, we quit!
        return true_paths_finished[0].found

    def symbolize_switch_tables(self, container, context):
        rodata = container.datasections.get(".rodata", None)
        if not rodata:
            assert False
        for _, function in container.functions.items():
            for jump in function.possible_switches:
                # we do two tries, changing the number of instructions to analyze before the switch
                # if 20 are enough, then good, otherwise we perform a much deeper analysis. 
                # this is because _very rarely_ too much analysis can break, so we prefer to keep it low if possible
                # an example is the br at 0x77e970 in the gcc_r spec cpu2017 benchmark, it breaks if tries > 50
                for tries in [20, 1000]:
                    inst_idx = function.addr_to_idx[jump]
                    instr = function.cache[inst_idx]
                    reg = instr.cs.operands[0].reg
                    debug(f"Analyzing switch on {instr.cs}, {instr.cs.reg_name(reg)}")
                    expr = self.resolve_register_value(reg, function, instr, max_steps=tries)
                    # print(instr.cs, expr)

                    # Super advanced pattern matching

                    # addr
                    if isinstance(expr.left, int):
                        debug(f"Found a blr at {instr.cs} but it is really a call to {hex(expr.left)}! - ignoring for now")
                        continue

                    # x0
                    if isinstance(expr.left, str):
                        continue

                    # [addr]
                    elif expr.left.mem and expr.left.right == None: 
                        # addr = int(str(expr.left.left))
                        # value = self._memory_read(container, addr, 8)
                        # swlbl = ".LC%x" % (value,)
                        # memory_replace(container, addr, 8, swlbl)
                        continue

                    # addr + ... (no register present in expression)
                    # if all([c not in str(expr) for c in ['x', 'w']]): 
                        # continue

                    # first_case_addr + [ jmptbl_addr + ??? ]
                    elif isinstance(expr.left.right, Expr) and expr.left.right.left \
                        and isinstance(expr.left.right.left, Expr) and expr.left.right.left.mem\
                        and isinstance(expr.left.right.left.left, int):
                        try: #XXX remove this try catch and uncomment (and fix) above expression about not having registers
                             # probably you need to implement multiple path traversal in the switch detection
                            base_case = expr.left.left
                            debug(f"BASE CASE: {base_case}")
                            size = expr.left.right.left.mem
                            jmptbl_addr = int(str(expr.left.right.left.left))
                            shift = expr.left.right.right
                            debug(f"SHIFT: {shift}")
                            debug(f"JMPTBL: {jmptbl_addr}")
                            debug(f"SIZE: {size}")

                            cases = self._guess_cases_number(container, function, instr.address)
                            debug(f"CASES: {cases}")
                            if cases == -1:
                                assert False

                            cases_list = []

                            for i in range(cases):
                                value = self._memory_read(container, jmptbl_addr + i*size, size, signed=True)
                                debug("VALUE:" + str(value))
                                addr = base_case + value*(2**shift)
                                swlbl = "(.LC%x-.LC%x)/%d" % (addr, base_case, 2**shift)
                                memory_replace(container, jmptbl_addr + i*size, size, swlbl)
                                cases_list += [addr]

                            debug(f"Found jmptbl at {hex(instr.address)}, loc {hex(jmptbl_addr)}, size {size}, base_case {base_case}")
                            function.add_switch(Jumptable(instr.address, jmptbl_addr, size, base_case, cases_list))
                            break
                        except:
                            critical(f"JUMP TABLE at {hex(instr.address)} recognized but failed to symbolize!")
                            continue

                    else:
                        info(f"JUMP TABLE at {hex(instr.address)} impossible to recognize!")
                        info(f"Potential crashes in function {function.name}")
                        info(f"final expression: {expr}")



    def _adjust_target(self, container, target):
        # Find the nearest section
        sec = None
        for sname, sval in sorted(
                container.datasections.items(), key=lambda x: x[1].base):
            if sval.base >= target:
                break
            sec = sval

        assert sec is not None

        end = sec.base  # + sec.sz - 1
        adjust = target - end

        assert adjust > 0

        return end, adjust

    def _is_target_in_region(self, container, target):
        for sec, sval in container.datasections.items():
            if sval.base <= target < sval.base + sval.sz:
                return True

        for fn, fval in container.functions.items():
            if fval.start <= target < fval.start + fval.sz:
                return True

        return False

    def _adjust_adrp_section_pointer_litpools(self, container, secname, orig_off, instruction):
        # we adjust things like adrp x0, 0x10000 (start of .bss)
        # to stuff like  ldr x0, =(.bss - (offset))
        # to make global variables work
        assert instruction.mnemonic.startswith("adr")
        base = container.datasections[secname].base
        reg_name = instruction.reg_writes()[0]
        diff = base - orig_off
        op = '-' if diff > 0 else '+'
        # if secname == ".got": secname = ".fake_got" # the got is special, as it
        secname = secname + "_start"
        # will get overwritten by the compiler after reassembly. We introduce a 
        # "fake_got" label so that we keep track of where the "old" got section was
        instruction.mnemonic = "ldr"
        instruction.op_str = "%s, =(%s %c 0x%x)"  % (reg_name, secname, op, abs(diff))
        instruction.instrumented = True

    def _adjust_adrp_section_pointer(self, container, secname, orig_off, instruction):
        assert instruction.mnemonic.startswith("adr")
        Rewriter.literal_saves += 1
        if secname in container.codesections:
            base = container.codesections[secname].base
            secname = f".fake{secname}"
        else:
            base = container.datasections[secname].base
        reg_name = instruction.op_str.split(",")[0]


        # old
        # diff = base - orig_off
        # op = '-' if diff > 0 else '+'
        # secname = secname + "_start"
        # pages = (abs(diff) // 0x1000) * 0x1000
        # instruction.instrument_before(InstrumentedInstruction(f"\tadrp {reg_name}, ({secname} {op} {pages})"))
        # instruction.mnemonic = "add" if op == "+" else "sub"
        # instruction.op_str = "%s, %s, %s"  % (reg_name, reg_name, hex(abs(diff) % 4096))

        # new
        diff = base
        op = '+'
        secname = ".fake.elf_header"
        pages = orig_off

        instruction.mnemonic = "adrp"
        instruction.op_str = f"{reg_name}, ({secname} {op} {hex(pages)})"

        if Rewriter.data_text_support:
            instruction.instrument_after(
                    InstrumentedInstruction(f"\tadd {reg_name}, {reg_name}, :lo12:{secname} // bruh"))


    def _get_resolved_address(self, function, inst, inst2, path):
        if inst2.cs.mnemonic == "add":
            if not inst2.cs.operands[2].type == CS_OP_IMM:
                return 0
            assert all([op.shift.value == 0 for op in inst2.cs.operands])
            return path.orig_off + inst2.cs.operands[2].imm
        elif inst2.cs.mnemonic.startswith("mov"):
            return inst2.cs.reg_name(inst2.cs.operands[0].reg) # moved to a different reg, new path
        elif inst2.cs.mnemonic.startswith("ldr"):
            assert inst2.cs.operands[1].type == CS_OP_MEM
            if not all([op.shift.value == 0 for op in inst2.cs.operands]):
                return 0
            return path.orig_off + inst2.cs.operands[1].mem.disp
        elif inst2.cs.mnemonic.startswith("str"):
            if inst2.cs.reg_name(inst2.cs.operands[0].reg) == path.orig_reg: # str <orig_reg>, [...]
                if not inst2.cs.reg_name(inst2.cs.operands[1].reg) == "x29":
                    # assert False
                    return 0
                expr = self.resolve_register_value(inst2.cs.operands[0].reg, function, inst2)
                if not isinstance(expr.left, int):
                    return 0
                return (expr.left, inst2.cs.operands[1].mem.disp)
            else:
                if inst2.cs.operands[1].mem.disp != 0: # str ..., [<orig_reg> + ...]
                    return path.orig_off + inst2.cs.operands[1].mem.disp
                else: # str ..., [<orig_reg> + <unknown_reg>]
                    return 0
        elif inst2.cs.mnemonic.startswith("stp"):
            if inst2.cs.reg_name(inst2.cs.operands[0].reg) == path.orig_reg: # stp <orig_reg>, ..., [...]
                op_num, adding = 0, 0
            elif inst2.cs.reg_name(inst2.cs.operands[1].reg) == path.orig_reg: # stp ..., <orig_reg>, [...]
                op_num, adding = 1, get_access_size_arm(inst2.cs)[0] // 2
            else: # stp ..., [<orig_reg> + ...]
                return path.orig_off + inst2.cs.operands[1].mem.disp

            mem, mem_op_idx = inst2.get_mem_access_op()
            if not inst2.cs.reg_name(mem.base) == "x29":
                return 0
            expr = self.resolve_register_value(inst2.cs.operands[op_num].reg, function, inst2)
            if not isinstance(expr.left, int):
                return 0
            return (expr.left, mem.disp + adding)
        else:
            return 0


    def _adjust_global_access(self, container, function, edx, inst):
        # there is an adrp somewhere in the code, this means global variable...
        # global variable addresses are dynamically built in multiple instructions
        # here we try to resolve the address with some capstone trickery and shady assumptions

        Rewriter.total_globals += 1

        orig_off = int(inst.cs.op_str.split("#")[-1], 16)
        orig_reg = inst.cs.op_str.split(',')[0]


        possible_sections = []
        for name,s in list(container.datasections.items()) + list(container.codesections.items()):
            if s.base // 0x1000 == orig_off // 0x1000 or \
               s.base <= orig_off < s.base + s.sz:
                possible_sections += [name]



        # WHAT TO DO
        # so actually this was never implemented? Not sure. I vividly remember testing it though...
        # well, now off to work!




        # WHAT TO DO PART 2
        # part 3
        # ok no to be honest you just need to pass the -lm flag
        # to gcc and he will fix .dynamic for you
        # now the only section that is "wobbly" is the .got.
        # how are we gonna fix the got? Not sure lol

        # WHAT TO DO PART 3
        # updates from the .got: it's the relocations baby
        # is it unsolvable? not sure
        # also I get crashes bc I removed the minimum alignment of 12

        # WHAT TO DO 4
        # adrp has now become 3 instructions, it sucks, but I think I can 
        # do better. let's now try fixing the .got

        # WHAT TO DO 5
        # .got is basically done! amazing job. 
        # it is a super bad hack though
        # on the test binary there is still some difference in the size
        # of .dynamic sections. Need to look into that.

        # WHAT TO DO 6
        # Now .dynamic is also done! YES
        # All that's left is to now enable across-section pointer
        # constructions and debug them until they work 
        # Still need to look into the adrp being 3 instructions though

        # WHAT TO DO 7
        # this is broken
        # the removal of symbol _GLOBAL_OFFSET_TABLE_ was not a good strategy
        # as gcc adds it back BUT IN THE WRONG PLACE, so stuff in .got is offset
        # lmao
        # allora aggiungere un .quad 0 all'inizio della got_start funziona
        # aggiusta i pointer ma c'e' il problema che ora la size della .got
        # e' sbagliata


        # WHAT TO DO 8
        # everything is super broken
        # need to scratch previous solution
        # lmao
        # now need to use fake_got, fake_bss, and so on
        # need to do:
        # 1. append original section address information at the end of assembly file
        # 2. parse them and append linker flags to gcc in retrowrite -a
        # 3. Re-enable cross section pointer constructions (now disabled) 


        # WHAT TO DO 8
        # Brokenness, destruction, crashes and sigsegvs
        # is everything I see around me
        # all hope is lost, 
        # only one thing comes to my mind
        # 1. Data sections need to be absolutely in sync with the old binary
        # 2. except .got and shit that we do fake
        # 3. when a pointer is a code pointer, it will eventually be called with bl
        # 4. at this point we do the transformation (and maybe, CFI), 
        # 5. SOMEHOW we can calculate back the original address that was in the binary 
        # 6. the adrps in the code cannot use an absolute address. they need a label. obviously.
        #    they need a label from the start of a binary. or maybe we define a place where virtual
        #    space layout replication begins and we go from there.
        # 7. The "hashmap" is now an array. Super slow. Please fix it.







        text = container.text_section # check for .text, as it is not a datasection
        ### FIXME
        ### WARNING:
        ### the text['sh_size'] - 0x320 down below is needed to fix adrp's at
        ### 0x7073e4 and 0x6d8444 and 0x775470 in cpugcc_r, because
        ### they point to .rodata but they also overlap in 0x31c with the .text
        ### since heuristics are broken for the above adrp. We decide to ignore
        ### the last 0x320 bytes of the text as a partial workaround
        ### this will be fixed with the .fake_text directly followed by .rodota
        ### mimicking the same section layout of the original binary
        ### when I get to implement heuristics-free global pointer constructions
        ### XXX
        # if text['sh_addr'] // 0x1000 == orig_off // 0x1000 or \
            # text['sh_addr'] <= orig_off < text['sh_addr'] + text['sh_size'] - 0x320:
            # possible_sections += ['.text']

        if len(possible_sections) == 0:
            critical(f"No possible section found for {inst}. Might be data inside text?")
            exit(1)

        # self._adjust_adrp_section_pointer(container, possible_sections[0], orig_off, inst)
        # return

        if len(possible_sections) >= 1:
            secname = possible_sections[0]
            # even if it's text, we rewrite it
            self._adjust_adrp_section_pointer(container, secname, orig_off, inst)
            return

            # self._adjust_adrp_section_pointer(container, secname, orig_off, inst)
            # return

        # assert(False)

        # if possible_sections[0] == '.data' and possible_sections[1] == '.bss':
            # self._adjust_adrp_section_pointer(container, possible_sections[0], orig_off, inst)
            # return

        # if possible_sections[0] == '.rodata' and possible_sections[1] == '.text' and possible_sections[2] == '.fini':
            # self._adjust_adrp_section_pointer(container, possible_sections[0], orig_off, inst)
            # return

        # if possible_sections == ['.init_array', '.fini_array', '.data.rel.ro', '.got']:
            # debug(f"Skipping shit at {hex(inst.address)}")
            # self._adjust_adrp_section_pointer(container, possible_sections[0], orig_off, inst)
            # return

        debug(f"Global access at {inst}, multiple sections possible: {possible_sections}, trying to resolve address...")

        # if we got here, it's bad, as we're not sure which section the global variable is in.
        # We try to resolve all possible addresses by simulating all possible control flow paths.
        # we will also track down stack pushes of global pointers because they can be loaded later

        class path:
            def __init__(self, orig_reg="x0", idx=0, stack_stores=[], orig_off=orig_off,
                               visited={}, function=function):
                self.stack_stores = stack_stores
                self.orig_reg = orig_reg
                self.idx = idx
                self.orig_off = orig_off
                self.visited = visited
                self.function = function

        resolved_addresses = []
        paths = [path(orig_reg, nexti, [], visited=defaultdict(lambda: False)) for nexti in function.nexts[edx]]
        while len(paths):
            p = paths[0]
            inst2 = p.function.cache[p.idx]
            if p.visited[inst2.address]:
                del paths[0]
                continue
            p.visited[inst2.address] = 1

            # check if someone is overwriting one of the saved global pointers on the stack
            # XXX: add support for stp
            if inst2.mnemonic == "str" and inst2.cs.reg_name(inst2.cs.operands[1].reg) == "x29" and\
                    inst2.cs.operands[1].mem.disp in p.stack_stores:
                p.stack_stores.remove(inst2.cs.operands[1].mem.disp)

            # check if we are loading a previously saved global pointer from the stack
            # XXX: add support for ldp
            if inst2.mnemonic == "ldr" and inst2.cs.reg_name(inst2.cs.operands[1].reg) == "x29" and\
                    inst2.cs.operands[1].mem.disp in p.stack_stores:
                debug(f"Found stack load at {inst2}, from {inst}!")
                new_reg = inst2.cs.reg_name(inst2.cs.operands[0].reg)
                paths.append(path(new_reg, p.idx + 1, [], p.orig_off, copy.deepcopy(p.visited)))

            if p.orig_reg in inst2.reg_reads():
                if inst2.instrumented or '=' in inst2.op_str:  # XXX: ugly hack to avoid reinstrumenting instructions
                    del paths[0]
                    continue
                raddr = self._get_resolved_address(p.function, inst, inst2, p)
                if isinstance(raddr, tuple):  # a global pointer was pushed on the stack
                    addr, disp = raddr
                    debug(f"Found new stack store at addr {inst2} from {inst}")
                    p.stack_stores += [disp]
                elif isinstance(raddr, str):  # the register we're tracking has been changed
                    paths.append(path(raddr, p.idx + 1, p.stack_stores[:], p.orig_off, copy.deepcopy(p.visited), function))
                elif raddr:                   # a global pointer was just used normally 
                    resolved_addresses += [(inst2, raddr, p.orig_reg)]
                else:
                    critical(f"Missed global resolved address on {inst2} from {inst}")

            if p.orig_reg in inst2.reg_writes_common():
                if len(p.stack_stores) == 0:
                    del paths[0] # we overwrote the register we're trying to resolve, so abandon this path
                    continue
                else:  # unless we pushed it on the stack
                    p.orig_reg = "None"

            if inst2.mnemonic == "b" and inst2.cs.operands[0].type == CS_OP_IMM:
                # we go across functions!
                # Some restrictions: 1. only through direct jumps 2. do not go back to the original func
                # otherwise we will get stuck in infinite loops
                fun2 = container.function_of_address(inst2.cs.operands[0].imm)
                if fun2 != None and fun2.start != p.function.start:
                    idx = fun2.addr_to_idx[inst2.cs.operands[0].imm]
                    debug(f"Found new trampoline at {inst2} from {inst}")
                    p.function = fun2
                    p.idx = idx
                    # paths.append(path(p.orig_reg, idx, p.stack_stores[:], p.orig_off, p.visited, fun2))

                    # del paths[0]
                    continue

            # print(p.function.nexts[p.idx])
            next_instrs = list(filter(lambda x: isinstance(x, int), p.function.nexts[p.idx]))
            if len(next_instrs) == 0:
                del paths[0]
                continue
            p.idx = next_instrs[0]
            for n in next_instrs[1:]:
                # if n < idx: continue
                if not isinstance(n, int): continue
                if n == 0: continue # avoid recursive calls to same function
                if p.visited[p.function.cache[n].address]: continue
                # count = list(filter(lambda x: x == 1, p.visited))
                # debug(f"Appending to {n}, {len(paths)}, {len(count)}")
                paths.append(path(p.orig_reg, n, p.stack_stores[:], p.orig_off, p.visited, p.function))



        possible_sections = set()
        for r in resolved_addresses[:]:
            (i, addr) = r[0], r[1]
            sec = container.section_of_address(addr)
            if sec:
                debug(f"to_fix: {i.cs}, in section {sec.name}")
                possible_sections.add(sec.name)
            else:
                critical(f"WARNING: no section for resolved addr {hex(addr)} at {i.cs}, ignoring")
                resolved_addresses.remove(r)


        debug(f"After resolving addresses, here are the possible sections: {possible_sections}")
        if len(possible_sections) == 1:
            secname = list(possible_sections)[0]
            if secname not in container.codesections:
                self._adjust_adrp_section_pointer(container, secname, orig_off, inst)
                debug(f"We're good, false alarm, the only possible section is: {secname}. Nice!")
                return
            # elif <= 853875: # success here
            # elif 345864 <= inst.address <= 853875: # success here
            # elif 345864 <= inst.address <= 826672: # success
            # elif 853875 <= inst.address <= 1461028: # bug
            # elif 853875 <= inst.address <= 1314488: # bug
            # elif 853875 <= inst.address <= 1313384: # success
            # elif 1313384 <= inst.address <= 1314488: # bug
            # elif 1313384 <= inst.address <= 1314304: # bug
            # elif 1313384 <= inst.address <= 1313720: # success
            # elif 1314304 <= inst.address <= 1314304: # XXX: remove this else
                # print(inst.address, "OMGGGGGGGGGGGGGGGG")
                # self._adjust_adrp_section_pointer(container, secname, orig_off, inst)
                # return
                # Rewriter.total_text += 1
                # no_func = 0
                # for _, functiona in container.functions.items():
                    # if orig_off <= functiona.start <= orig_off + 0x1000:
                        # no_func += 1
                # if no_func > 1:
                    # Rewriter.impossible_text += 1
                    # nexti = function.cache[function.nexts[edx][0]]
                    # if len(function.nexts[edx]) == 1 and nexti.cs.mnemonic == "add" and p.orig_reg in nexti.reg_writes_common() and p.orig_reg in nexti.reg_reads_common():
                        # Rewriter.trivial_text += 1
                    # elif len(function.nexts[function.addr_to_idx[nexti.address]]) == 1:
                        # nexti = function.cache[function.nexts[function.nexts[edx][0]][0]]
                        # if len(function.nexts[edx]) == 1 and nexti.cs.mnemonic == "add" and p.orig_reg in nexti.reg_writes_common() and p.orig_reg in nexti.reg_reads_common():
                            # Rewriter.trivial_text += 1

        # if we got here, it's *very* bad, as we're *still* not sure which
        # section the global variable is in, or that section is the .text
        # section. 
        # As our last hope we try to ugly-hack-patch all instructions that use the register with the
        # global address loaded (instructions in the resolved_addresses list)
        debug(f"WARNING: trying to fix each instruction manually...")

        # we don't really want an ADRP in the middle of code, if possible
        # so we erase it 
        inst.mnemonic = "// " + inst.mnemonic

        for inst2, resolved_address, p_orig_reg in resolved_addresses:

            if inst2.mnemonic not in ["add", "ldr"] and not inst2.mnemonic.startswith("str"):
                debug(f"Warning: skipping {inst2} as not supported in global address emulation")
                continue

            is_an_import = False
            for rel in container.relocations[".dyn"]:
                if rel['st_value'] == resolved_address or rel['offset'] == resolved_address:
                    is_an_import = rel['name']
                    break
                elif resolved_address in container.plt:
                    is_an_import = container.plt[resolved_address]
                    break

            # reg_name2 = inst2.cs.reg_name(inst2.cs.operands[0].reg)
            # reg_name3 = inst2.cs.reg_name(inst2.cs.operands[1].reg)

            # if inst2.mnemonic.startswith("str"):
                # old_mnemonic = inst2.mnemonic
                # # if reg_name2 == orig_reg:  # str <orig_reg>, [...]
                # inst2.instrument_before(InstrumentedInstruction(
                    # "adrp %s, .LC%x" % (reg_name2, resolved_address)))
                # inst2.instrument_before(InstrumentedInstruction(
                    # "add %s, %s, :lo12:.LC%x" % (reg_name2, reg_name2, resolved_address)))
                # # else:                      # str ..., [<orig_reg> + ...]
                    # # inst2.instrument_before(InstrumentedInstruction(
                        # # "adrp %s, .LC%x" % (reg_name2, resolved_address)))
                    # # inst2.instrument_before(InstrumentedInstruction(
                        # # "add %s, %s, :lo12:.LC%x" % (reg_name2, reg_name2, resolved_address)))
                    # # inst2.mnemonic =  "ldr"
                    # # inst2.op_str =  reg_name3 + f", =.LC%x" % (resolved_address)
                    # # inst2.instrument_after(InstrumentedInstruction(
                        # # f"{old_mnemonic} {reg_name2}, [{reg_name3}]"))
            # elif is_an_import:
                # inst2.op_str =  reg_name2 + f", =%s" % (is_an_import)
            # else:
                # if is_reg_32bits(reg_name2):
                    # reg_name2 = get_64bits_reg(reg_name2)
                # if inst2.mnemonic == "add":
                    # inst2.mnemonic = "// " + inst2.mnemonic



            if is_an_import:
                inst2.op_str =  reg_name2 + f", =%s" % (is_an_import)
            else:
                inst2.instrument_before(InstrumentedInstruction(
                    "adrp %s, .LC%x" % (p_orig_reg, resolved_address)))
                inst2.instrument_before(InstrumentedInstruction(
                    "add %s, %s, :lo12:.LC%x" % (p_orig_reg, p_orig_reg, resolved_address)))

                # this is a ugly hack, and slow, but this should get
                # triggered _very rarely_. 
                displace = resolved_address - p.orig_off
                if displace != 0:
                    inst2.instrument_before(InstrumentedInstruction(
                        "sub %s, %s, 0x%x" % (p_orig_reg, p_orig_reg, displace)))




            inst2.op_str += " // from adrp at 0x%x" % (inst.address)

            self.xrefs[resolved_address] += [inst2.address]






    def symbolize_mem_accesses(self, container, context):
        for _, function in container.functions.items():
            for edx, inst in enumerate(function.cache):
                if inst.address in self.symbolized:
                    continue

                if inst.mnemonic == "adrp":
                    self._adjust_global_access(container, function, edx, inst)

                if inst.mnemonic == "adr":
                    if Rewriter.detect_and_symbolize_switch_tables:
                        value = inst.cs.operands[1].imm
                        if value % 0x1000 == 0: # an adr to a page, probably same as adrp
                            self._adjust_global_access(container, function, edx, inst)
                        else:
                            inst.op_str = inst.op_str.replace("#0x%x" % value, ".LC%x" % value)
                    else:
                        # we just make the adr as it would be an adrp
                        # and rebase it against the landing pad. So in a jump table offsets
                        # will be calculated against the landing pad, not the instrumented .text
                        # and there's no need to symbolize those offsets.
                        self._adjust_global_access(container, function, edx, inst)
                        orig_off = int(inst.cs.op_str.split("#")[-1], 16)
                        orig_reg = inst.cs.op_str.split(',')[0]
                        inst.instrument_after(InstrumentedInstruction(f"add {orig_reg}, {orig_reg}, {orig_off & 0xfff}"))

                # if it is something like 'ldr x0, #0xcafe'
                if inst.mnemonic in ["ldr","ldrsw"] and not "[" in inst.cs.op_str: 
                    value = int(inst.cs.op_str.split("#")[-1], 16)
                    inst.op_str = inst.op_str.replace("#0x%x" % value, ".LC%x" % value)
                    sec = container.section_of_address(value)
                    if sec.name == ".text":
                        # this is a literal pool! there is a pointer in text we must change!
                        fun = container.function_of_address(value)
                        if fun == None: continue
                        debug(f"Detected read inside text from {inst}")
                        access_size = get_reg_size_arm(inst.op_str.split(",")[0])
                        oldins = fun.cache[(value - fun.start) // 4]
                        if access_size in [16,8,4]:
                            mybytes = fun.bytes[value - fun.start:value - fun.start + access_size]
                            oldins.mnemonic = "".join(["\t.byte 0x%x\n" % i for i in mybytes])
                            oldins.op_str = "// this is data, value read from .LC%x" % inst.address
                            for i in range((access_size // 4) - 1):
                                nextinst = fun.cache[(value - fun.start + 4 + i*4) // 4]
                                nextinst.mnemonic = " // null because of previous data"
                                nextinst.op_str = ""
                        else:
                            critical(f"Access size {access_size} from {inst} not yet implemented when loading data from text. aborting!")
                            exit(1)



    def _handle_relocation(self, container, section, rel):
        reloc_type = rel['type']
        if reloc_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_RELATIVE"]:
            value = rel['addend']
            label = "0x%x" % value + " + .fake.elf_header"
            if int(value) in container.ignore_function_addrs:
                return
            section.replace(rel['offset'], 8, label)
        elif reloc_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_GLOB_DAT"]:
            if section.name != '.got': return
            if rel['name'] in Rewriter.GCC_RELOCATIONS: return
            section.replace(rel['offset'], 8, rel['name'])
        elif reloc_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_ABS64"]:
            if rel['name'] in Rewriter.GCC_RELOCATIONS: return
            name = rel['name']
            if rel['addend']: name += " + " + str(rel['addend'])
            section.replace(rel['offset'], 8, name)
        elif reloc_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_JUMP_SLOT"]:
            debug(f"Skipping relocation {rel}")
        elif reloc_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_COPY"]:
            if rel['name'] in Rewriter.GCC_RELOCATIONS: return
            section.replace(rel['offset'], 8, rel['name'])

            # We cannot generate R_AARCH64_COPY relocation just by assembler directives
            # the most similar would be .comm but it does not work for some reason? 
            # so by using .quad <symbol> we have a pointer to a pointer that we need to 
            # dereference once. So we instrument _init to do that for us
            # basically we fix relocations manually. the final solution. 
            entry = container.loader.elffile.header["e_entry"]
            start_fun = container.function_of_address(entry)
            data_sec = container.section_of_address(rel['offset'])
            symbol_list = data_sec.symbols[rel['offset']]
            for x in symbol_list:
                if x.name == rel['name']:
                    symbol_list.remove(x)
            start_fun.cache[(entry - start_fun.start) // 4].instrument_before(InstrumentedInstruction('''
// dereference %s to adjust R_AARCH64_COPY relocation
adrp x7, .LC%x
add x7, x7, :lo12:.LC%x
ldr x6, [x7]
ldr x6, [x6]
str x6, [x7]
            ''' % (rel['name'], rel['offset'], rel['offset'])))

        else:
            critical(rel)
            critical("[*] Unhandled relocation {}".format(
                describe_reloc_type(reloc_type, container.loader.elffile)))

    # def fix_got_section(self, container):
        # # gcc will add some stuff to the .got that is already there
        # # we want to keep the same size of the .got so here we remove
        # # the stuff gcc will add back (relocations, mostly)

        # # delete first three entries of .got, it does not seem we need to keep them
        # gotsec = container.datasections['.got']
        # gotsec.delete(0, 8*3) 
        # # we now remove the entries of the got relative to all imports
        # for rel in container.relocations['.plt']:
            # if rel['type'] == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_JUMP_SLOT"]:
                # gotsec.delete(rel['offset'] - gotsec.base, 8)
                # Rewriter.total_deleted_from_got += 8
        # symtab = container.loader.elffile.get_section_by_name(".symtab")
        # # this symbol needs to be removed as gcc adds it back 
        # # (stores the address of the .dynamic section)
        # dyntable = symtab.get_symbol_by_name("_GLOBAL_OFFSET_TABLE_")
        # if len(dyntable) == 1:
            # gotsec.delete(dyntable[0]['st_value'] - gotsec.base, 8)

        # Rewriter.total_deleted_from_got += 4*8



    def symbolize_data_sections(self, container, context=None):
        for sec in container.relocations.values():
            for rel in sec:
                section = container.section_of_address(rel['offset'])
                if section:
                    self._handle_relocation(container, section, rel)
                else:
                    print("[x] Couldn't find valid section {:x}".format(
                        rel['offset']))


    def recover_eh_frame(self, container, context=None):
        # BEGIN __init__
        dwarf_map = dict()

        # Mapping from function name to a map from instruction offset in cache
        # to the cfi directive to be added before that line.
        cfi_map = defaultdict(lambda: defaultdict(list))
        # END __init__

        dw_info = container.loader.elffile.get_dwarf_info()
        if dw_info.eh_frame_sec == None: return 

        info("Recovering .eh_frame information")
        ehframe_entries = dw_info.EH_CFI_entries()


        lsda_encoding = None
        code_alignment_factor = 1
        # lsdas = list(sorted(container.loader.elffile.get_dwarf_info()["gcc_except_table"]["lsdas"],
        #                     key=lambda x: x["idx"]))

        for entry in ehframe_entries:

            if type(entry) == FDE:
                # This is called every time we deal with a function descriptor
                if type(entry) != FDE:
                    raise Exception("This function requires an elftools.dwarf.callframe.FDE")

                initial_location = entry.header.initial_location

                # I think this corresponds to where the function is! Which we can match 
                # up with retrowrite.
                # We should check that it points to a CIE and that the personality function 
                # is gxx_personality_v0. If not, it could be e.g. Rust. Not checked 
                # what they use.
                lsda_table = None
                function = container.functions.get(initial_location)
                if not function:
                    print("Could not find function at location 0x%x, is this normal ?" % initial_location)
                    continue
                current = cfi_map[function.start]

                if entry.lsda_pointer:
                    if Rewriter.emulate_calls:
                        if lsda_encoding == None:
                            critical("LSDA encoding not found. Aborting")
                            exit(1)
                        current[0].append(".cfi_personality 0, __gxx_personality_v0")
                        current[0].append(".cfi_lsda 0x%x, .LC%x" % (lsda_encoding, entry.lsda_pointer))
                    else:
                        debug("LDSA Pointer: %x" % entry.lsda_pointer)

                        lsda_pointer = entry.lsda_pointer
                        modifier = entry.lsda_pointer & 0xF0
                        # if modifier == DW_EH_encoding_flags['DW_EH_PE_pcrel']:
                            # lsda_pointer -= 

                        # XXX
                        # XXX
                        # XXX Deal with wrong lsda_pointer in non-PIE binaries
                        # XXX
                        # XXX

                        lsda_table = LSDATable(container.loader.elffile.stream, entry.lsda_pointer, initial_location, container)
                        dwarf_map[initial_location] = lsda_table.generate_header()
                        dwarf_map[initial_location] += lsda_table.generate_table()

                        func = container.functions[initial_location]
                        # func.except_table_loc = entry.lsda_pointer
                        func.except_table_loc = func.start

                        # SHOULD LOOK LIKE THIS :
                        # for entry in lsda_table.entries
                        #     dwarf_map[...] = entry...



                location = -1
                # For each DWARF instruction in the instruction list, what do we do?
                for instruction in entry.instructions:
                    debug(">>>>>", instruction)

                    # This is decoding the DWARF virtual machine instructions :)
                    # Some of these directly correspond to assembler directives we 
                    # can emit at appropriate locations in the assembly.
                    # Advance tells us how to move through that function, but
                    # TODO: haven't properly decoded it yet.

                    opcode = instruction.opcode
                    args = instruction.args

                    location, cfi_line = self.interpret_dwarf_instruction(location, [opcode] + args, entry.cie.header.code_alignment_factor, entry.cie.header.data_alignment_factor)
                    debug("\t > We're at", hex(location), "and CFI line is", cfi_line)
                    if cfi_line:
                        current[location].append("\t"+cfi_line)


            elif type(entry) == CIE:
                # We can process the CIE entries, which is nice.
                # print(entry.header)
                # print(entry.augmentation_dict)
                personality = entry.augmentation_dict.get('personality', None)
                # https://www.airs.com/blog/archives/460
                # There's a few bits going on here.
                # When we want to find an exception, we find the FDE, we find the 
                # appropriate CIE, we find the personality function and we then apply 
                # the appropriate function (gxx_personality_v0 in our case) to the 
                # 'stuff' contained in the language-specific data area, which *is* 
                # .gcc_except_table.
                if personality:
                    personality_function = personality.function
                    debug("Personality Function: 0x%x" % personality_function)
                lsda_encoding_or_none = entry.augmentation_dict.get('LSDA_encoding', None)
                if lsda_encoding_or_none:
                    lsda_encoding = lsda_encoding_or_none
                    debug("LSDA Encoding %d" % lsda_encoding)
                else:
                    debug("CIE entry without LSDA_encoding field!")
            elif type(entry) == ZERO:
                debug(entry.offset)
            else:
                raise Exception("Unhandled type %s" % (type(entry)))


        if Rewriter.emulate_calls:
            # add cfi instructions inside landing pad 
            for addr, loc in cfi_map.items():
                for l, cfi in loc.items():
                    container.global_cfi_map[addr + l*4 + 4] += cfi
        else:
            # add cfi instrucitons in the instrumented functions
            for addr, cfi_map in cfi_map.items():
                func = container.functions[addr]
                func.cfi_map = cfi_map
            # BEGIN rewrite_table
            for addr, table in dwarf_map.items():
                func = container.functions[addr]
                func.except_table = table


        # Add definition for personality at the end
        personality='''
            .data
            .hidden DW.ref.__gxx_personality_v0
            .weak   DW.ref.__gxx_personality_v0
            .section .data.rel.ro.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
            .align 8
            .type   DW.ref.__gxx_personality_v0, @object
            .size   DW.ref.__gxx_personality_v0, 8
        DW.ref.__gxx_personality_v0:
            .quad   __gxx_personality_v0
            .ident  "GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0"
            .section        .note.GNU-stack,"",@progbits
        '''
        # .hidden __dso_handle
        container.personality = personality

    def interpret_dwarf_instruction(self, current_loc, instruction, code_alignment_factor, data_alignment_factor):
        cfi_line = None
        _PRIMARY_MASK = 0b11000000
        _PRIMARY_ARG_MASK = 0b00111111
        opcode = instruction[0]

        primary = opcode & _PRIMARY_MASK
        primary_arg = opcode & _PRIMARY_ARG_MASK

        if primary == DW_CFA_advance_loc:
            return current_loc + (primary_arg*code_alignment_factor)//4, cfi_line
        if primary == DW_CFA_offset:
            cfi_line = ".cfi_offset %s, %d" % (primary_arg, instruction[2] * data_alignment_factor)
            return current_loc, cfi_line
        if primary in [DW_CFA_restore, DW_CFA_restore_extended]:
            cfi_line = ".cfi_restore %s" % (primary_arg)
            return current_loc, cfi_line


        debug("OPCODE", opcode)

        # ADVANCE_LOC = 64 = 0x40
        # OFFSET = 128 = 0x80
        # RESTORE = 192 = 

        if opcode in [DW_CFA_advance_loc1, DW_CFA_advance_loc2]:
            if instruction[0] & 0b111 == DW_CFA_set_loc:
                current_loc = instruction[1]
            else:
                current_loc += instruction[1]//code_alignment_factor

        elif opcode == DW_CFA_def_cfa_offset:
            # cfi_line = ".cfi_def_cfa_offset %s\n\t.cfi_offset x29, -%d" % (instruction[1], instruction[1])
            cfi_line = ".cfi_def_cfa_offset %s" % (instruction[1])
        elif opcode in [DW_CFA_offset, DW_CFA_offset_extended]:
            cfi_line = ".cfi_offset %s, %d" % (instruction[1], instruction[2] * data_alignment_factor)
        elif opcode == DW_CFA_def_cfa_register:
            cfi_line = ".cfi_def_cfa_register %s" % (instruction[1])
        elif opcode == DW_CFA_def_cfa:
            cfi_line = ".cfi_def_cfa %s, %s" % (instruction[1], instruction[2])
        elif opcode == DW_CFA_remember_state:
            cfi_line = ".cfi_remember_state"
        elif opcode in [DW_CFA_restore, DW_CFA_restore_extended]:
            cfi_line = ".cfi_restore %s" % (instruction[1])
        # elif opcode == DW_CFA_restore + DW_CFA_restore_state:
            # cfi_line = ".cfi_restore_state" 
        elif opcode == DW_CFA_restore_state:
            cfi_line = ".cfi_restore_state" 
        elif opcode == DW_CFA_nop:
            pass

        else:
            critical("[x] Unhandled DWARF instruction: %x" % instruction[0])
            if instruction[0] > 192:
                print("RESTORE+",instruction[0]-192)
            if instruction[0] > 128 and instruction[0] < 192:
                print("OFFSET",instruction[0]-128)
            if instruction[0] > 64 and instruction[0] < 128:
                print("ADVANCE_LOC+",instruction[0]-64)
            # exit(1) # maybe we don't need to exit right away
        return current_loc, cfi_line


# This code borrows from Angr's CLE loader. We basically ask pyelftools to 
# parse dwarf structs based on the lsda_pointers we find in the _eh_frame 
# FDEs. This isn't done yet, but that is a next step, and this info should 
# probably be attached there as an LSDA entry so we can decode it into 
# assembler.
class LSDATable():
    """
    The LSDA Table in GCC-Frontend Compilers (All GCC Languages) implements the 
    LSDA using __gxx_personality_v0. Thus this should work for all GCC-languages 
    we care about, but that isn't guaranteed.
    """
    def __init__(self, elffile, fileoffset, fstart, container):
        self.elf = elffile
        self.lsda_offset = fileoffset
        self.entry_structs = DWARFStructs(True, 64, 8)
        self.entries = []
        self.fstart = fstart
        self.sz = container.functions[fstart].sz
        self._formats = self._eh_encoding_to_field(self.entry_structs)
        self.actions = []
        self.ttentries = OrderedDict()
        self.typetable_offset = 0
        self.typetable_encoding = 0xff
        self.typetable_offset_present = False
        self._parse_lsda()

    @staticmethod
    def _eh_encoding_to_field(entry_structs):
        """
        Shamelessly copied from pyelftools since the original method is a bounded method.
        Return a mapping from basic encodings (DW_EH_encoding_flags) the
        corresponding field constructors (for instance
        entry_structs.Dwarf_uint32).
        """
        return {
            DW_EH_encoding_flags['DW_EH_PE_absptr']:
                entry_structs.Dwarf_target_addr,
            DW_EH_encoding_flags['DW_EH_PE_uleb128']:
                entry_structs.Dwarf_uleb128,
            DW_EH_encoding_flags['DW_EH_PE_udata2']:
                entry_structs.Dwarf_uint16,
            DW_EH_encoding_flags['DW_EH_PE_udata4']:
                entry_structs.Dwarf_uint32,
            DW_EH_encoding_flags['DW_EH_PE_udata8']:
                entry_structs.Dwarf_uint64,

            DW_EH_encoding_flags['DW_EH_PE_sleb128']:
                entry_structs.Dwarf_sleb128,
            DW_EH_encoding_flags['DW_EH_PE_sdata2']:
                entry_structs.Dwarf_int16,
            DW_EH_encoding_flags['DW_EH_PE_sdata4']:
                entry_structs.Dwarf_int32,
            DW_EH_encoding_flags['DW_EH_PE_sdata8']:
                entry_structs.Dwarf_int64,
        }

    def _parse_lsda(self):
        self._parse_lsda_header()
        self._parse_lsda_entries()

    def _parse_lsda_header(self):
        # https://www.airs.com/blog/archives/464
        self.elf.seek(self.lsda_offset)

        lpstart_raw = self.elf.read(1)[0]
        lpstart = None
        if lpstart_raw != DW_EH_encoding_flags['DW_EH_PE_omit']:
            # See https://www.airs.com/blog/archives/464, it should be omit in
            # practice
            info("Landing pad found!")
            raise Exception("We do not handle this case for now")
            base_encoding = lpstart_raw & 0x0F
            modifier      = lpstart_raw & 0xF0

            lpstart = struct_parse(
                Struct('dummy',
                       self._formats[base_encoding]('LPStart')),
                self.elf
            )['LPStart']

            if modifier == 0:
                pass
            elif modifier == DW_EH_encoding_flags['DW_EH_PE_pcrel']:
                lpstart += self.address + (self.elf.tell() - self.base_offset)
            else:
                critical("Unsupported modifier in LSDA encoding")
                raise Exception("what")

        self.typetable_encoding = self.elf.read(1)[0] 
        critical("TT encoding " + hex(self.typetable_encoding) + " of function " + hex(self.fstart))
        # NOW TODO : the encoding is the right one + 1, which is weird

        if self.typetable_encoding != DW_EH_encoding_flags['DW_EH_PE_omit']:
            self.typetable_offset = struct_parse(
                Struct('dummy',
                       self.entry_structs.Dwarf_uleb128('TType')),
                self.elf
            )['TType']
            self.typetable_offset_present = True
        else:
            self.typetable_offset_present = False
        self.typetable_offset_field_length = self.elf.tell()

        call_site_table_encoding = self.elf.read(1)[0]
        if call_site_table_encoding != DW_EH_encoding_flags['DW_EH_PE_uleb128']:
            critical(f"TT: Call site table encoding {hex(call_site_table_encoding)} not supported.")
            exit(1)
        call_site_table_len = struct_parse(
            Struct('dummy',
                   # self.entry_structs.Dwarf_uleb128('CSTable')),
                   self._formats[call_site_table_encoding & 0xf]('CSTable')),
            self.elf
        )['CSTable']

        debug("lpstart", lpstart_raw)
        debug("lpstart_pcrel", lpstart)
        debug("typetable_encoding", self.typetable_encoding)
        debug("call_site_table_encoding", call_site_table_encoding)

        debug("CALL SITE TABLE LENGTH %d" % call_site_table_len)
        debug("TYPETABLE OFFSET %d" % self.typetable_offset)

        self.end_label = ".LLSDATT%x" % self.fstart
        self.table_label = ".LLSDATTD%x" % self.fstart
        self.action_label = ".LLSDACSE%x" % self.fstart
        self.callsite_label = ".LLSDACSB%x" % self.fstart
        self.ttable_prefix_label = ".LLSDATYP%x" % self.fstart 

        # Need to construct some representation here.
        self.header = {
            "lpstart": lpstart_raw,
            "encoding": call_site_table_encoding,
            "typetable_encoding": self.typetable_encoding,
            "call_site_table_len": call_site_table_len,
            "cs_act_tt_total_len": self.typetable_offset, # Don't forget to check typetable_offset_present
        }

    def _parse_lsda_entries(self):
        start_cs_offset = self.elf.tell()
        debug("TT start_cs_offset " + hex(start_cs_offset))
        action_count = 0

        while self.elf.tell() - start_cs_offset < self.header["call_site_table_len"]:
            base_encoding = self.header["encoding"] & 0x0f
            modifier = self.header["encoding"] & 0xf0

            # Maybe we need to store the offset in the entry ?

            # header
            s = struct_parse(
                Struct('CallSiteEntry',
                       self._formats[base_encoding]('cs_start'),
                       self._formats[base_encoding]('cs_len'),
                       self._formats[base_encoding]('cs_lp'),
                       self.entry_structs.Dwarf_uleb128('cs_action'),
                       ),
                self.elf
            )

            cs_action = s['cs_action']
            if cs_action != 0:
                action_offset_bytes = (cs_action+1) >> 1
                action_count = max(action_count, action_offset_bytes)

            self.entries.append(s)

        num_types = 0
        for i in range(action_count):
            action = struct_parse(
                Struct("ActionEntry",
                    self.entry_structs.Dwarf_int8('act_filter'),
                    self.entry_structs.Dwarf_uint8('act_next')
                ),
                self.elf
            )
            if action['act_filter'] < 0:
                critical("Negative filter, consult https://www.airs.com/blog/archives/464")
                exit(1)

            if action['act_filter'] != 0x7f:
                num_types = max(num_types, action['act_filter'])
            self.actions.append(action)

        if not self.typetable_offset_present: return

        ttendloc = self.typetable_offset_field_length + self.typetable_offset

        sizes = {2: 2, 3: 4, 4: 8} # hword, word, xword
        lenght_of_type_row = sizes[self.typetable_encoding & 7]
        debug("TT length_of_type_row " + hex(lenght_of_type_row))
        debug("TT ttendloc  " + hex(ttendloc))
        debug("TT num_types  " + str(num_types))
        debug("TT seeking at  " + hex(ttendloc - num_types * lenght_of_type_row))
        self.elf.seek(ttendloc - num_types * lenght_of_type_row)

        for i in range(num_types):
            ttentryloc = self.elf.tell()
            debug("****** TT LOC: %x" % (ttentryloc))


            ptr = struct_parse(
                Struct("ActionEntry",
                    self._formats[self.typetable_encoding & 0xf]('ptr')
                ),
                self.elf
            )['ptr']
            debug("****** TT PTR: %x" % ptr)

            symbolized_target = 0
            if ptr != 0 and self.typetable_encoding & 0x80: #indirect address 
                symbolized_target = ptr + ttentryloc
            else:
                symbolized_target = ptr

            typeentry = {'address': symbolized_target}
            self.ttentries[i] = typeentry
            debug("****** TT x: %x" % (symbolized_target))


    def generate_tableoffset(self):
        if self.typetable_offset_present:
            ttoffset = ".uleb128 %s-%s // Typetable end offset" % (self.end_label, self.table_label)
        else:
            ttoffset = "// @TType Encoding is DW_EH_PE_omit, ignoring."
        return ttoffset

    def generate_header(self):
        ttoffset = self.generate_tableoffset()

        table_header = """
.LFE%x:
    .section	.gcc_except_table,"a",@progbits
    .p2align 2
GCC_except_table%x:
.LLSDA%x:
    .byte 0x%x   // Landing pad Encoding
    .byte 0x%x   // Type table  Encoding
    %s
.LLSDATTD%x:
    .byte 0x1
        """ % (
            self.fstart,
            self.fstart,
            self.fstart,
            self.header["lpstart"],
            self.header["typetable_encoding"],
            ttoffset,
            self.fstart,
        )
        return table_header

    def generate_table(self):
        table = """
    .uleb128 %s-%s
.LLSDACSB%x:
%s
.LLSDACSE%x:
    // Actions list
%s
    // Typetable start
%s
.LLSDATT%x:
    .p2align 2
        """ % (
            self.action_label,
            self.callsite_label,
            self.fstart,
            self.generate_callsites(),
            self.fstart,
            self.generate_actions(),
            self.generate_typetable(),
            self.fstart
        )
        return table
    
    def generate_callsites(self):
        #.LLSDACSB2:
        #   .uleb128 .LEHB4-.LFB2    ; uint8_t start
        #   .uleb128 .LEHE4-.LEHB4   ; uint8_t len
        #   .uleb128 .L19-.LFB2      ; uint8_t lp
        #   .uleb128 0x3             ; uint8_t action

        function_end = self.sz + self.fstart

        def callsite_ftr(entry):
            cbw_e = ""
            jlo_e = ""

            # XXX: code below might need to be de-commented

            # if self.fstart + entry["cs_start"] + entry["cs_len"] >= function_end:
                # cbw_e = "E"
            # if self.fstart + entry["cs_lp"] >= function_end:
                # jlo_e = "E"

            """
            cse: The start of the instructions for the current call site, 
                 a byte offset from the landing pad base. This is encoded 
                 using the encoding from the header.
            cbw: The length of the instructions for the current call site, 
                 in bytes. This is encoded using the encoding from the header.
            jlo: A pointer to the landing pad for this sequence of instructions, 
                 or 0 if there isn’t one. This is a byte offset from the 
                 landing pad base. This is encoded using the encoding from the header.
            act: The action to take, an unsigned LEB128. 
                 This is 1 plus a byte offset into the action table. 
                 The value zero means that there is no action.
            """

            cse = "\t.uleb128 .LC%x-.L%x    \t// Call Site Entry (%u)" % (self.fstart + entry["cs_start"], self.fstart, entry["cs_start"])
            cbw = "\t.uleb128 .LC%s%x-.LC%x \t// Call Between (%u)" % (cbw_e, self.fstart + entry["cs_start"] + entry["cs_len"], self.fstart + entry["cs_start"], entry["cs_len"])
            jlo = "\t.uleb128 .LC%s%x-.L%x  \t// Jump Location (%u)" % (jlo_e, self.fstart + entry["cs_lp"], self.fstart, entry["cs_lp"]) 
            if entry["cs_lp"] == 0:
                jlo = "\t.uleb128 0  \t\t\t\t// Jump Location (no landing pad)"
            act = "\t.uleb128 0x%x          \t\t// Action\n" % (entry["cs_action"])
            return "\n".join([cse, cbw, jlo, act])

        return "\n".join(map(callsite_ftr, self.entries))

    def generate_typetable(self):

        ttable = ""
        i = 1
        for idx, tp in (list(self.ttentries.items())):
            debug("*******", idx)
            label = "%sE%s" % (self.ttable_prefix_label,i)
            i+=1

            target_label = "0"
            if tp["address"] != 0:
                # not documented elsewhere lol
                # https://github.com/gnustep/libobjc2/blob/master/dwarf_eh.h
                if self.typetable_encoding & 0x80: #indirect address 
                    target_label = ".LC%x-." % (tp["address"])
                else:
                    target_label = ".LC%x" % (tp["address"])

            sizes = {2: ".hword", 3: ".word", 4: ".quad"}
            ttable += "\n%s:\n\t%s %s""" % (label, sizes[self.typetable_encoding & 7], target_label)
        return ttable

    def generate_actions(self):
        action_table = ""
        for action in self.actions:
            action_table += "    .byte 0x%x // action filter \n" % (action["act_filter"])
            action_table += "    .byte 0x%x // next record\n" % (action["act_next"]) 
        return action_table

    def generate_footer(self):
        return "%s:\n" % self.end_label
