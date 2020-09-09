from collections import defaultdict
import struct

from capstone import CS_OP_IMM, CS_OP_MEM, CS_GRP_JUMP, CS_OP_REG

from . import disasm
from arm.librw.util.logging import *
from arm.librw.util.arm_util import non_clobbered_registers, memory_replace, count_instructions

INSTR_SIZE = 4

class SzPfx():
    PREFIXES = {
        1: '.byte',
        2: '.hword', # on ARM words are 4 bytes, so we use half word
        4: '.word',
        8: '.quad',
        16: '.xmmword',
    }

    @staticmethod
    def pfx(sz):
        return SzPfx.PREFIXES[sz]


class Container():
    def __init__(self):
        self.functions = dict()
        self.function_names = set()
        self.sections = dict()
        self.globals = None
        self.relocations = defaultdict(list)
        self.loader = None
        self.ignore_function_addrs = list()
        self.text_section = None
        # PLT information
        self.plt_base = None
        self.plt = dict()

        self.gotplt_base = None
        self.gotplt_sz = None
        self.gotplt_entries = list()

    def add_function(self, function):
        if function.name in self.function_names:
            function.name = "%s_%x" % (function.name, function.start)
        self.functions[function.start] = function
        self.function_names.add(function.name)

    def add_section(self, section):
        print(f"Added {section.name}")
        self.sections[section.name] = section

    def add_globals(self, globals):
        self.globals = globals
        done = set()

        for location, gobjs in globals.items():
            found = None
            for sec, section in self.sections.items():
                if section.base <= location < section.base + section.sz:
                    found = sec
                    break

            if not found:
                continue

            for gobj in gobjs:
                if gobj['name'] in done:
                    continue
                self.sections[found].add_global(location, gobj['name'],
                                                gobj['sz'])
                done.add(gobj['name'])

    def is_target_gotplt(self, target):
        assert self.gotplt_base and self.gotplt_sz

        if not (self.gotplt_base <= target <
                self.gotplt_base + self.gotplt_sz):
            return False

        for ent in self.gotplt_entries:
            if ent.address == target:
                if (CS_GRP_JUMP in ent.groups
                        and ent.operands[0].type == CS_OP_MEM):
                    return ent.operands[0].mem.disp + ent.address + ent.size

        return False

    def attach_loader(self, loader):
        self.loader = loader
        self.text_section = self.loader.elffile.get_section_by_name(".text")


    def is_in_section(self, secname, value):
        assert self.loader, "No loader found!"

        if secname in self.sections:
            section = self.sections[secname]
        if secname == ".text":
            if self.text_section == None: return True
            section = self.text_section

        base = section['sh_addr']
        sz = section['sh_size']
        if base <= value < base + sz:
            return True
        return False

    def add_relocations(self, section_name, relocations):
        self.relocations[section_name].extend(relocations)

    def section_of_address(self, addr):
        for _, section in self.sections.items():
            if section.base <= addr < section.base + section.sz:
                return section
        # check for .text, as container.sections has only datasections
        if self.is_in_section(".text", addr):
            return self.text_section
        return None

    def function_of_address(self, addr):
        for _, function in self.functions.items():
            if function.start <= addr < function.start + function.sz:
                return function
        return None

    def add_plt_information(self, relocinfo):
        plt_base = self.plt_base

        # we start from idx=2 because the start of the .plt takes 32 bytes
        # on aarch64, while instead it takes only 16 in x86. 
        # TODO: make this more robust, not empirical
        for idx, relocation in enumerate(relocinfo, 2):
            self.plt[plt_base + idx * 16] = relocation['name']

    def reloc(self, target):
        assert self.loader, "No loader found!"
        return "import"

class Jumptable():
    def __init__(self, br_address=0, jump_table_address=0, case_size=1, case_no=1, cases=[]):
        self.br_address = br_address
        self.jump_table_address = jump_table_address
        self.case_size = case_size
        self.case_no = case_no
        self.cases = cases
        self.first_case = sorted(cases)[0]
        self.base_case = cases[0]
        self.last_case = sorted(cases)[-1]

class Function():
    def __init__(self, name, start, sz, bytes, bind="STB_LOCAL"):
        self.name = name
        self.cache = list()
        self.start = start
        self.sz = sz
        self.bytes = bytes
        self.bbstarts = set()
        self.bind = bind
        self.possible_switches = list()
        self.switches = list()
        self.switches_to_fix = list()
        self.addr_to_idx = dict()

        # Populated during symbolization.
        # Invalidated by any instrumentation.
        self.nexts = defaultdict(list)
        self.prevs = defaultdict(list)

        self.bbstarts.add(start)

        # Dict to save function analysis results
        self.analysis = defaultdict(lambda: None)

        # Is this an instrumented function?
        self.instrumented = False

    def set_instrumented(self):
        self.instrumented = True

    def disasm(self):
        assert not self.cache
        for decoded in disasm.disasm_bytes(self.bytes, self.start):
            ins = InstructionWrapper(decoded)
            self.cache.append(ins)


    def is_valid_instruction(self, address):
        assert self.cache, "Function not disassembled!"

        for instruction in self.cache:
            if instruction.address == address:
                return True

        return False

    def instruction_of_address(self, address):
        assert self.cache, "Function not disassembled!"

        for instruction in self.cache:
            if instruction.address <= address < instruction.address + instruction.sz:
                return instruction

        return None

    def add_switch(self, jump_table):
        self.switches += [jump_table]
        print(self.name)
        for case in set(jump_table.cases):
            instr = self.cache[self.addr_to_idx[case]]
            same_cases = [e for e,x in enumerate(jump_table.cases) if x == instr.address]
            instr.op_str += f" // Case {same_cases} of switch at {hex(jump_table.br_address)}"

    def fix_shortjumps(self):
        # fix short conditional branches, like tbz, if too much instrumentation was added
        for instruction in self.cache:
            if instruction.mnemonic in ["tbz", "tbnz"]:
                start = instruction.address
                target = instruction.cs.operands[-1].imm
                next_instruction = start + INSTR_SIZE
                instrs = count_instructions(self, start, target)
                if instrs > 2**13: #32kB = 2^15 bytes = (2^15 / 4) instrs
                     instruction.instrument_after(InstrumentedInstruction(
                         ".tbz_%x_false:\n\tb .LC%x\n.tbz_%x_true:\n\tb .LC%x" \
                         %  (start, next_instruction, start, target)))
                     instruction.op_str = instruction.op_str.replace(
                             ".LC%x" % target, ".tbz_%x_true" % start)

    def fix_jmptbl_size(self, container):
        # jump tables may not fit if there is too much instrumentation. 
        for jmptbl in self.switches:
            # jump tables can have negative values
            # so we start from the first possible landing point
            # and we get what is the number of instructions between that
            # and the base case. We do the same, backwards, from the 
            # latest possible landing point

            max_instrs = max(count_instructions(self, jmptbl.first_case, jmptbl.base_case),
                             count_instructions(self, jmptbl.base_case, jmptbl.last_case))

            if max_instrs > (0x7f << (8 * (jmptbl.case_size-1))):
                self.switches_to_fix += [(jmptbl, max_instrs)]

        for (jmptbl,instr_no) in self.switches_to_fix:
            add_instr = self.cache[self.addr_to_idx[jmptbl.br_address]-1]
            assert add_instr.mnemonic == "add"
            shift = add_instr.cs.operands[2].shift.value
            while instr_no > (0x7f << (8 * (jmptbl.case_size-1))): # 0x7f -> no negative numbers!
                instr_no /= 2
                shift += 1

            # now we need to add nop padding to fix alignment of each case
            while True:
                total_nops = 0
                possible = True
                padding = {}

                # this could be optimized by remembering the instrs number for each case
                for case in sorted(set(jmptbl.cases)):
                    instr_case = self.cache[self.addr_to_idx[case]]
                    instrs = count_instructions(self, instr_case.address, jmptbl.base_case)
                    alignment = (2 ** (shift - 2))
                    # nops = (alignment - (instrs % alignment)) % alignment
                    nops = (alignment - (instrs % alignment)) #XXX ? see line directly before
                    # we insert just the right amount of nops to make the case aligned
                    print("Inserted ", nops, "nops")
                    padding[case] = nops
                    total_nops += nops

                    if case == jmptbl.base_case or case == jmptbl.last_case:
                        if (instrs + total_nops)/(alignment) > (0x7f << (8 * (jmptbl.case_size-1))):
                            possible = False
                            break
                        total_nops = 0

                if not possible:
                    shift += 1 # we added so many nops there's no space left for the jmptbl
                    continue
                break

            for addr, nops in padding.items():
                previnstr_case = self.cache[self.addr_to_idx[addr] - 1]
                previnstr_case.instrument_after(InstrumentedInstruction("\n\tnop"*nops))

            if shift <= 4: # aarch64 limitation of the add instruction
                add_instr.op_str = add_instr.op_str[:-1] + str(shift)
            else:
                reg = add_instr.cs.reg_name(add_instr.cs.operands[-1].reg)
                add_instr.instrument_before(
                        InstrumentedInstruction(f"\tlsl {reg}, {reg}, {shift-2}"))
            add_instr.op_str = add_instr.op_str.replace("sxtb", "sxtw") # correct cast if wrong

            size = jmptbl.case_size
            debug(f"Fixing up jump table at {hex(jmptbl.br_address)} with new shift {shift}")
            # change the actual jump table in memory 
            for i in range(1, len(jmptbl.cases)):
                swlbl = "(.LC%x-.LC%x)/%d" % (jmptbl.cases[i], jmptbl.cases[0], 2**shift)
                memory_replace(container, jmptbl.jump_table_address + (i-1)*size, size, swlbl)


    def __str__(self):
        assert self.cache, "Function not disassembled!"

        results = []
        # Put all function names and define them.
        if self.bind == "STB_GLOBAL":
            results.append(".globl %s" % (self.name))
        else:
            results.append(".local %s" % (self.name))
        results.append(".type %s, @function" % (self.name))
        results.append("%s:" % (self.name))

        for instruction in self.cache:
            if isinstance(instruction, InstrumentedInstruction):
                if not self.instrumented:
                    print("[x] Old style instrumentation detected:", self.name)
                results.append("%s" % (instruction))
                continue

            if instruction.address in self.bbstarts:
                results.append(".L%x:" % (instruction.address))
                results.append(".LC%x:" % (instruction.address))
            else:
                results.append(".LC%x:" % (instruction.address))

            for iinstr in instruction.before:
                results.append("{}".format(iinstr))

            results.append(
                "\t%s %s" % (instruction.mnemonic, instruction.op_str))

            for iinstr in instruction.after:
                results.append("{}".format(iinstr))

        results.append(".size %s,.-%s" % (self.name, self.name))

        return "\n".join(results)

    def next_of(self, instruction_idx):
        nexts = list()
        for x in self.nexts[instruction_idx]:
            #XXX: does not make any sense
            if isinstance(x, str):
                nexts.append(x)
            else:
                nexts.append(x)
        return nexts


class InstructionWrapper():
    def __init__(self, instruction):
        self.cs = instruction
        self.address = instruction.address
        self.mnemonic = instruction.mnemonic
        self.op_str = instruction.op_str
        self.sz = instruction.size

        # Instrumentation cache for this instruction
        self.before = list()
        self.after = list()

        # CF Leaves function?
        self.cf_leaves_fn = None

    def __str__(self):
        return "%x: %s %s" % (self.address, self.mnemonic, self.op_str)

    def get_mem_access_op(self):
        for idx, op in enumerate(self.cs.operands):
            if op.type == CS_OP_MEM:
                return (op.mem, idx)
        return (None, None)

    def reg_reads(self):
        # Handle nop
        if self.mnemonic.startswith("nop"):
            return []
        if self.mnemonic.startswith("movz"):
            return []   # strange behaviour from capstone, movz does not read any regs
        regs = self.cs.regs_access()[0]
        return [self.cs.reg_name(x) for x in regs]

    def reg_writes(self):
        # Handle nop
        if self.mnemonic.startswith("nop"):
            return []
        regs = self.cs.regs_access()[1]
        return [self.cs.reg_name(x) for x in regs]

    def reg_writes_common(self):
        if self.mnemonic.startswith("bl"): # assume the function called uses all temporary registers
            return non_clobbered_registers
        return self.reg_writes()

    def instrument_before(self, iinstr, order=None):
        if order:
            self.before.insert(order, iinstr)
        else:
            self.before.append(iinstr)

    def instrument_after(self, iinstr, order=None):
        if order:
            self.after.insert(order, iinstr)
        else:
            self.after.append(iinstr)


class InstrumentedInstruction():
    def __init__(self, code, label=None, forinst=None):
        self.code = code
        self.label = label
        self.forinst = forinst

    def __str__(self):
        if self.label:
            return "%s: # %s\n\t%s" % (self.label, self.forinst, self.code)
        else:
            return "%s" % (self.code)


class DataSection():
    def __init__(self, name, base, sz, bytes, align=16):
        self.name = name
        self.cache = list()
        self.base = base
        self.sz = sz
        self.bytes = bytes
        self.relocations = list()
        self.align = align
        self.named_globals = defaultdict(list)

    def load(self):
        assert not self.cache
        for byte in self.bytes:
            self.cache.append(DataCell(byte, 1))

    def add_relocations(self, relocations):
        self.relocations.extend(relocations)

    def add_global(self, location, label, sz):
        self.named_globals[location].append({
            'label': label,
            'sz': sz,
        })

    def read_at(self, address, sz, signed=False):
        cacheoff = address - self.base

        if cacheoff >= len(self.cache):
            critical("[x] Could not read value in section {} addr {}".format(self.name, address))
            return
        if any([
                not isinstance(x.value, int)
                for x in self.cache[cacheoff:cacheoff + sz]
        ]):
            return None

        bytes_read = [x.value for x in self.cache[cacheoff:cacheoff + sz]]
        bytes_read_padded = bytes_read + [0]*(sz - len(bytes_read))

        
        # https://docs.python.org/2/library/struct.html
        if sz == 1: letter = "B"
        elif sz == 2: letter = "H"
        elif sz == 4: letter = "I"
        elif sz == 8: letter = "Q"
        if signed: letter = letter.lower()

        return struct.unpack("<" + letter, bytes(bytes_read_padded))[0]

    def replace(self, address, sz, value):
        cacheoff = address - self.base

        if cacheoff >= len(self.cache):
            critical("[x] Could not replace value in {} addr {}".format(self.name, address))
            return

        self.cache[cacheoff].value = value
        self.cache[cacheoff].sz = sz

        for cell in self.cache[cacheoff + 1:cacheoff + sz]:
            cell.set_ignored()

    def iter_cells(self):
        location = self.base
        for cidx, cell in enumerate(self.cache):
            if cell.ignored or cell.is_instrumented:
                continue
            yield cidx, location, cell
            location = location + cell.sz

    def __str__(self):
        if not self.cache:
            return ""

        results = []
        results.append(".section {}".format(self.name))

        # fake got is a way to evade relocation hell.
        # see the comment in _adjust_adrp_section_pointer() for more
        if self.name == '.got':
            results.append(".fake_got:")

        if self.name != ".fini_array":
            results.append(".align {}".format(self.align))

        location = self.base
        valid_cells = False

        for cell in self.cache:
            if cell.ignored:
                continue

            valid_cells = True

            if cell.is_instrumented:
                results.append("\t%s" % (cell))
                continue

            if location in self.named_globals:
                for gobj in self.named_globals[location]:
                    symdef = ".type\t{name},@object\n.globl {name}".format(
                        name=gobj["label"])
                    lblstr = "{}: # {:x} -- {:x}".format(
                        gobj["label"], location, location + gobj["sz"])

                    results.append(symdef)
                    results.append(lblstr)

            results.append(".LC%x:" % (location))
            location += cell.sz

            for before in cell.before:
                results.append("\t%s" % (before))

            if self.name == '.bss':
                cell.value = 0
            results.append("\t%s" % (cell))

            for after in cell.after:
                results.append("\t%s" % (after))

        if valid_cells:
            return "\n".join(results)
        else:
            return ""


class DataCell():
    def __init__(self, value, sz):
        self.value = value
        self.sz = sz
        self.ignored = False
        self.is_instrumented = False

        # Instrumentation
        self.before = list()
        self.after = list()

    @staticmethod
    def instrumented(value, sz):
        dc = DataCell(value, sz)
        dc.is_instrumented = True

        return dc

    def set_ignored(self):
        self.ignored = True

    def __str__(self):
        if not self.ignored:
            if self.is_instrumented:
                return self.value
            if isinstance(self.value, int):
                return "%s 0x%x" % (SzPfx.pfx(self.sz), self.value)
            return "%s %s" % (SzPfx.pfx(self.sz), self.value)
        else:
            return ""

    def instrument_before(self, idata):
        assert idata.is_instrumented

        self.before.append(idata)

    def instrument_after(self, idata):
        assert idata.is_instrumented

        self.after.append(idata)
