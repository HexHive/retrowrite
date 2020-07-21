from collections import defaultdict, namedtuple
import struct

from capstone import *
from elftools.elf.constants import SH_FLAGS
from elftools.elf.enums import ENUM_E_TYPE
from intervaltree import Interval, IntervalTree

md = None

def disasm_bytes(bytes, addr):
    global md
    if not md:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_ATT
        md.detail = True

    ret = []

    for i in md.disasm(bytes, addr.offset):
        address = Address(addr.section, i.address)
        ret.append(InstructionWrapper(i, address))

    return ret


class SzPfx():
    PREFIXES = {
        1: '.byte',
        2: '.word',
        4: '.long',
        8: '.quad',
        16: '.xmmword',
    }

    @staticmethod
    def pfx(sz):
        return SzPfx.PREFIXES[sz]


class Address(namedtuple('Address', 'section offset')):
    __slots__ = ()

    def as_dict(self):
        return {'section': self.section.name, 'offset': self.offset}

    def __str__(self):
        return '%s%x' % (self.section.name.replace('-', '_'), self.offset)

    def __hash__(self):
        return hash(self.section.name) ^ hash(self.offset)

    def __eq__(self, other):
        return (other.section.name == self.section.name and
                other.offset == self.offset)

class Container():
    def __init__(self):
        # Using an IntervalTree instead of a dict containing the starting address
        # of each function for function_of_address saves 25-30% of the run time
        # when symbolizing btrfs (approx 4.3 out of 16 seconds)
        self.functions = defaultdict(IntervalTree)

        self.function_names = set()
        self.code_section_names = set()
        self.sections = dict()
        self.globals = None
        self.code_relocations = defaultdict(list)
        self.loader = None
        # PLT information
        self.plt_base = None
        self.plt = dict()

        self.gotplt_base = None
        self.gotplt_sz = None
        self.gotplt_entries = list()

    def add_function(self, function):
        if function.name in self.function_names:
            function.name = "%s_%s" % (function.name, function.address)

        function_start = function.address.offset
        function_end = function.address.offset + function.sz

        # Add the function to the interval tree unless there is already a function there
        if not self.functions[function.address.section.name][function_start:function_end] and function_start != function_end:
            self.functions[function.address.section.name][function_start:function_end] = function

        self.function_names.add(function.name)
        self.code_section_names.add(function.address.section.name)

    def add_section(self, section):
        self.sections[section.name] = section

    def add_globals(self, globals):
        self.globals = globals
        for gobj in globals:
            self.sections[gobj['section'].name].add_global(gobj['offset'], gobj['name'], gobj['sz'])


    def is_target_gotplt(self, target):
        if not self.gotplt_base or not self.gotplt_sz:
            return False

        if not (self.gotplt_base <= target <
                self.gotplt_base + self.gotplt_sz):
            return False

        for ent in self.gotplt_entries:
            if ent.address == target:
                if (CS_GRP_JUMP in ent.groups
                        and ent.operands[0].type == CS_OP_MEM):
                    return ent.operands[0].mem.disp + ent.address + ent.size

        return False

    def get_function_by_name(self, name):
        for fn in self.iter_functions():
            if name == fn.name:
                return fn
        else:
            return None

    def attach_loader(self, loader):
        self.loader = loader

    def add_code_relocations(self, section_name, relocations):
        self.code_relocations[section_name].extend(relocations)

    def function_of_address(self, addr):
        if addr.section.name not in self.functions:
            return None

        function_data = self.functions[addr.section.name][addr.offset]
        if not function_data:
            return None

        interval, = function_data
        return interval.data

    def iter_functions(self):
        for _, it in self.functions.items():
            for i in it:
                yield i.data

    def adjust_address(self, address):
        if self.loader.elffile['e_type'] == 'ET_REL':
            # Relocatable file, there can't be cross-section references unless
            # they use relocations
            assert address.offset >= 0 and address.offset < address.section.data_size

            return address
        elif self.loader.elffile['e_type'] == 'ET_DYN':
            # Position-independent userspace binary, there can be cross-section
            # references
            if address.offset >= 0 and address.offset < address.section.data_size:
                # The address is still inside this section
                return address

            absolute_address = address.section['sh_addr'] + address.offset

            # The address points to a different section
            for section in self.loader.elffile.iter_sections():
                if section['sh_addr'] <= absolute_address < section['sh_addr'] + section.data_size:
                    return Address(section, absolute_address - section['sh_addr'])

        else:
            # What is this binary?
            assert False

    def reloc(self, target):
        assert self.loader, "No loader found!"
        return "import"


class Function():
    def __init__(self, name, address, sz, bytes, container, bind="STB_LOCAL"):
        self.name = name
        self.cache = list()
        self.address = address
        self.sz = sz
        self.bytes = bytes
        self.bbstarts = set()
        self.container = container
        self.bind = bind

        # Populated during symbolization.
        # Invalidated by any instrumentation.
        self.nexts = defaultdict(list)

        self.bbstarts.add(address)

        # Dict to save function analysis results
        self.analysis = defaultdict(lambda: None)

        # Is this an instrumented function?
        self.instrumented = False

    def set_instrumented(self):
        self.instrumented = True

    def disasm(self):
        assert not self.cache
        self.cache = disasm_bytes(self.bytes, self.address)

    def is_valid_instruction(self, address):
        assert self.cache, "Function not disassembled!"

        if address.section != self.address.section:
            return False

        for instruction in self.cache:
            if instruction.address.offset == address.offset:
                return True

        return False

    def instruction_of_address(self, address):
        assert self.cache, "Function not disassembled!"

        if address.section != self.address.section:
            return None

        for instruction in self.cache:
            if instruction.address.offset <= address.offset < instruction.address.offset + instruction.sz:
                return instruction

        return None

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
                results.append(".L%s:" % str(instruction.address))
                results.append(".LC%s:" % str(instruction.address))
            else:
                results.append(".LC%s:" % str(instruction.address))

            for iinstr in instruction.before:
                results.append("{}".format(iinstr))

            results.append('.LCorig_%s:' % str(instruction.address))

            # HACK: gas will assemble 'nopl 0(%rax, %rax, 1)' as a 4-byte NOP but
            # in the original module it might be 5 bytes
            if instruction.sz == 5 and instruction.mnemonic == 'nopl':
                results.append("\t.byte 0x0f, 0x1f, 0x44, 0x00, 0x00")
            else:
                results.append(
                    "\t%s %s" % (instruction.mnemonic, instruction.op_str))

            for iinstr in instruction.after:
                results.append("{}".format(iinstr))

        results.append(".size %s,.-%s" % (self.name, self.name))

        # Add a label for the address after the end of the function (used for unwind information)
        # but only if there is not already another function at the same address
        address_after_end = Address(self.cache[-1].address.section, self.cache[-1].address.offset + self.cache[-1].sz)

        if not self.container.function_of_address(address_after_end):
            results.append('.LC%s:' % str(address_after_end))

        return "\n".join(results)

    def next_of(self, instruction_idx):
        nexts = list()
        for x in self.nexts[instruction_idx]:
            if isinstance(x, str):
                nexts.append(x)
            else:
                nexts.append(x)
        return nexts


class InstructionWrapper():
    def __init__(self, instruction, address):
        self.cs = instruction
        self.address = address
        self.mnemonic = instruction.mnemonic
        self.op_str = instruction.op_str
        self.sz = instruction.size

        # Instrumentation cache for this instruction
        self.before = list()
        self.after = list()

        # CF Leaves function?
        self.cf_leaves_fn = None

    def __str__(self):
        return "%s: %s %s" % (self.address, self.mnemonic, self.op_str)

    def get_mem_access_op(self):
        for idx, op in enumerate(self.cs.operands):
            if op.type == CS_OP_MEM:
                return (op.mem, idx)
        return (None, None)

    def get_imm_op(self):
        for idx, op in enumerate(self.cs.operands):
            if op.type == CS_OP_IMM:
                return (op.imm, idx)
        return (None, None)

    def reg_reads(self):
        # Handle nop
        if self.mnemonic.startswith("nop"):
            return []
        regs = self.cs.regs_access()[0]
        return [self.cs.reg_name(x) for x in regs]

    def reg_writes(self):
        # Handle nop
        if self.mnemonic.startswith("nop"):
            return []
        regs = self.cs.regs_access()[1]
        return [self.cs.reg_name(x) for x in regs]

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
    def __init__(self, name, base, sz, bytes, flags, type, align=16):
        self.name = name
        self.cache = list()
        self.base = base
        self.sz = sz
        self.bytes = bytes
        self.relocations = list()
        self.align = align
        self.flags = flags
        self.type = type
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

    def read_at(self, address, sz):
        cacheoff = address - self.base
        if any([
                not isinstance(x.value, int)
                for x in self.cache[cacheoff:cacheoff + sz]
        ]):
            return None

        value = struct.unpack(
            "<I",
            bytes([x.value for x in self.cache[cacheoff:cacheoff + sz]]))[0]

        return value

    def replace(self, offset, sz, value):
        # cacheoff = address - self.base

        if offset >= len(self.cache):
            print("[x] Could not replace value in {}".format(self.name))
            return

        self.cache[offset].value = value
        self.cache[offset].sz = sz

        for cell in self.cache[offset + 1:offset + sz]:
            cell.set_ignored()

    def get_closest_non_ignored_offset(self, offset):
        if offset >= len(self.cache):
            return len(self.cache) - 1

        if not self.cache[offset].ignored:
            return offset

        ret = offset - 1

        while ret >= 0:
            if not self.cache[ret].ignored:
                return ret

            ret -= 1

        raise RuntimeError('Invalid data address')

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

        flags = ''
        if (self.flags & SH_FLAGS.SHF_ALLOC) != 0:
            flags += 'a'
        if (self.flags & SH_FLAGS.SHF_WRITE) != 0:
            flags += 'w'
        if (self.flags & SH_FLAGS.SHF_EXECINSTR) != 0:
            flags += 'x'

        results.append('.section {},"{}",@{}'.format(self.name, flags, self.type[4:].lower()))

        if self.name != ".fini_array":
            results.append(".align {}".format(self.align))

        # location = self.base
        location = 0
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

            # GAS doesn't like '-' in section names
            results.append(".LC%s%x:" % (self.name.replace('-', '_'), location))
            location += cell.sz

            for before in cell.before:
                results.append("\t%s" % (before))

            if self.name == '.bss':
                cell.value = 0

            if self.name == '.altinstructions':
                results.append("\t%s" % (str(cell).replace('.LC.text', '.LCorig_.text')))
            else:
                results.append("\t%s" % (cell))

            for after in cell.after:
                results.append("\t%s" % (after))

        # Append a label after the end of the section
        results.append(".LC%s%x:" % (self.name.replace('-', '_'), location))

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
