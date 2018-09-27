from collections import defaultdict
import struct

from capstone import CS_OP_IMM, CS_OP_MEM

from . import disasm


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


class Container():
    def __init__(self):
        self.functions = dict()
        self.function_names = set()
        self.sections = dict()
        self.globals = None
        self.relocations = defaultdict(list)
        self.loader = None

    def add_function(self, function):
        if function.name in self.function_names:
            function.name = "%s_%x" % (function.name, function.start)
        self.functions[function.start] = function
        self.function_names.add(function.name)

    def add_section(self, section):
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

    def attach_loader(self, loader):
        self.loader = loader

    def is_in_section(self, secname, value):
        assert self.loader, "No loader found!"

        section = self.loader.elffile.get_section_by_name(secname)
        base = section['sh_addr']
        sz = section['sh_size']
        if base <= value < base + sz:
            return True
        return False

    def add_relocations(self, section_name, relocations):
        self.relocations[section_name].extend(relocations)

    def function_of_address(self, addr):
        for _, function in self.functions.items():
            if function.start <= addr < function.start + function.sz:
                return function
        return None

    def reloc(self, target):
        assert self.loader, "No loader found!"
        return "import"


class Function():
    def __init__(self, name, start, sz, bytes, bind="STB_LOCAL"):
        self.name = name
        self.cache = list()
        self.start = start
        self.sz = sz
        self.bytes = bytes
        self.bbstarts = set()
        self.bind = bind

        self.bbstarts.add(start)

    def disasm(self):
        assert not self.cache
        for decoded in disasm.disasm_bytes(self.bytes, self.start):
            #if not decoded.mnemonic.startswith("nop"):
            self.cache.append(InstructionWrapper(decoded))

    def instruction_of_address(self, address):
        assert self.cache, "Function not disassembled!"

        for instruction in self.cache:
            if instruction.address <= address < instruction.address + instruction.sz:
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
                results.append("%s" % (instruction))
                continue

            if instruction.address in self.bbstarts:
                results.append(".L%x:" % (instruction.address))
                # XXX: This is a hack!
                results.append(".LC%x:" % (instruction.address))
            else:
                results.append(".LC%x:" % (instruction.address))
            results.append(
                "\t%s %s" % (instruction.mnemonic, instruction.op_str))
        results.append(".size %s,.-%s" % (self.name, self.name))

        return "\n".join(results)


class InstructionWrapper():
    def __init__(self, instruction):
        self.cs = instruction
        self.address = instruction.address
        self.mnemonic = instruction.mnemonic
        self.op_str = instruction.op_str
        self.sz = instruction.size

    def __str__(self):
        return "%x: %s %s" % (self.address, self.mnemonic, self.op_str)

    def get_mem_access_op(self):
        for idx, op in enumerate(self.cs.operands):
            if op.type == CS_OP_MEM:
                return (op.mem, idx)
        return (None, None)


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

    def read_at(self, address, sz):
        cacheoff = address - self.base
        value = struct.unpack(
            "<I",
            bytes([x.value for x in self.cache[cacheoff:cacheoff + sz]]))[0]

        return value

    def replace(self, address, sz, value):
        cacheoff = address - self.base
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
        assert self.cache, "Section not loaded!"

        # XXX: HACK!
        if self.name == ".init_array":
            self.cache = self.cache[1:]

        results = []
        results.append(".align {}".format(self.align))
        results.append(".section {}".format(self.name))
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
            results.append("\t%s" % (cell))

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
