
import argparse
import sys
import io
import struct
from collections import defaultdict
from collections import OrderedDict

from capstone import CS_OP_IMM, CS_GRP_JUMP, CS_GRP_CALL, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP

from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.callframe import FDE, CIE, ZERO
from elftools.dwarf.constants import *
from elftools.dwarf.enums import *
from elftools.dwarf.structs import DWARFStructs
from elftools.common.utils import struct_parse
from elftools.construct import Struct


class Rewriter():
    GCC_FUNCTIONS = [
        "_start",
        "__libc_start_main",
        "__libc_csu_fini",
        "__libc_csu_init",
        "__lib_csu_fini",
        "_init",
        "__libc_init_first",
        "_fini",
        "_rtld_fini",
        "_exit",
        "__get_pc_think_bx",
        "__do_global_dtors_aux",
        "__gmon_start",
        "frame_dummy",
        "__do_global_ctors_aux",
        "__register_frame_info",
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "__frame_dummy_init_array_entry",
        "__init_array_start",
        "__do_global_dtors_aux_fini_array_entry",
        "__init_array_end",
        "__stack_chk_fail",
        "__cxa_atexit",
        "__cxa_finalize",
        "__cxa_begin_catch",
        "__cxa_end_catch",
        "__cxa_allocate_exception",
        "__gxx_personality_v0",
    ]

    DATASECTIONS = [".rodata", ".data", ".bss", ".data.rel.ro", ".init_array"]

    def __init__(self, container, outfile):
        self.container = container
        self.outfile = outfile

        for sec, section in self.container.sections.items():
            section.load()

        for _, function in self.container.functions.items():
            if function.name in Rewriter.GCC_FUNCTIONS:
                continue
            function.disasm()

    def symbolize(self):
        symb = Symbolizer()
        symb.symbolize_text_section(self.container, None)
        symb.symbolize_data_sections(self.container, None)
        symb.recover_ehframe(self.container, None)

    def dump(self):
        results = list()
        for sec, section in sorted(
                self.container.sections.items(), key=lambda x: x[1].base):
            results.append("%s" % (section))

        results.append(".section .text")
        results.append(".align 16")

        for _, function in sorted(self.container.functions.items()):
            """
            if function.name == "frame_dummy":
                results.append("\t.extern frame_dummy\n")
                continue
            """
            if function.name in Rewriter.GCC_FUNCTIONS:
                continue
            results.append("\t.text\n%s" % (function))

        if self.container.personality:
            results.append(self.container.personality)       

        with open(self.outfile, 'w') as outfd:
            outfd.write("\n".join(results + ['']))


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
            # See https://www.airs.com/blog/archives/460, it should be omit in
            # practice
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
                raise Exception("what")

        typetable_encoding = self.elf.read(1)[0]
        typetable_offset = None
        # NOW TODO : the encoding is the right one + 1, which is weird

        self.typetable_offset = 0

        if typetable_encoding != DW_EH_encoding_flags['DW_EH_PE_omit']:
            self.typetable_offset = struct_parse(
                Struct('dummy',
                       self.entry_structs.Dwarf_uleb128('TType')),
                self.elf
            )['TType']
            self.typetable_offset_present = True
        else:
            self.typetable_offset_present = False

        call_site_table_encoding = self.elf.read(1)[0]
        call_site_table_len = struct_parse(
            Struct('dummy',
                   self.entry_structs.Dwarf_uleb128('CSTable')),
            self.elf
        )['CSTable']

        if self.typetable_offset_present == False:
            self.typetable_offset = call_site_table_len

        print("lpstart", lpstart_raw)
        print("lpstart_pcrel", lpstart)
        print("typetable_encoding", typetable_encoding)
        print("call_site_table_encoding", call_site_table_encoding)

        print("CALL SITE TABLE LENGTH %d" % call_site_table_len)
        print("TYPETABLE OFFSET %d" % self.typetable_offset)

        self.end_label = ".LLSDATT%x" % self.fstart
        self.table_label = ".LLSDATTD%x" % self.fstart
        self.action_label = ".LLSDACSE%x" % self.fstart
        self.callsite_label = ".LLSDACSB%x" % self.fstart
        self.ttable_prefix_label = ".LLSDATYP%x" % self.fstart 

        # Need to construct some representation here.
        self.header = {
            "lpstart": lpstart_raw,
            "encoding": call_site_table_encoding,
            "typetable_encoding": typetable_encoding,
            "call_site_table_len": call_site_table_len,
            "cs_act_tt_total_len": self.typetable_offset, # Don't forget to check typetable_offset_present
        }

    def _parse_lsda_entries(self):
        start_cs_offset = self.elf.tell()

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

        processed_bytes = self.elf.tell()-start_cs_offset
        print("+++++ %d bytes read, %d to go, %d actions" % (processed_bytes, self.typetable_offset-processed_bytes, action_count))

        idx = action_count
        processed_action_count = 0

        while idx > 0: 
            
            action = struct_parse(
                Struct("ActionEntry",
                    self.entry_structs.Dwarf_uint8('act_filter'),
                    self.entry_structs.Dwarf_uint8('act_next')
                ),
                self.elf
            )
            
            print(">>>> ACTION ", action)
            self.actions.append(action)
            processed_action_count = processed_action_count + 1
            idx -= 1


        ttendloc = self.lsda_offset+self.typetable_offset+3
        
        print("TT %x" % (ttendloc))
        for action in self.actions:

            type_bytes_offset = (action.act_filter * -8)
            ttentryloc = ttendloc + type_bytes_offset
            print("****** TT LOC: %x" % (ttentryloc))
            self.elf.seek(ttentryloc, io.SEEK_SET)
            ptrbytes = self.elf.read(8)
            ptr = struct.unpack("<Q", ptrbytes)[0]
            print("****** TT PTR: %x" % ptr)

            symbolized_target = 0
            if ptr != 0:
                symbolized_target = ptr + ttentryloc

            typeentry = {'address': symbolized_target}
            self.ttentries[action.act_filter] = typeentry
            print("****** TT x: %x" % (symbolized_target))            

    
    def generate_tableoffset(self):
        ttoffset = ""
        if self.typetable_offset_present:
            ttoffset = ".uleb128 %s-%s" % (self.end_label, self.table_label)
        else:
            ttoffset = "# @TType Encoding is DW_EH_PE_omit, ignoring."
        return ttoffset    
    
    def generate_header(self):
        print("generate header", self.fstart)
        print("generate table label", self.table_label)

        ttoffset = self.generate_tableoffset()

        table_header = """
.LFE%x:
    .section	.gcc_except_table,"a",@progbits
    .align 4
GCC_except_table%x:
.LLSDA%x:
    .byte 0x%x   # @LPStart encoding
    .byte 0x%x   # @TType Encoding
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
        print("generate table", self.fstart)
        table = """
    .uleb128 %s-%s
.LLSDACSB%x:
%s
.LLSDACSE%x:
    %s
    .align 4
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
            if self.fstart + entry["cs_start"] + entry["cs_len"] >= function_end:
                cbw_e = "E"
            jlo_e = ""
            if self.fstart + entry["cs_lp"] >= function_end:
                jlo_e = "E"

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

            cse = "\t.uleb128 .LC%x-.L%x    \t# Call Site Entry (%u)" % (self.fstart + entry["cs_start"], self.fstart, entry["cs_start"])
            cbw = "\t.uleb128 .LC%s%x-.LC%x \t# Call Between (%u)" % (cbw_e, self.fstart + entry["cs_start"] + entry["cs_len"], self.fstart + entry["cs_start"], entry["cs_len"])
            jlo = "\t.uleb128 .LC%s%x-.L%x  \t# Jump Location (%u)" % (jlo_e, self.fstart + entry["cs_lp"], self.fstart, entry["cs_lp"]) 
            act = "\t.uleb128 0x%x          \t# Action\n" % (entry["cs_action"])
            return "\n".join([cse, cbw, jlo, act])

        
        return "\n".join(map(callsite_ftr, self.entries))

    def generate_typetable(self):

        ttable = ""
        i = 1
        for idx, tp in reversed(list(self.ttentries.items())):
            print("*******", idx)
            label = "%sE%s" % (self.ttable_prefix_label,i)
            i+=1

            target_label = ""
            if tp["address"] != 0:
                target_label = ".LC%x-." % (tp["address"])
                #target_label = ".LC%x" % (tp["address"])
            else:
                target_label = "0"
            
            ttable += """
%s:
     .quad %s
            """ % (label, target_label)


        return ttable
    
    def generate_actions(self):
        action_table = "\n"
        
        for action in self.actions:

            action_table += "# Action Filter and Next Record\n"
            action_table += "    .byte %u\n" % (action["act_filter"])
            action_table += "    .byte %u\n" % (action["act_next"]) 
            action_table += "\n"

        return action_table
    
    def generate_footer(self):
        return "%s:\n" % self.end_label

class Symbolizer():
    def __init__(self):
        self.bases = set()
        self.pot_sw_bases = defaultdict(set)
        self.symbolized = set()

    # TODO: Use named symbols instead of generic labels when possible.
    # TODO: Replace generic call labels with function names instead
    def symbolize_text_section(self, container, context):
        # Symbolize using relocation information.
        for rel in container.relocations[".text"]:
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
                        self.pot_sw_bases[fn.start].add(ripbase + value)
                else:
                    print("[*] Possible incorrect handling of relocation!")
                    value = mem_access.disp
                    inst.op_str = inst.op_str.replace(
                        hex(value), ".LC%x" % (rel['st_value']))

            self.symbolized.add(inst.address)

        self.symbolize_cf_transfer(container, context)
        # Symbolize remaining memory accesses
        self.symbolize_mem_accesses(container, context)
        self.symbolize_switch_tables(container, context)

    def symbolize_cf_transfer(self, container, context=None):
        for _, function in container.functions.items():
            addr_to_idx = dict()
            for inst_idx, instruction in enumerate(function.cache):
                addr_to_idx[instruction.address] = inst_idx

            for inst_idx, instruction in enumerate(function.cache):

                is_jmp = CS_GRP_JUMP in instruction.cs.groups
                is_call = CS_GRP_CALL in instruction.cs.groups

                if not (is_jmp or is_call):
                    # Simple, next is idx + 1
                    if instruction.mnemonic.startswith('ret'):
                        function.nexts[inst_idx].append("ret")
                        instruction.cf_leaves_fn = True
                    else:
                        function.nexts[inst_idx].append(inst_idx + 1)
                    continue

                instruction.cf_leaves_fn = False

                if is_jmp and not instruction.mnemonic.startswith("jmp"):
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

                if instruction.cs.operands[0].type == CS_OP_IMM:
                    target = instruction.cs.operands[0].imm
                    # Check if the target is in .text section.
                    if container.is_in_section(".text", target):
                        function.bbstarts.add(target)
                        instruction.op_str = ".L%x" % (target)
                    elif target in container.plt:
                        instruction.op_str = "{}@PLT".format(
                            container.plt[target])
                    else:
                        gotent = container.is_target_gotplt(target)
                        if gotent:
                            found = False
                            for relocation in container.relocations[".dyn"]:
                                if gotent == relocation['offset']:
                                    instruction.op_str = "{}@PLT".format(
                                        relocation['name'])
                                    found = True
                                    break
                            if not found:
                                print("[x] Missed GOT entry!")
                        else:
                            print("[x] Missed call target: %x" % (target))

                    if is_jmp:
                        if target in addr_to_idx:
                            idx = addr_to_idx[target]
                            function.nexts[inst_idx].append(idx)
                        else:
                            instruction.cf_leaves_fn = True
                            function.nexts[inst_idx].append("undef")
                elif is_jmp:
                    function.nexts[inst_idx].append("undef")

    def symbolize_switch_tables(self, container, context):
        rodata = container.sections.get(".rodata", None)
        if not rodata:
            return

        all_bases = set([x for _, y in self.pot_sw_bases.items() for x in y])

        for faddr, swbases in self.pot_sw_bases.items():
            fn = container.functions[faddr]
            for swbase in sorted(swbases, reverse=True):
                value = rodata.read_at(swbase, 4)
                if not value:
                    continue

                value = (value + swbase) & 0xffffffff
                if not fn.is_valid_instruction(value):
                    continue

                # We have a valid switch base now.
                swlbl = ".LC%x-.LC%x" % (value, swbase)
                rodata.replace(swbase, 4, swlbl)

                # Symbolize as long as we can
                for slot in range(swbase + 4, rodata.base + rodata.sz, 4):
                    if any([x in all_bases for x in range(slot, slot + 4)]):
                        break

                    value = rodata.read_at(slot, 4)
                    if not value:
                        break

                    value = (value + swbase) & 0xFFFFFFFF
                    if not fn.is_valid_instruction(value):
                        break

                    swlbl = ".LC%x-.LC%x" % (value, swbase)
                    rodata.replace(slot, 4, swlbl)

    def _adjust_target(self, container, target):
        # Find the nearest section
        sec = None
        for sname, sval in sorted(
                container.sections.items(), key=lambda x: x[1].base):
            if sval.base >= target:
                break
            sec = sval

        assert sec is not None

        end = sec.base  # + sec.sz - 1
        adjust = target - end

        assert adjust > 0

        return end, adjust

    def _is_target_in_region(self, container, target):
        for sec, sval in container.sections.items():
            if sval.base <= target < sval.base + sval.sz:
                return True

        for fn, fval in container.functions.items():
            if fval.start <= target < fval.start + fval.sz:
                return True

        return False

    def symbolize_mem_accesses(self, container, context):
        for _, function in container.functions.items():
            for inst in function.cache:
                if inst.address in self.symbolized:
                    continue

                mem_access, _ = inst.get_mem_access_op()
                if not mem_access:
                    continue

                # Now we have a memory access,
                # check if it is rip relative.
                base = mem_access.base
                if base == X86_REG_RIP:
                    value = mem_access.disp
                    ripbase = inst.address + inst.sz
                    target = ripbase + value

                    is_an_import = False

                    for relocation in container.relocations[".dyn"]:
                        if relocation['st_value'] == target:
                            is_an_import = relocation['name']
                            sfx = ""
                            break
                        elif target in container.plt:
                            is_an_import = container.plt[target]
                            sfx = "@PLT"
                            break
                        elif container.got[target] and \
                             relocation['offset'] == target:
                            is_an_import = relocation['name']
                            sfx = "@GOTPCREL"
                            break
                        elif relocation['offset'] == target:
                            # XXX
                            #is_an_import = relocation['name']
                            #sfx = "@GOTPCREL"
                            break
                        else:
                            sym = container.imports[target]
                            if sym:
                                ele = next(iter(sym))
                                is_an_import = "%d+%s"%(target-ele.begin, ele.data)
                                sfx = ""

                    if is_an_import:
                        inst.op_str = inst.op_str.replace(
                            hex(value), "%s%s" % (is_an_import, sfx))
                    else:
                        # Check if target is contained within a known region
                        in_region = self._is_target_in_region(
                            container, target)
                        if in_region:
                            inst.op_str = inst.op_str.replace(
                                hex(value), ".LC%x" % (target))
                        else:
                            target, adjust = self._adjust_target(
                                container, target)
                            inst.op_str = inst.op_str.replace(
                                hex(value), "%d+.LC%x" % (adjust, target))
                            print("[*] Adjusted: %x -- %d+.LC%x" %
                                  (inst.address, adjust, target))

                    if container.is_in_section(".rodata", target):
                        self.pot_sw_bases[function.start].add(target)

    def _handle_relocation(self, container, section, rel):
        reloc_type = rel['type']
        if reloc_type == ENUM_RELOC_TYPE_x64["R_X86_64_PC32"]:
            swbase = None
            for base in sorted(self.bases):
                if base > rel['offset']:
                    break
                swbase = base
            value = rel['st_value'] + rel['addend'] - (rel['offset'] - swbase)
            swlbl = ".LC%x-.LC%x" % (value, swbase)
            section.replace(rel['offset'], 4, swlbl)
        elif reloc_type == ENUM_RELOC_TYPE_x64["R_X86_64_64"]:
            # C++ ABI functions, to be ignored
            # if not (rel["name"].startswith("_ZTV") or rel["name"] == "__gxx_personality_v0"):
            if rel['st_value']:
                value = rel['st_value'] + rel['addend']
                label = ".LC%x" % value
            else:
                label = "%s+%d" % (rel['name'], rel['addend'])
            section.replace(rel['offset'], 8, label)
        elif reloc_type == ENUM_RELOC_TYPE_x64["R_X86_64_RELATIVE"]:
            value = rel['addend']
            label = ".LC%x" % value
            section.replace(rel['offset'], 8, label)
        elif reloc_type == ENUM_RELOC_TYPE_x64["R_X86_64_COPY"]:
            # NOP
            pass
        else:
            print("[*] Unhandled relocation {}".format(
                describe_reloc_type(reloc_type, container.loader.elffile)))

    def symbolize_data_sections(self, container, context=None):
        # Section specific relocation
        for secname, section in container.sections.items():
            for rel in section.relocations:
                self._handle_relocation(container, section, rel)

        # .dyn relocations
        dyn = container.relocations[".dyn"]
        for rel in dyn:
            section = container.section_of_address(rel['offset'])
            if section:
                # rela.dyn relocations in .init_array are likely libc-specific 
                # logic, e.g. frame_dummy, so let us skip this and allow libc to rebuild this
                # when we recompile.
                if section.__dict__['name'] == '.init_array':
                    # If the address does not point to anywhere
                    if not container.function_of_address(rel["addend"]):
                        continue
                    # Because we removed the frame_dummy pointer from the
                    # beginning of init_array, we should offset the other
                    # pointers in that section
                    rel["offset"] -= 8
                self._handle_relocation(container, section, rel)
            else:
                print("[x] Couldn't find valid section {:x}".format(
                    rel['offset']))
    
    # We find all vtables and put them in self.vtables
    def _find_all_vtables(self, container):
        container.put_vtable_stuff_here()

        symbol_tables = [
            sec for sec in container.loader.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        for section in symbol_tables:
            for symbol in section.iter_symbols():
                # We find the vtable entries in the symbol table
                if (symbol['st_info']['type'] == "STT_OBJECT"
                        and symbol.name.startswith("_ZTV")):
                    # self.vtables[symbol['']]
                    # print(symbol.name)
                    pass
    
    def is_vtable_relocation(self, relocation):
        return True


    def recover_ehframe(self, container, context=None):
        # BEGIN __init__
        dwarf_map = dict()

        # Mapping from function name to a map from instruction offset in cache
        # to the cfi directive to be added before that line.
        cfi_map = defaultdict(lambda: defaultdict(list))
        # END __init__

        ehframe_entries = container.loader.elffile.get_dwarf_info().EH_CFI_entries()

        lsda_encoding = None
        # lsdas = list(sorted(container.loader.elffile.get_dwarf_info()["gcc_except_table"]["lsdas"],
        #                     key=lambda x: x["idx"]))

        print(container.functions)

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
                print(entry.__dict__)
                #print("Function Address: %s" % hex(initial_location))
                lsda_table = None
                #print("lsda pointer", entry.lsda_pointer)
                if entry.lsda_pointer:
                    #print("LDSA Pointer: %s" % entry.lsda_pointer)
                    lsda_table = LSDATable(container.loader.elffile.stream, entry.lsda_pointer, initial_location, container)
                    dwarf_map[initial_location] = lsda_table.generate_header()
                    dwarf_map[initial_location] += lsda_table.generate_table()
                    # SHOULD LOOK LIKE THIS :
                    # for entry in lsda_table.entries
                    #     dwarf_map[...] = entry...

                location = initial_location

                function = container.functions.get(initial_location)
                if not function:
                    print("Could not find function at location %d, is this normal ?" % initial_location)
                    continue
                current = cfi_map[function.start]

                # For each DWARF instruction in the instruction list, what do we do?
                for instruction in entry.instructions:
                    print(">>>>>", instruction)
                    
                    # This is decoding the DWARF virtual machine instructions :)
                    # Some of these directly correspond to assembler directives we 
                    # can emit at appropriate locations in the assembly.
                    # Advance tells us how to move through that function, but
                    # TODO: haven't properly decoded it yet.

                    opcode = instruction.opcode
                    args = instruction.args

                    #print([opcode] + args)
                    original_location = location
                    location, cfi_line = interpret_dwarf_instruction(location, [opcode] + args)
                    #print("Were're at", location, "and CFI line is", cfi_line)
                    if cfi_line:
                        current[location].append("\t"+cfi_line)


            elif type(entry) == CIE:
                # We can process the CIE entries, which is nice.
                print(entry.header)
                print(entry.augmentation_dict)
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
                    print("Personality Function: 0x%x" % personality_function)
                lsda_encoding = entry.augmentation_dict.get('LSDA_encoding', None)
                if lsda_encoding:
                    print("LSDA Encoding %d" % lsda_encoding)
            elif type(entry) == ZERO:
                print(entry.offset)
            else:
                raise Exception("Unhandled type %s" % (type(entry)))
            #print("----\n")
      

        # Check if any cfi information needs to be added
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
        # END rewrite_table


    
def interpret_dwarf_instruction(current_loc, instruction):
    DATA_ALIGN = 8
    cfi_line = None
    # instruction = instruction.strip().split()

    # ADVANCE_LOC = 64 = 0x40
    # OFFSET = 128 = 0x80
    # RESTORE = 192 = 

    #General Purpose Register RAX 0 %rax
    #General Purpose Register RDX 1 %rdx
    #General Purpose Register RCX 2 %rcx
    #General Purpose Register RBX 3 %rbx
    #General Purpose Register RSI 4 %rsi
    #General Purpose Register RDI 5 %rdi
    #Frame Pointer Register RBP 6 %rbp
    #Stack Pointer Register RSP 7 %rsp
    #Extended Integer Registers 8-15 8-15 %r8–%r15

    dwarf_x86_64_regmap = {0: 'rax', 1: 'rdx', 2: 'rcx', 3: 'rbi', 4: 'rsi', 5: 'rdi', 6: 'rbp', 7: 'rsp'}

    for i in range(8, 16):
        dwarf_x86_64_regmap[i] = "r%d" % i


    print("+++++ Instruction being handled! ++++++", instruction)
    if instruction[0] == DW_CFA_advance_loc + DW_CFA_advance_loc1:
        current_loc += instruction[1]
    elif instruction[0] == DW_CFA_advance_loc + DW_CFA_advance_loc2:
        current_loc += instruction[1]
    elif instruction[0] == DW_CFA_advance_loc + DW_CFA_advance_loc4:
        current_loc += instruction[1]
    elif instruction[0] == DW_CFA_advance_loc + DW_CFA_set_loc:
        current_loc = instruction[1]

    elif instruction[0] == DW_CFA_def_cfa_offset:
        cfi_line = ".cfi_def_cfa_offset %s\n\t.cfi_offset rbp, -%d" % (instruction[1], instruction[1])
    elif instruction[0] == DW_CFA_offset:
        cfi_line = ".cfi_offset %s, -%d" % (dwarf_x86_64_regmap.get(instruction[1], instruction[1]),
                                            instruction[2] * DATA_ALIGN)
    elif instruction[0] == DW_CFA_def_cfa_register:
        cfi_line = ".cfi_def_cfa_register %s" % dwarf_x86_64_regmap.get(instruction[1], instruction[1])
    elif instruction[0] == DW_CFA_def_cfa:
        cfi_line = ".cfi_def_cfa %s, %s" % (dwarf_x86_64_regmap.get(instruction[1], instruction[1]),
                                            instruction[2])
    elif instruction[0] == DW_CFA_remember_state:
        cfi_line = ".cfi_remember_state"
    elif instruction[0] == DW_CFA_restore:
        cfi_line = ".cfi_restore %s" % dwarf_x86_64_regmap.get(instruction[1], instruction[1])
    elif instruction[0] == DW_CFA_restore + DW_CFA_restore_state:
        cfi_line = ".cfi_restore_state" 
    elif instruction[0] == DW_CFA_nop:
        pass
    
    else:
        print("[x] Unhandled DWARF instruction: %x" % instruction[0])
        if instruction[0] > 192:
            print("RESTORE+",instruction[0]-192)
        if instruction[0] > 128 and instruction[0] < 192:
            print("OFFSET",instruction[0]-128)
        if instruction[0] > 64 and instruction[0] < 128:
            print("ADVANCE_LOC+",instruction[0]-64)

        print(instruction)
    return current_loc, cfi_line


if __name__ == "__main__":
    from .loader import Loader
    from .analysis import register

    argp = argparse.ArgumentParser()

    argp.add_argument("bin", type=str, help="Input binary to load")
    argp.add_argument("outfile", type=str, help="Symbolized ASM output")
    argp.add_argument("--ignore-no-pie", dest="ignore_no_pie", action='store_true', help="Ignore position-independent-executable check (use with caution)")
    argp.add_argument("--ignore-stripped", dest="ignore_stripped", action='store_true',
                      help="Ignore stripped executable check (use with caution)")
    argp.set_defaults(ignore_no_pie=False)
    argp.set_defaults(ignore_stripped=False)

    args = argp.parse_args()

    loader = Loader(args.bin)

    if loader.is_pie() == False and args.ignore_no_pie == False:
        print("RetroWrite requires a position-independent executable.")
        print("It looks like %s is not position independent" % args.bin)
        sys.exit(1)

    if loader.is_stripped() == True and args.ignore_stripped == False:
        print("RetroWrite requires a none stripped executable.")
        print("It looks like %s is stripped" % args.bin)
        sys.exit(1)


    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    loader.load_data_sections(slist, lambda x: x in Rewriter.DATASECTIONS)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    global_list = loader.global_data_list_from_symtab()
    loader.load_globals_from_glist(global_list)

    loader.identify_imports()

    loader.container.attach_loader(loader)

    rw = Rewriter(loader.container, args.outfile)
    rw.symbolize()
    rw.dump()
