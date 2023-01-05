#!/usr/bin/env python

import struct
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import SH_FLAGS
from elftools.dwarf.callframe import FDE

from .container import Container, Function, Section, disasm_bytes, CHANGE_NAME_SECS
from .rw import Rewriter

from librw_arm64.util.logging import debug, info, critical


class Loader():
    def __init__(self, fname):
        debug(f"Loading {fname}...")
        self.fname = fname
        self.fd = open(fname, 'rb')
        self.elffile = ELFFile(self.fd)
        self.container = Container()
        self.dependencies = self.parse_elf_dependencies()
        self.load_symbols()

    def is_stripped(self):
        if self.is_go_binary(): # we can recover functions from .gopclntab
            return False

        # Get the symbol table entry for the respective symbol
        symtab = self.elffile.get_section_by_name('.symtab')
        if not symtab:
            print('No symbol table available, this file is probably stripped!')
            return True
        return False

    def is_library(self):
        symtab = self.elffile.get_section_by_name('.symtab')
        if not symtab:
            return False

        sym = symtab.get_symbol_by_name("main")
        if not sym or not sym[0]:
            print('Symbol {} not found')
            return True
        return False

    def is_pie(self):
        base_address = next(seg for seg in self.elffile.iter_segments() 
                if seg['p_type'] == "PT_LOAD")['p_vaddr']
        return self.elffile['e_type'] == 'ET_DYN' and base_address == 0

    def load_symbols(self):
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]
        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                continue
            for symbol in section.iter_symbols():
                if not len(symbol.name):
                    continue
                symbol.secname = section.name
                symbol.name = self.sanitize_symbol_name(symbol.name)
                self.container.symbols += [symbol]

    def extract_functions_eh_frame(self):
        funcs = []
        try:
            ehframe_entries = self.elffile.get_dwarf_info().EH_CFI_entries()
            for entry in ehframe_entries:
                if type(entry) == FDE:
                    initial_location = entry.header.initial_location
                    size = entry.header.address_range
                    if size == 0: 
                        continue # probably a weak symbol ? 
                    funcs += [(initial_location, size)]
            return funcs
        except:
            return []

    def sanitize_symbol_name(self, name):
        for x in "\'\",-{}; []/*@()%:<>\\":
            name = name.replace(x, "_")
        return name


    def load_functions(self, fnlist, use_ghidra=False):
        debug("Loading functions...")
        if use_ghidra: return self.load_functions_ghidra(fnlist)
        text_section = self.elffile.get_section_by_name(".text")
        data = text_section.data()
        base = text_section['sh_addr']
        if not self.is_stripped(): # fnlist is not empty
            for faddr, fvalue in fnlist.items():
                sec = self.container.section_of_address(faddr)
                if not sec: continue
                sec.functions += [faddr]
                sec.functions_ends += [faddr + fvalue["sz"]]

                section_offset = faddr - base
                bytes = data[section_offset:section_offset + fvalue["sz"]]

                # replace banned chars
                fixed_name = self.sanitize_symbol_name(fvalue['name'])
                bind = fvalue["bind"] if fixed_name not in ["main", "_init"] else "STB_GLOBAL" #main and _init should always be global
                function = Function(fixed_name, faddr, fvalue["sz"], bytes, bind)
                self.container.add_function(function)

        # is it stripped? 
        else:
            ehfuncs = self.extract_functions_eh_frame()
            # expand ehfuncs with fnlist
            for addr, fn in fnlist.items():
                if (addr, fn['sz']) not in ehfuncs:
                    ehfuncs += [(addr, fn['sz'])]
            ehfuncs = sorted(ehfuncs)
            if len(ehfuncs):
                for e, item in enumerate(ehfuncs):
                    faddr, size = item
                    sec = self.container.section_of_address(faddr)
                    sec.functions += [faddr]
                    sec.functions_ends += [faddr + size]
                    section_offset = faddr - base
                    bytes = sec.bytes[section_offset:section_offset + size]

                    fixed_name = f"func_{hex(faddr)}"
                    if faddr in fnlist: # if by chance we do actually have function names (android)
                        fixed_name = self.sanitize_symbol_name(fnlist[faddr]['name'])
                    
                    bind = "STB_GLOBAL" #main and _init should always be global
                    function = Function(fixed_name, faddr, size, bytes, bind)
                    self.container.add_function(function)

                    if e+1 < len(ehfuncs): 
                        next_addr = ehfuncs[e+1][0]
                        if next_addr > sec.base + sec.sz: # next function is in another section?
                            continue
                    else:
                        next_addr = sec.base + sec.sz # go until the end of the current section


                    if faddr + size != next_addr:
                        new_addr = faddr + size
                        new_size = next_addr - new_addr
                        new_section_offset = new_addr - base
                        debug("adding filler function at addr ", hex(new_addr), "with size", new_size)
                        new_bytes = sec.bytes[new_section_offset:new_section_offset + new_size]
                        new_function = Function(f"filler_{hex(new_addr)}", new_addr, new_size, new_bytes, bind)
                        self.container.add_function(new_function)
                        self.container.section_of_address(new_addr).functions += [new_addr]
                        self.container.section_of_address(new_addr).functions_ends += [new_addr + new_size]

                for sec in self.container.codesections.values():
                    if len(sec.functions):
                        first_func_start = sorted(sec.functions)[0]
                        if sec.base <= first_func_start:
                            newsize = first_func_start - sec.base
                            debug("adding filler function at addr ", hex(sec.base), "with size", first_func_start)
                            new_bytes = sec.bytes[:newsize]
                            new_function = Function(f"filler_{hex(sec.base)}", sec.base, newsize, new_bytes, "STB_GLOBAL")
                            self.container.add_function(new_function)
                            sec.functions += [sec.base]
                            sec.functions_ends += [sec.base + newsize]



            # else: # no functions detected, just assume there is a single big one to make everything work 
            for sec in self.container.codesections:
                # if sec in [".plt"]: continue # plt needs to be regenerated, do not treat it as function
                if len(self.container.codesections[sec].functions) == 0:
                    section = self.elffile.get_section_by_name(sec)
                    base = section["sh_addr"]
                    data = section.data()
                    function = Function(f"all_{sec}", base, len(data), data, "STB_GLOBAL")
                    self.container.codesections[sec].functions += [base]
                    self.container.codesections[sec].functions_ends += [base + len(data)]
                    self.container.add_function(function)


        # entrypoint = self.elffile.header.e_entry
        # startsize = 80
        # bytes = data[entrypoint - base:entrypoint - base + startsize]
        # start = Function("_start", entrypoint, startsize, bytes, "STB_GLOBAL") #_start is always global
        # self.container.add_function(start)

    def _is_data_section(self, sname, sval):
        # A data section should be present in memory (SHF_ALLOC), and its size should
        # be greater than 0. 
        return (
            # sval['sz'] > 0 and # removed cause .gosymtab can have size 0
            (sval['flags'] & SH_FLAGS.SHF_ALLOC) != 0 and (
                (sval['flags'] & SH_FLAGS.SHF_EXECINSTR) == 0 or sname not in Rewriter.CODESECTIONS
            ) 
        )

    def _is_code_section(self, sname, sval):
        # A code section should be present in memory (SHF_ALLOC), and its size should
        # be greater than 0. 
        return (
            # sval['sz'] > 0 and # removed cause .init can have size 0
            (sval['flags'] & SH_FLAGS.SHF_ALLOC) != 0 and (
                (sval['flags'] & SH_FLAGS.SHF_EXECINSTR) != 0) 
        )

    def load_sections(self, seclist, section_filter=lambda x: True):
        debug("Loading sections...")
        for sec in [sec for sec in seclist if section_filter(sec)]:
            sval = seclist[sec]
            section = self.elffile.get_section_by_name(sec)
            data = section.data()
            more = bytearray()
            more.extend(data)
            if len(more) < sval['sz']:
                more.extend(
                    [0x0 for _ in range(0, sval['sz'] - len(more))])

            bytes = more
            debug("Adding section: ", sec, hex(sval["base"]), "with size", hex(sval['sz']),
                  "with align ", sval['align'])
            sec = sec.replace("-","_")
            if sec in CHANGE_NAME_SECS:
                sec = "a"+sec
            ds = Section(sec, sval["base"], sval["sz"], bytes,
                             (sval['align']))

            if self._is_code_section(sec, sval):
                self.container.add_code_section(ds)
            elif self._is_data_section(sec, sval):
                self.container.add_data_section(ds)

        # Find if there is a plt section
        for sec in seclist:
            if sec == '.plt':
                self.container.plt_base = seclist[sec]['base']
            if sec == ".plt.got":
                section = self.elffile.get_section_by_name(sec)
                data = section.data()
                entries = list(
                    disasm_bytes(section.data(), seclist[sec]['base']))
                self.container.gotplt_base = seclist[sec]['base']
                self.container.gotplt_sz = seclist[sec]['sz']
                self.container.gotplt_entries = entries

    def load_relocations(self, relocs):
        for reloc_section, relocations in relocs.items():

            # transform stuff like ".rela.dyn" in ".dyn"
            section = reloc_section[5:]

            if reloc_section == ".rela.plt":
                self.container.add_plt_information(relocations)

            if section in self.container.datasections:
                self.container.datasections[section].add_relocations(relocations)
            else:
                print("[*] Relocations for a section that's not loaded:",
                      reloc_section)
                self.container.add_relocations(section, relocations)

    def reloc_list_from_symtab(self):
        relocs = defaultdict(list)

        for section in self.elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            symtable = self.elffile.get_section(section['sh_link'])

            for rel in section.iter_relocations():
                symbol = None
                if rel['r_info_sym'] != 0:
                    symbol = symtable.get_symbol(rel['r_info_sym'])

                if symbol:
                    if symbol['st_name'] == 0:
                        symsec = self.elffile.get_section(symbol['st_shndx'])
                        symbol_name = symsec.name
                    else:
                        symbol_name = symbol.name
                else:
                    symbol = dict(st_value=None)
                    symbol_name = None

                reloc_i = {
                    'name': symbol_name,
                    'st_value': symbol['st_value'],
                    'offset': rel['r_offset'],
                    'addend': rel['r_addend'],
                    'type': rel['r_info_type'],
                }

                relocs[section.name].append(reloc_i)

        return relocs

    def is_go_binary(self):
        return ".gopclntab" in self.container.datasections

    def flist_from_gopclntab(self):
        # https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/
        function_list = dict()
        gopclntab = self.elffile.get_section_by_name(".gopclntab")
        godata = gopclntab.data()
        funcnum = struct.unpack("<Q", godata[8:16])[0]
        info(f"Detected {funcnum} functions")
        for i in range(funcnum):
            addrp = godata[16 + i*16: 16 + i*16 + 8]
            name_ptrp = godata[16 + i*16 + 8: 16 + i*16 + 16]
            addr = struct.unpack("<Q", addrp)[0]
            name_ptr = struct.unpack("<Q", name_ptrp)[0]
            name = "go."
            name_startp = godata[name_ptr+8:name_ptr+12]
            name_start = struct.unpack("<I", name_startp)[0]
            while 0xa <= godata[name_start] <= 0x7f:
                name += chr(godata[name_start])
                name_start += 1
            function_list[addr] = {
                'name': name,
                'sz': 0x0,
                'visibility': "",
                'bind': "STB_GLOBAL",
            }

        # get function size
        # we disasm until we find
        # bl xxxx
        # b <first inst of function>
        text = self.elffile.get_section_by_name(".text")
        textdata = text.data()
        faddrs = sorted(list(function_list.keys()))

        for e,addr in enumerate(faddrs):
            rel_addr = addr - text['sh_addr'] # it's an absolute offset to transform to relative
            cursor = rel_addr
            max_insn = 20001
            if e < len(faddrs) - 1:
                max_insn = (faddrs[e+1] - addr) // 4
            else:
                max_insn = (text['sh_size'] - rel_addr)//4
            max_insn = min(max_insn, (len(textdata) - rel_addr - 1)//4)
            for x in range(max_insn):
                ins = struct.unpack("<I", textdata[cursor:cursor+4])[0]
                next_ins = struct.unpack("<I", textdata[cursor+4:cursor+8])[0]
                if (ins & 0b11111100000000000000000000000000 == 0x94000000) and\
                (next_ins & 0b11111100000000000000000000000000 == 0x14000000):
                    # it a branch instruction
                    dist = 0x4000000 - (next_ins & 0b11111111111111111111111111) 
                    if (cursor+4 - dist*4) == rel_addr:
                        # gotcha! it's the start of the function!
                        cursor += 8
                        break
                cursor += 4
            else:
                debug(f"Function {hex(addr)} size not found! Assuming it is {hex(cursor - rel_addr)} because then the next one starts")

            function_list[addr]['sz'] = cursor - rel_addr

        # add the first function, sometimes it is missing
        if faddrs[0] > text['sh_addr']:
            print("ADDING from ", hex(text['sh_addr']), "to", hex(faddrs[0]))
            function_list[text['sh_addr']] = {
            'name': "mystart",
            'sz': faddrs[0] - text['sh_addr'],
            'visibility': "",
            'bind': "STB_GLOBAL", }

        return function_list

    def flist_from_symtab(self):
        function_list = dict()
        for symbol in self.container.symbols:
            if (symbol['st_info']['type'] == 'STT_FUNC'
                    and symbol['st_shndx'] != 'SHN_UNDEF'):
                function_list[symbol['st_value']] = {
                    'name': symbol.name,
                    'sz': symbol['st_size'],
                    'visibility': symbol['st_other']['visibility'],
                    'bind': symbol['st_info']['bind'],
                }
        if self.is_go_binary():
            info("Go binary detected")
            keys = sorted(function_list.keys())
            txtstart = self.elffile.get_section_by_name(".text")['sh_addr']
            for e,a in enumerate(keys):
                if e >= len(keys) - 1: continue
                if a <= txtstart: continue
                fend = a + function_list[a]['sz']
                nextfstart = keys[e+1]
                print(f"{hex(fend)} does not arrive to {hex(nextfstart)}")
                if fend < nextfstart:
                    function_list[fend] = {
                        'name': "filler_%x" % fend,
                        'sz': nextfstart - fend,
                        'visibility': "",
                        'bind': "STB_GLOBAL",
                    }

            for a,f in self.flist_from_gopclntab().items():
                function_list[a] = f

        return function_list

    def slist_from_symtab(self):
        sections = dict()
        for section in self.elffile.iter_sections():
            sections[section.name] = {
                'base': section['sh_addr'],
                'sz': section['sh_size'],
                'offset': section['sh_offset'],
                'align': section['sh_addralign'],
                'flags': section['sh_flags'],
                'type': section['sh_type'],
            }

        return sections

    def load_globals_from_glist(self, glist):
        self.container.add_globals(glist)

    def global_data_list_from_symtab(self):
        global_list = defaultdict(list)
        for symbol in self.container.symbols:
            # XXX: HACK
            if "@@GLIBC" in symbol.name:
                continue
            if symbol['st_other']['visibility'] == "STV_HIDDEN":
                continue
            if symbol['st_size'] == 0:
                continue

            if (symbol['st_info']['type'] == 'STT_OBJECT'
                    and symbol['st_shndx'] != 'SHN_UNDEF'):
                global_list[symbol['st_value']].append({
                    'name':
                    "{}_{:x}".format(symbol.name, symbol['st_value']),
                    'sz':
                    symbol['st_size'],
                })

        return global_list

    def parse_elf_dependencies(self):
        # here we parse the .dynamic and .dynstr to see what the dependencies
        # of a binary are. Basically we do what ldd does, but worse.
        # we do it by parsing .dynamic as outlined here
        # https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/dynamicsection.html
        deps = []
        dynamic = self.elffile.get_section_by_name(".dynamic")
        if not dynamic: return []

        for tag in dynamic.iter_tags("DT_NEEDED"):
            deps += [tag.needed]
        info(f"Found dependencies {','.join(deps)}")
        return deps

    def load_functions_ghidra(self):
        prescript = """
#!/usr/bin/env python2

from ghidra.app.script import GhidraScript
setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false")
setAnalysisOption(currentProgram, "Stack", "false")
setAnalysisOption(currentProgram, "ARM Constant Reference Analyzer", "false")
setAnalysisOption(currentProgram, "x86 Constant Reference Analyzer", "false")
"""
        postscript = """
#!/usr/bin/env python2
import json
import __main__ as ghidra_app

args = ghidra_app.getScriptArgs()
functions = currentProgram.getFunctionManager().getFunctions(True)
reslist = {}
for function in list(functions):
    reslist[function.name] = (hex(int("0x" + str(function.entryPoint), 16) - 0x100000), hex(function.getBody().getNumAddresses()))

with open(args[0], "w") as output_file:
    json.dump(reslist, output_file)
"""
        import distutils.spawn 
        import os
        import random
        import string
        import json
        ghidra_exec = distutils.spawn.find_executable("ghidra-headless")
        if not ghidra_exec: 
            ghidra_exec = distutils.spawn.find_executable("analyzeHeadless")
        if not ghidra_exec: 
            critical("ghidra-headless or analyzeHeadless not found!")
            exit(1)

        with open("/tmp/prescript", "w") as f:
            f.write(prescript)
        with open("/tmp/postscript", "w") as f:
            f.write(postscript)
        
        tmp = "/tmp/{self.fname}_" + "".join(random.choice(string.digits) for _ in range(12))
        os.system(f"ghidra-headless /tmp HeadlessAnalysis -overwrite -import {self.fname} -scriptPath /tmp -prescript prescript -postscript postscript {tmp}")

        if not os.path.exists(tmp):
            critical("ghidra analysis failed!")
            exit(1)

        with open(tmp, "r") as f:
            fun_dict = json.load(f)

        os.remove(tmp)

        for fname, fattrs in fun_dict.items():
            faddr, fsize = fattrs
            faddr = int(faddr, 16)
    
            fsize = int(fsize, 16)
    
            sec = self.container.section_of_address(faddr)
            if not sec: continue
            sec.functions += [faddr]
            sec.functions_ends += [faddr + fsize]

            section_offset = faddr - sec.base
            bytes = sec.bytes[section_offset:section_offset + fsize]

            # replace banned chars
            fixed_name = self.sanitize_symbol_name(fname)
            bind =  "STB_GLOBAL" 
            function = Function(fixed_name, faddr, fsize, bytes, bind)
            self.container.add_function(function)

        
