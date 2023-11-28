#!/usr/bin/env python

import argparse
import struct
from collections import defaultdict

from intervaltree import IntervalTree

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from .container import Container, Function, DataSection
from .disasm import disasm_bytes


class Loader():
    def __init__(self, fname):
        self.fd = open(fname, 'rb')
        self.elffile = ELFFile(self.fd)
        self.container = Container()
    # this function is checking is the binarie is suited for retrowrite rewriting (PIE/PIC)
    def is_pie(self):
        base_address = next(seg for seg in self.elffile.iter_segments() 
                                        if seg['p_type'] == "PT_LOAD")['p_vaddr']
        return self.elffile['e_type'] == 'ET_DYN' and base_address == 0

    def is_stripped(self):
        # Get the symbol table entry for the respective symbol
        symtab = self.elffile.get_section_by_name('.symtab')
        if not symtab:
            print('No symbol table available, this file is probably stripped!')
            return True

        sym = symtab.get_symbol_by_name("main")[0]
        if not sym:
            print('Symbol {} not found')
            return True
        return False

    def is_pie(self):
        base_address = next(seg for seg in self.elffile.iter_segments() 
                                        if seg['p_type'] == "PT_LOAD")['p_vaddr']
        return self.elffile['e_type'] == 'ET_DYN' and base_address == 0

    def load_functions(self, fnlist):
        text_section = self.elffile.get_section_by_name(".text")
        text_data = text_section.data()
        text_base = text_section['sh_addr']
        for faddr, fvalue in fnlist.items():
            section_offset = faddr - text_base
            bytes = text_data[section_offset:section_offset + fvalue["sz"]]
            fixed_name = fvalue["name"].replace("@", "_")

            function = Function(fixed_name, faddr, fvalue["sz"], bytes,
                                fvalue["bind"])
            self.container.add_function(function)

        section = self.elffile.get_section_by_name(".init_array")
        data = section.data()
        # section = self.elffile.get_section_by_name(".fini_array")
        # data += section.data()
        for e,i in enumerate(range(0, len(data), 8)):
            address = data[i:i+8]
            addr_int = struct.unpack("<Q", address)[0]
            func = self.container.functions.get(addr_int, None)
            if func == None:
                print(f"ERROR: missed .init_array function symbol at {hex(addr_int)}")
                # TODO 
                # We need to add them to the function list
                # we need to "add_function" like right above
                min_next_func = 0xffffffffffffffff
                for func in self.container.functions:
                    if func > addr_int:
                        min_next_func = min(min_next_func, func)
                if min_next_func != 0xffffffffffffffff:
                    sz = min_next_func - addr_int
                    func_bytes = text_data[addr_int - text_base:addr_int - text_base + sz]
                    if e == 0:
                        # skip first initial array and just do ret (problems with _ITM_registerTMClone... begin unlinkable)
                        self.container.add_function(Function(f"entry_{hex(addr_int)}", addr_int, sz, b"\xc3"))
                    else:
                        self.container.add_function(Function(f"entry_{hex(addr_int)}", addr_int, sz, func_bytes))

        # fill gaps 
        # functions = list(sorted(self.container.functions.items()))
        # print(functions)
        # for i, f in enumerate(functions):
        #     _, function = f
        #     if i < len(functions) - 1:
        #         if function.start + function.sz < functions[i+1][1].start:
        #             sz = functions[i+1][1].start - (function.start + function.sz)
        #             new_start = function.start + function.sz
        #             func_bytes = text_data[new_start - text_base:new_start + sz - text_base]
        #             self.container.add_function(Function(f"entry_{hex(new_start)}", new_start, sz, func_bytes))
            


    def load_data_sections(self, seclist, section_filter=lambda x: True):
        for sec in [sec for sec in seclist if section_filter(sec)]:
            sval = seclist[sec]
            section = self.elffile.get_section_by_name(sec)
            data = section.data()
            more = bytearray()
            if sec == ".init_array":
                # TODO: get INTPTR_SIZE from specific architecture as needed.
                INTPTR_SIZE = 8

                for i in range(0, len(data), INTPTR_SIZE):

                    ptr_raw = data[i:i+INTPTR_SIZE]
                    ptr = struct.unpack("<Q", ptr_raw)[0]

                    func = self.container.functions.get(ptr, None)
                    if func == None:
                        print("Found .init_array pointer to an unknown function at address 0x%08x" % (ptr))
                        print("This could be a bug. Please report it your case here: https://github.com/HexHive/retrowrite/issues/new")
                    else:
                        # GCC will output frame_dummy by default in most new 
                        # binaries as needed, as part of libc. If we find it 
                        # here we should strip it out so that it isn't 
                        # symbolized when we process relocations.
                        if func.name == "frame_dummy":
                            print(".init_array frame_dummy pointer removed.")
                            continue
                        # we are all good.
                        print(".init_array function %s left in place" % func.name)

                    more.extend(ptr_raw)
            else:
                more.extend(data)
                if len(more) < sval['sz']:
                    more.extend(
                        [0x0 for _ in range(0, sval['sz'] - len(more))])

            bytes = more
            ds = DataSection(sec, sval["base"], sval["sz"], bytes,
                             sval['align'])

            self.container.add_section(ds)

        # Find if there is a plt section
        for sec in seclist:
            if sec == '.plt':
                self.container.plt_base = seclist[sec]['base']
            if sec == '.plt.sec': # support old gcc version, skip one plt entry
                self.container.plt_base = seclist[sec]['base'] - 16 
            if sec == ".plt.got" or sec == ".plt.sec":
                section = self.elffile.get_section_by_name(sec)
                data = section.data()
                entries = list(
                    disasm_bytes(section.data(), seclist[sec]['base']))
                self.container.gotplt_base = seclist[sec]['base']
                self.container.gotplt_sz = seclist[sec]['sz'] + 16
                self.container.gotplt_entries = entries
            if sec == ".got":
                self.container.got = IntervalTree()
                base = seclist[sec]['base']
                end = base + seclist[sec]['sz']
                self.container.got[base:end] = "GOT"

    def load_relocations(self, relocs):
        for reloc_section, relocations in relocs.items():
            section = reloc_section[5:]

            if reloc_section == ".rela.plt":
                self.container.add_plt_information(relocations)

            if section in self.container.sections:
                self.container.sections[section].add_relocations(relocations)
            else:
                print("[*] Relocations for a section that's not loaded:" + str(reloc_section))
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

    def flist_from_symtab(self):
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        function_list = dict()

        for section in symbol_tables:

            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for symbol in section.iter_symbols():
                if symbol['st_other']['visibility'] == "STV_HIDDEN":
                    continue


                if (symbol['st_info']['type'] == 'STT_FUNC'
                        and symbol['st_shndx'] != 'SHN_UNDEF'):
                    function_list[symbol['st_value']] = {
                        'name': symbol.name,
                        'sz': symbol['st_size'],
                        'visibility': symbol['st_other']['visibility'],
                        'bind': symbol['st_info']['bind'],
                    }

        return function_list

    def slist_from_symtab(self):
        sections = dict()
        for section in self.elffile.iter_sections():
            sections[section.name] = {
                'base': section['sh_addr'],
                'sz': section['sh_size'],
                'offset': section['sh_offset'],
                'align': section['sh_addralign'],
            }

        return sections

    def load_globals_from_glist(self, glist):
        self.container.add_globals(glist)

    def global_data_list_from_symtab(self):
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        global_list = defaultdict(list)

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for symbol in section.iter_symbols():
                # XXX: HACK
                if "@@GLIBC" in symbol.name:
                    continue

                if "@GLIBCXX" in symbol.name:
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

    def identify_imports(self):
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        symmap = IntervalTree()

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section.name != ".dynsym":
                continue

            for symbol in section.iter_symbols():
                if (symbol['st_info']['type'] == 'STT_OBJECT'
                    and symbol['st_shndx'] != 'SHN_UNDEF'):

                    start = symbol['st_value']
                    end = symbol['st_value'] + symbol['st_size']

                    symmap[start:end] = symbol.name

        self.container.imports = symmap
        print("IDENTIFIED IMPORTS")

if __name__ == "__main__":
    from .rw import Rewriter

    argp = argparse.ArgumentParser()

    argp.add_argument("bin", type=str, help="Input binary to load")
    argp.add_argument(
        "--flist", type=str, help="Load function list from .json file")

    args = argp.parse_args()

    loader = Loader(args.bin)

    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    loader.load_data_sections(slist, lambda x: x in Rewriter.DATASECTIONS)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    global_list = loader.global_data_list_from_symtab()
    loader.load_globals_from_glist(global_list)

    loader.identify_imports()
