#!/usr/bin/env python

import argparse
from collections import defaultdict
import json

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from container import Container, Function, DataSection


class Loader():
    def __init__(self, fname):
        self.fd = open(fname, 'rb')
        self.elffile = ELFFile(self.fd)
        self.container = Container()

    def load_functions(self, fnlist):
        section = self.elffile.get_section_by_name(".text")
        data = section.data()
        base = section['sh_addr']
        for faddr, fvalue in fnlist.items():
            section_offset = faddr - base
            bytes = data[section_offset:section_offset + fvalue["sz"]]
            function = Function(fvalue["name"], faddr, fvalue["sz"], bytes)
            self.container.add_function(function)

    def load_data_sections(self, seclist, section_filter=lambda x: True):
        for sec in [sec for sec in seclist if section_filter(sec)]:
            sval = seclist[sec]
            section = self.elffile.get_section_by_name(sec)
            bytes = section.data()
            ds = DataSection(sec, sval["base"], sval["sz"], bytes)
            self.container.add_section(ds)

    def load_relocations(self, relocs):
        for reloc_section, relocations in relocs.items():
            section = reloc_section[5:]

            if section in self.container.sections:
                self.container.sections[section].add_relocations(relocations)
            else:
                print("[*] Relocations for a section that's not loaded!")
                self.container.add_relocations(section, relocations)

    def reloc_list_from_symtab(self):
        relocs = defaultdict(list)

        for section in self.elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            symtable = self.elffile.get_section(section['sh_link'])

            for rel in section.iter_relocations():
                if rel['r_info_sym'] == 0:
                    continue

                symbol = symtable.get_symbol(rel['r_info_sym'])
                if symbol['st_name'] == 0:
                    symsec = self.elffile.get_section(symbol['st_shndx'])
                    symbol_name = symsec.name
                else:
                    symbol_name = symbol.name

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
                    }

        return function_list

    def slist_from_symtab(self):
        sections = dict()
        for section in self.elffile.iter_sections():
            sections[section.name] = {
                'base': section['sh_addr'],
                'sz': section['sh_size'],
            }

        return sections


if __name__ == "__main__":
    from rw import Rewriter

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

    for addr, function in loader.container.functions.items():
        print(hex(addr), function.name)
