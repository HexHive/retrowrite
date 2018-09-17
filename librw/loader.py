#!/usr/bin/env python

import argparse

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection


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
        for fname, fvalue in fnlist.items():
            section_offset = fvalue["start"] - base
            bytes = data[section_offset:section_offset + fvalue["sz"]]
            function = Function(fname, fvalue["start"], fvalue["sz"], bytes)
            self.container.add_function(function)

    def load_data_sections(self, seclist, section_filter=lambda x: True):
        for section, sval in section_filter(seclist):
            # TODO
            bytes = list()
            ds = DataSection(section, sval["base"], sval["sz"], bytes)
            self.container.add_section(ds)

    def flist_from_symtab(self):
        symbol_tables = [sec for sec in self.elffile.iter_sections() if
                         isinstance(sec, SymbolTableSection)]

        function_list = dict()

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for symbol in section.iter_symbols():
                if (symbol['st_info']['type'] == 'STT_FUNC' and
                   symbol['st_shndx'] != 'SHN_UNDEF'):
                    function_list[symbol.name] = {
                        'start': symbol['st_value'],
                        'sz': symbol['st_size'],
                    }

        return function_list

    def slist_from_symtab(self):
        pass


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("bin", type=str, help="Input binary to load")
    argp.add_argument("--flist", type=str,
                      help="Load function list from .json file")

    args = argp.parse_args()

    loader = Loader(args.bin)
    flist = loader.flist_from_symtab()
    loader.load_functions(flist)
