#!/usr/bin/env python

import argparse
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import SH_FLAGS
from elftools.elf.enums import ENUM_E_TYPE

from .container import Container, Function, DataSection
from .disasm import disasm_bytes


class Loader():
    def __init__(self, fname):
        self.fd = open(fname, 'rb')
        self.elffile = ELFFile(self.fd)
        self.container = Container()

    def load_functions(self, fnlist):
        for fn in fnlist:
            section = fn['section']
            bytes = section.data()[fn['offset']:fn['offset'] + fn['sz']]
            function = Function(fn['name'], section, fn['offset'],
                fn['sz'], bytes, fn['bind'])

            print('Added function %s' % fn['name'])

            self.container.add_function(function, section)

    def load_data_sections(self, seclist, section_filter=lambda x, y, z: True):
        for sec in [sname for sname, sval in seclist.items() if section_filter(sname, sval, self.container)]:
            sval = seclist[sec]
            section = self.elffile.get_section_by_name(sec)
            data = section.data()
            more = bytearray()
            if sec == ".init_array":
                if len(data) > 8:
                    data = data[8:]
                else:
                    data = b''
                more.extend(data)
            else:
                more.extend(data)
                if len(more) < sval['sz']:
                    more.extend(
                        [0x0 for _ in range(0, sval['sz'] - len(more))])

            bytes = more
            ds = DataSection(sec, sval["base"], sval["sz"], bytes, sval['flags'],
                             sval['type'], sval['align'])

            print('Loaded data section %s' % sec)
            self.container.add_section(ds)

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
            section = reloc_section[5:]

            if reloc_section == ".rela.plt":
                self.container.add_plt_information(relocations)

            if section in self.container.sections:
                # Data section relocation
                self.container.sections[section].add_relocations(relocations)
            else:
                # Code section relocation
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

                if symbol and symbol['st_shndx'] != 'SHN_UNDEF':
                    reloc_i['target_section'] = self.elffile.get_section(symbol['st_shndx'])
                else:
                    reloc_i['target_section'] = None


                relocs[section.name].append(reloc_i)

        return relocs

    def flist_from_symtab(self):
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        function_list = []

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

                    fn_section = self.elffile.get_section(symbol['st_shndx'])

                    if self.elffile['e_type'] == ENUM_E_TYPE['ET_REL']:
                        fn_offset = symbol['st_value']
                    else:
                        fn_offset = symbol['st_value'] - fn_section['sh_addr']

                    function_list.append({
                        'name': symbol.name,
                        'sz': symbol['st_size'],
                        'visibility': symbol['st_other']['visibility'],
                        'bind': symbol['st_info']['bind'],
                        'section': fn_section,
                        'offset': fn_offset,
                    })

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
        symbol_tables = [
            sec for sec in self.elffile.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]

        global_list = []

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for symbol in section.iter_symbols():
                # XXX: HACK
                if "@@GLIBC" in symbol.name:
                    continue
                if symbol['st_other']['visibility'] == "STV_HIDDEN":
                    continue
                if symbol['st_size'] == 0:
                    continue

                if (symbol['st_info']['type'] == 'STT_OBJECT'
                        and symbol['st_shndx'] != 'SHN_UNDEF'):

                    global_section = self.elffile.get_section(symbol['st_shndx'])

                    if self.elffile['e_type'] == ENUM_E_TYPE['ET_REL']:
                        global_offset = symbol['st_value']
                    else:
                        global_offset = symbol['st_value'] - global_section['sh_addr']

                    global_list.append({
                        'name': "{}_{:x}".format(symbol.name, symbol['st_value']),
                        'sz': symbol['st_size'],
                        'section': global_section,
                        'offset': global_offset,
                    })

        return global_list


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
