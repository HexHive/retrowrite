#!/usr/bin/env python

import argparse
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import SH_FLAGS
from elftools.elf.enums import ENUM_E_TYPE

from .kcontainer import Container, Function, DataSection, Address, disasm_bytes


class Loader():
    def __init__(self, fname):
        self.fd = open(fname, 'rb')
        self.elffile = ELFFile(self.fd)
        self.container = Container()

    # Create a function object for each function in fnlist and add it to the
    # container
    def load_functions(self, fnlist):
        for fn in fnlist:
            section = fn['address'].section
            offset = fn['address'].offset
            function_start = offset
            function_end = offset + fn['sz']

            bytes = section.data()[function_start:function_end]
            function = Function(fn['name'], fn['address'],
                fn['sz'], bytes, self.container, fn['bind'])

            print('Added function %s' % fn['name'])

            self.container.add_function(function)

    # Load all the data sections of the executable
    def load_data_sections(self, seclist, section_filter=lambda sname, sval, container: True):
        section_names_list = [sname for sname, sval in seclist.items()
            if section_filter(sname, sval, self.container)]

        for sname in section_names_list:
            sval = seclist[sname]
            section = self.elffile.get_section_by_name(sname)
            data = section.data()
            more = bytearray()
            if sname == ".init_array":
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
            ds = DataSection(sname, sval["base"], sval["sz"], bytes, sval['flags'],
                             sval['type'], sval['align'])

            print('Loaded data section %s' % sname)
            self.container.add_section(ds)

    # Load all the relocations
    def load_relocations(self, relocs):
        for reloc_section, relocations in relocs.items():
            section = reloc_section[5:]

            if section in self.container.sections:
                # Data section relocation
                self.container.sections[section].add_relocations(relocations)
            else:
                # Code section relocation
                self.container.add_code_relocations(section, relocations)

    def reloc_list_from_symtab(self):
        relocs = defaultdict(list)

        # Find all the relocation sections in the file
        # relocation_section is a section containing the relocations for another
        # section (the target section)
        for relocation_section in self.elffile.iter_sections():
            if not isinstance(relocation_section, RelocationSection):
                continue

            # symtable is the symbol table section associated with this
            # relocation section
            symtable = self.elffile.get_section(relocation_section['sh_link'])

            # target_section is the section that the relocation affects (i.e.
            # the section where the linker/loader will write the value computed by
            # the relocation)
            target_section = self.elffile.get_section_by_name(relocation_section.name[5:])

            for relocation in relocation_section.iter_relocations():
                if relocation_section.name == '.rela.dyn':
                    for s in self.elffile.iter_sections():
                        section_start =  s['sh_addr'] if s['sh_addr'] > 0 else s['sh_offset']
                        section_end = section_start + s.data_size
                        if section_start <= relocation['r_offset'] < section_end:
                            target_section = s
                            break
                    else:
                        assert False
                # symbol is the symbol that the relocation refers to
                symbol = None
                # symbol_section is the section that contains the symbol
                symbol_section = None

                if relocation['r_info_sym'] != 0:
                    symbol = symtable.get_symbol(relocation['r_info_sym'])

                if symbol:
                    # This relocation points to a symbol
                    symbol_section = self.elffile.get_section(symbol['st_shndx']) if symbol['st_shndx'] != 'SHN_UNDEF' else None

                    # Symbols can have a name or no name
                    if symbol['st_name'] == 0:
                        # The symbol doesn't have a name, we will use the name of
                        # the section that contains it instead. Symbols that don't
                        # have a name always have a section
                        assert symbol_section
                        symbol_name = symbol_section.name
                    else:
                        # The symbol has a name
                        symbol_name = symbol.name

                    # relocation_address is the address at which the relocation will
                    # be applied
                    # symbol_address is the address of the symbol, or None if the
                    # symbol is external/imported
                    if self.elffile['e_type'] == 'ET_REL':
                        relocation_address = Address(target_section, relocation['r_offset'])
                        symbol_address = Address(symbol_section, symbol['st_value']) if symbol_section else None
                    else:
                        relocation_address = Address(target_section, relocation['r_offset'] - target_section['sh_addr'])
                        symbol_address = Address(symbol_section, symbol['st_value'] - symbol_section['sh_addr']) if symbol_section else None
                else:
                    symbol_name = None
                    # This relocation doesn't point to a symbol, we have to use
                    # 0 as the symbol's value, which basically means that this
                    # points to some place in the executable. This can only work
                    # for non-relocatable files because relocatable files could
                    # have any layout in memory
                    absolute_address = relocation['r_addend']
                    assert self.elffile['e_type'] != 'ET_REL'

                    for section in self.elffile.iter_sections():
                        if section['sh_addr'] <= absolute_address < section['sh_addr'] + section.data_size:
                            symbol_address = Address(section, absolute_address - section['sh_addr'])
                            break;
                    else:
                        assert False, 'Relocation with no symbol outside of all sections'

                    # import pdb; pdb.set_trace()
                    relocation_address = Address(target_section, relocation['r_offset'] - target_section['sh_addr'])

                reloc_i = {
                    'name': symbol_name,
                    'address': relocation_address,
                    'addend': relocation['r_addend'],
                    'type': relocation['r_info_type'],
                    'symbol_address': symbol_address,
                }

                relocs[relocation_section.name].append(reloc_i)

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
                        'address': Address(fn_section, fn_offset),
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
