import argparse
import json

from librw.kloader import Loader
from librw.krw import Rewriter
from librw.analysis.kregister import RegisterAnalysis

from .instrument import Instrument

from elftools.elf.constants import SH_FLAGS


def is_data_section(sname, sval, container):
    # A data section should be present in memory (SHF_ALLOC), and its size should
    # be greater than 0. There are some code sections in kernel modules that
    # only contain short trampolines and don't have any function relocations
    # in them. The easiest way to deal with them for now is to treat them as
    # data sections but this is a bit of a hack because they could contain
    # references that need to be symbolized
    return (
        (sval['flags'] & SH_FLAGS.SHF_ALLOC) != 0 and (
            (sval['flags'] & SH_FLAGS.SHF_EXECINSTR) == 0 or sname not in container.code_section_names
        ) and sval['sz'] > 0
    )


def do_symbolization(input, outfile):
    loader = Loader(input)

    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    loader.load_data_sections(slist, is_data_section)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    global_list = loader.global_data_list_from_symtab()
    loader.load_globals_from_glist(global_list)

    loader.container.attach_loader(loader)

    rw = Rewriter(loader.container, outfile)
    rw.symbolize()

    # try:
    #     # Try to find a cache of analysis results.
    #     with open(outfile + ".analysis_cache") as fd:
    #         analysis = json.load(fd)

    # except IOError:
    # print("[*] Analyzing free registers")
    # RegisterAnalysis.analyze(loader.container)

    # analysis = dict()
    # for func in loader.container.iter_functions():
    #     addr = func.address
    #     analysis[str(addr)] = dict()
    #     analysis[str(addr)]["free_registers"] = dict()
    #     for k, info in func.analysis["free_registers"].items():
    #         analysis[str(addr)]["free_registers"][k] = list(info)

    # print("[*] Done")

        # with open(outfile + ".analysis_cache", "w") as fd:
        #     json.dump(analysis, fd)


    # for func, info in analysis.items():
    #     for key, finfo in info.items():
    #         loader.container.functions[int(func)].analysis[key] = dict()
    #         for k, v in finfo.items():
    #             try:
    #                 addr = int(k)
    #             except ValueError:
    #                 addr = k
    #             loader.container.functions[int(func)].analysis[key][addr] = v

    return rw

if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("binary", type=str, help="Input binary to instrument")
    argp.add_argument("outfile", type=str, help="Symbolized asm output")

    args = argp.parse_args()

    rewriter = do_symbolization(args.binary, args.outfile)

    instrumenter = Instrument(rewriter)
    instrumenter.do_instrument()

    rewriter.dump()
