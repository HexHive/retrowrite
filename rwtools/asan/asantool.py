import argparse
import json

from elftools.elf.constants import SH_FLAGS

from librw.loader import Loader
from librw.rw import Rewriter
from librw.analysis.register import RegisterAnalysis
from librw.analysis.stackframe import StackFrameAnalysis

from .instrument import Instrument

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

    rw = Rewriter(loader.container, outfile + ".s")
    rw.symbolize()

    StackFrameAnalysis.analyze(loader.container)

    # Try to find a cache of analysis results.
    with open(outfile + ".analysis_cache") as fd:
        analysis = json.load(fd)

    print("[*] Loading analysis cache")
    for func, info in analysis.items():
        for key, finfo in info.items():
            fn = loader.container.get_function_by_name(func)
            fn.analysis[key] = dict()
            for k, v in finfo.items():
                try:
                    addr = int(k)
                except ValueError:
                    addr = k
                fn.analysis[key][addr] = v

    return rw


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("binary", type=str, help="Input binary to instrument")
    argp.add_argument("outfile", type=str, help="Input binary to instrument")

    argp.add_argument(
        "--compile", type=str, help="Compile command for the binary")

    argp.add_argument(
        "--gcc", action='store_true', help="Use gcc compile final binary")

    argp.add_argument(
        "--clang", action='store_true', help="Use clang compile final binary")

    args = argp.parse_args()

    rewriter = do_symbolization(args.binary, args.outfile)

    instrumenter = Instrument(rewriter)
    instrumenter.do_instrument()

    # instrumenter.dump_stats()

    rewriter.dump()
