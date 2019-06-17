import argparse
import json

from librw.loader import Loader
from librw.rw import Rewriter
from librw.analysis.register import RegisterAnalysis
from librw.analysis.stackframe import StackFrameAnalysis

from .instrument import Instrument


def do_symbolization(input, outfile):
    loader = Loader(input)

    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    loader.load_data_sections(slist, lambda x: x in Rewriter.DATASECTIONS)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    global_list = loader.global_data_list_from_symtab()
    loader.load_globals_from_glist(global_list)

    loader.container.attach_loader(loader)

    rw = Rewriter(loader.container, outfile + ".s")
    rw.symbolize()

    StackFrameAnalysis.analyze(loader.container)

    try:
        # Try to find a cache of analysis results.
        with open(outfile + ".analysis_cache") as fd:
            analysis = json.load(fd)

        print("[*] Loading analysis cache")
        for func, info in analysis.items():
            for key, finfo in info.items():
                loader.container.functions[int(func)].analysis[key] = dict()
                for k, v in finfo.items():
                    try:
                        addr = int(k)
                    except ValueError:
                        addr = k
                    loader.container.functions[int(func)].analysis[key][addr] = v
    except IOError:
        print("[*] Analyzing free registers")
        RegisterAnalysis.analyze(loader.container)
        analysis = dict()

        for addr, func in loader.container.functions.items():
            analysis[addr] = dict()
            analysis[addr]["free_registers"] = dict()
            for k, info in func.analysis["free_registers"].items():
                analysis[addr]["free_registers"][k] = list(info)

        with open(outfile + ".analysis_cache", "w") as fd:
            json.dump(analysis, fd)

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

    instrumenter.dump_stats()

    rewriter.dump()
