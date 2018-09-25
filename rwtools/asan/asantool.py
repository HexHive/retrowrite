import argparse

from librw.loader import Loader
from librw.rw import Rewriter

from .instrument import Instrument


def do_symbolization(input, outfile):
    loader = Loader(input)

    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    loader.load_data_sections(slist, lambda x: x in Rewriter.DATASECTIONS)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    loader.container.attach_loader(loader)

    rw = Rewriter(loader.container, outfile + ".s")
    rw.symbolize()

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

    rewriter.dump()
