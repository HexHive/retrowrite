#/usr/bin/env python3

import argparse
import json
import tempfile
import subprocess
import os
import sys

if __name__ == "__main__":
    argp = argparse.ArgumentParser(description='Retrofitting compiler passes though binary rewriting.')

    argp.add_argument("bin", type=str, help="Input binary to load")
    argp.add_argument("outfile", type=str, help="Symbolized ASM output")

    argp.add_argument("-a", "--asan", action='store_true',
                      help="Add binary address sanitizer instrumentation")

    argp.add_argument("-x", "--cpp", action="store_true",
                      help="Enable C++ Support")
 
    argp.add_argument("-s", "--assembly", action="store_true",
                      help="Generate Symbolized Assembly")
    # python3 -m librw_x64.rw </path/to/binary> <path/to/output/asm/files>
    argp.add_argument("-k", "--kernel", action='store_true',
                      help="Instrument a kernel module")
    argp.add_argument(
        "--kcov", action='store_true', help="Instrument the kernel module with kcov")
    argp.add_argument("-c", "--cache", action='store_true',
                      help="Save/load register analysis cache (only used with --asan)")
    argp.add_argument("--ignore-no-pie", dest="ignore_no_pie", action='store_true', help="Ignore position-independent-executable check (use with caution)")
    argp.add_argument("--ignore-stripped", dest="ignore_stripped", action='store_true',
                      help="Ignore stripped executable check (use with caution)")

    argp.set_defaults(cpp=False)
    argp.set_defaults(ignore_no_pie=False)
    argp.set_defaults(ignore_stripped=False)

    args = argp.parse_args()

    # TODO: sort this out:
    if args.kernel:
        from librw_x64.krw import Rewriter
        from librw_x64 import krw
        from librw_x64.analysis.kregister import RegisterAnalysis
        from librw_x64.analysis.kstackframe import StackFrameAnalysis
        from rwtools_x64.kasan.instrument import Instrument
        from rwtools_x64.kasan.asantool import KcovInstrument
        from librw_x64.kloader import Loader
        from librw_x64.analysis import kregister
    else:
        from librw_x64.rw import Rewriter
        from librw_x64.analysis.register import RegisterAnalysis
        from librw_x64.analysis.stackframe import StackFrameAnalysis
        from rwtools_x64.asan.instrument import Instrument
        from librw_x64.loader import Loader
        from librw_x64.analysis import register


    loader = Loader(args.bin)
    if loader.is_pie() == False and args.ignore_no_pie == False:
        print("***** RetroWrite requires a position-independent executable. *****")
        print("It looks like %s is not position independent" % args.bin)
        print("If you really want to continue, because you think retrowrite has made a mistake, pass --ignore-no-pie.")
        sys.exit(1)
    if loader.is_stripped() == True and args.ignore_stripped == False:
        print("RetroWrite requires a none stripped executable.")
        print("It looks like %s is stripped" % args.bin)
        print("If you really want to continue, because you think retrowrite has made a mistake, pass --ignore-stripped.")
        sys.exit(1)

    flist = loader.flist_from_symtab()
    loader.load_functions(flist)

    slist = loader.slist_from_symtab()
    if args.kernel:
        loader.load_data_sections(slist, krw.is_data_section)
    else:
        loader.load_data_sections(slist, lambda x: x in Rewriter.DATASECTIONS)

    reloc_list = loader.reloc_list_from_symtab()
    loader.load_relocations(reloc_list)

    global_list = loader.global_data_list_from_symtab()
    loader.load_globals_from_glist(global_list)

    loader.identify_imports()

    loader.container.attach_loader(loader)

    kwarg = {}
    if args.cpp == True:
        kwarg["eh_frame"] = True
        kwarg["lang_cpp"] = True
    else:
        kwarg["eh_frame"] = False
        kwarg["lang_cpp"] = False

    rw = Rewriter(loader.container, args.outfile, **kwarg)
    rw.symbolize()


    if args.asan:
        if args.kernel:
            rewriter = asank(rw, loader, args)
            instrumenter = Instrument(rewriter)
            instrumenter.do_instrument()

            if args.kcov:
                kcov_instrumenter = KcovInstrument(rewriter)
                kcov_instrumenter.do_instrument()
            rewriter.dump()
        else:
            asan(rw, loader, args)
            rw.dump()
    else:

        rw.dump()
