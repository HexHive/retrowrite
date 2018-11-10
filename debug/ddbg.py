import argparse
import json
import numpy as np
import subprocess as sp
import copy

from librw.loader import Loader
from librw.rw import Rewriter
from librw.analysis.register import RegisterAnalysis

from rwtools.asan.instrument import Instrument
from librw.analysis.stackframe import StackFrameAnalysis


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
            for key, info in func.analysis.items():
                analysis[addr][key] = dict()
                for k, v in info.items():
                    analysis[addr][key][k] = list(v)

        with open(outfile + ".analysis_cache", "w") as fd:
            json.dump(analysis, fd)

    return rw


def delta_debug(args):
    excluded = set()
    all_locations = set()
    safe_set = set()

    verified = False
    err_locs = set()

    rewriter = do_symbolization(args.binary, args.outfile)
    instrumenter = Instrument(rewriter)
    instrumenter.do_instrument()

    for func, sites in instrumenter.memcheck_sites.items():
        for site in sites:
            addr = rewriter.container.functions[func].cache[site]
            all_locations.add(addr.address)

    while not verified:
        instrument_sites = all_locations.difference(excluded).difference(safe_set)
        while len(instrument_sites) > 1:
            rewriter = do_symbolization(args.binary, args.outfile)
            instrumenter = Instrument(rewriter)
            # Create round skip
            round_skip = set()
            for site in instrument_sites:
                randsk = np.random.randint(2, size=1)
                if randsk:
                    round_skip.add(site)
            # Exclude these sites
            instrumenter.skip_instrument = round_skip.union(excluded)
            instrumenter.do_instrument()
            rewriter.dump()
            # Test!
            result = test_function(args)
            # True case, test case passed. Therefore, something in round_skip is
            # causing the error.
            if result:
                safe_set = safe_set.union(
                    all_locations.difference(instrumenter.skip_instrument))
                excluded = all_locations.difference(round_skip)
            else:
                # Ok, we failed again, add round skip to excluded to safely exclude
                excluded = excluded.union(round_skip)

            print(len(all_locations), len(instrument_sites),
                  len(excluded), len(round_skip))

            instrument_sites = all_locations.difference(excluded).difference(safe_set)

        print("[*] Localized Error to:", instrument_sites)

        # Verify the solution set
        err_locs.update(instrument_sites)
        excluded = copy.copy(err_locs)
        rewriter = do_symbolization(args.binary, args.outfile)

        instrumenter = Instrument(rewriter)
        instrumenter.skip_instrument = excluded

        print("[*] Verifying Solution:", excluded)
        instrumenter.do_instrument()
        rewriter.dump()

        result = test_function(args)
        if result:
            verified = True
            print("Error set:", [hex(x) for x in err_locs])
        else:
            print("[X] Verification Failed. Retrying.")


SPEC_LOC = "/home/number_four/projects/spec"
SPEC_CMD = "cd " + SPEC_LOC + " && source shrc && runspec --config asan.cfg --nobuild"
MAKE_CMD = "cd tests/SPECCPU2006 && make && make asan_install"


def test_function(args):
    try:
        print("[*] Building ...")
        sp.check_call(MAKE_CMD, shell=True)
        print("[*] Running SPEC CMD")
        proc = sp.Popen(["/bin/bash", "-c", SPEC_CMD], stdout=sp.PIPE, stderr=sp.PIPE)
        proc.wait()
        output, err = proc.communicate()
    except sp.CalledProcessError:
        return False

    err_str = "****************************************"
    #err_str = "*** Miscompare of su3imp.out;"
    output = output.decode('utf-8').split("\n")
    print("\n".join(output))
    if any([x.strip().startswith(err_str) for x in output]):
    #if any([x.strip().startswith("*** Miscompare") for x in output]):
        print("Miscompare found! Failed Test!")
        return False
    return True


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
    delta_debug(args)
