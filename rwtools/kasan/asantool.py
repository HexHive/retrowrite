import argparse
import json
import tempfile
import subprocess

from elftools.elf.constants import SH_FLAGS

from librw.kloader import Loader
from librw.krw import Rewriter
from librw.analysis.kregister import RegisterAnalysis
from librw.analysis.kstackframe import StackFrameAnalysis
from librw.kcontainer import InstrumentedInstruction

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

    rw = Rewriter(loader.container, outfile)
    rw.symbolize()

    StackFrameAnalysis.analyze(loader.container)

    with tempfile.NamedTemporaryFile(mode='w') as cf_file:
        with tempfile.NamedTemporaryFile(mode='r') as regs_file:
            rw.dump_cf_info(cf_file)
            cf_file.flush()

            subprocess.check_call(['cftool', cf_file.name, regs_file.name])

            analysis = json.load(regs_file)

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

class KcovInstrument():
    CALLER_SAVED_REGS = [
        'rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11',
    ]

    def __init__(self, rewriter):
        self.rewriter = rewriter

    def do_instrument(self):
        for fn in self.rewriter.container.iter_functions():
            fn.set_instrumented()

            for iidx, instr in enumerate(fn.cache):
                if instr.address in fn.bbstarts:
                    iinstr = []
                    free_regs = fn.analysis['free_registers'][iidx]
                    flags_are_free = 'rflags' in free_regs

                    regs_to_save = [
                        r for r in KcovInstrument.CALLER_SAVED_REGS
                        if r not in free_regs
                    ]

                    if not flags_are_free:
                        iinstr.append('\tpushfq')

                    for reg in regs_to_save:
                        iinstr.append('\tpushq %{}'.format(reg))

                    # Keep the stack pointer aligned
                    used_stack_slots = len(regs_to_save) if flags_are_free else len(regs_to_save) + 1

                    if (used_stack_slots % 2) != 0:
                        iinstr.append('\tsubq $8, %rsp')

                    iinstr.append('\tcallq __sanitizer_cov_trace_pc')

                    if (used_stack_slots % 2) != 0:
                        iinstr.append('\taddq $8, %rsp')

                    for reg in regs_to_save[::-1]:
                        iinstr.append('\tpopq %{}'.format(reg))

                    if not flags_are_free:
                        iinstr.append('\tpopfq')

                    instr.instrument_before(InstrumentedInstruction('\n'.join(iinstr)))


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("binary", type=str, help="Input binary to instrument")
    argp.add_argument("outfile", type=str, help="Input binary to instrument")

    argp.add_argument(
        "--kcov", action='store_true', help="Instrument the kernel module with kcov")

    args = argp.parse_args()

    rewriter = do_symbolization(args.binary, args.outfile)

    instrumenter = Instrument(rewriter)
    instrumenter.do_instrument()

    if args.kcov:
        kcov_instrumenter = KcovInstrument(rewriter)
        kcov_instrumenter.do_instrument()

    rewriter.dump()
