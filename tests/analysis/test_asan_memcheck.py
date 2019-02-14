import sys
import os
#sys.path.pop(0)
sys.path[0] = os.path.join(sys.path[0], "retrowrite")
print(sys.path)

from retrowrite.librw.container import Function, Container
from retrowrite.librw.analysis.register import RegisterAnalysis
from retrowrite.librw.analysis.stackframe import StackFrameAnalysis
from retrowrite.librw.rw import Rewriter

from retrowrite.rwtools.asan.instrument import Instrument


CODE_3_FREE = """
push %rbp
movq %rsi, 4(%rdi)
popq %rax
popq %r10
popq %r11
ret
"""


def generate_code(free, use, access, rflags):
    code = ["ret"]
    for reg in free:
        code.insert(0, "popq %{}".format(reg))
    for reg in use:
        code.insert(0, "push %{}".format(reg))
    if rflags:
        code.insert(0, "jne .START")
    code.insert(0, access)
    code.insert(0, "pushq %rbp")
    code.insert(0, ".START:")

    return '\n'.join(code)


def get_function(code):
    import keystone as ks

    ksa = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    ksa.syntax = ks.KS_OPT_SYNTAX_ATT
    asm, count = ksa.asm(code)

    asm = bytes(asm)

    func = Function("DYNCODE", 0x1000, len(asm), asm)

    container = Container()
    container.add_function(func)

    return container


def get_instrumented(free, use, access, rflags, instrument_stack=False):
    code = generate_code(free, use, access, rflags)
    container = get_function(code)
    nexts = []
    rw = Rewriter(container, "")
    func = rw.container.functions[0x1000]

    for idx, inst in enumerate(func.cache):
        if idx in nexts:
            func.nexts[idx].append("call")
        elif idx + 1 < len(func.cache):
            func.nexts[idx].append(idx + 1)
        else:
            func.nexts[idx].append("ret")

    rw.container.functions[0x1000] = func

    StackFrameAnalysis.analyze(container)
    RegisterAnalysis().analyze(container)

    func = rw.container.functions[0x1000]

    for idx, instruction in enumerate(func.cache):
        print(instruction, func.analysis['free_registers'][idx])

    instrumenter = Instrument(rw)
    if instrument_stack:
        instrumenter.instrument_stack()

    instrumenter.instrument_mem_accesses()
    return rw


def test_memac8_3free_rflags_free():
    rw = get_instrumented(
        ["rax", "r10", "r11"],
        [],
        "movq %rsi, 4(%rdi)",
        False)

    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_3free_rflags_free():
    rw = get_instrumented(["rax", "r10", "r11"], [], "mov %esi, 4(%rdi)", False)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac2_3free_rflags_free():
    rw = get_instrumented(
        ["rax", "r10", "r11"],
        [],
        "mov %si, 4(%rdi)",
        False)

    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac1_3free_rflags_free():
    rw = get_instrumented(
        ["rax", "r10", "r11"],
        [],
        "mov %sil, 4(%rdi)",
        False)

    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_3free_rflags_used():
    rw = get_instrumented(
        ["rax", "r10", "r11"],
        [],
        "mov %esi, 4(%rdi)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_3free_rflags_used_rax_used():
    rw = get_instrumented(
        ["r10", "r11"],
        ["rax"],
        "mov %esi, 4(%rdi)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_1free_rflags_used_rax_used():
    rw = get_instrumented(
        ["r10", "r11"],
        ["rax", 'r8', 'r9', 'r11', 'rcx'],
        "mov %esi, 4(%rdi)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_1free_rax_used():
    rw = get_instrumented(
        ["r10"],
        ["rax", 'r8', 'r9', 'r11', 'rcx'],
        "mov %esi, 4(%rdi)",
        False)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_0free_rflags_free():
    rw = get_instrumented(
        [],
        ["rax", 'r8', 'r9', 'r11', 'rcx', "r10"],
        "mov %esi, 4(%rdi)",
        False)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))

def test_memac4_rdi_free_rflags_free():
    rw = get_instrumented(
        ['rdi'],
        ["rax", 'r8', 'r9', 'r11', 'rcx', "r10"],
        "mov %esi, 4(%r12)",
        False)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_0free_rflags_used():
    rw = get_instrumented(
        [],
        ["rax", 'r8', 'r9', 'r11', 'rcx', "r10"],
        "mov %esi, 4(%rdi)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_memac4_rax_free_rflags_used():
    rw = get_instrumented(
        ["rax"],
        ['r8', 'r9', 'r11', 'rcx', "r10"],
        "mov %esi, 4(%rdi)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_stack_instrumentation_1():
    code = """ pushq %rbp
        pushq %rbx
        mov %rdi,%rbx
        sub $0x38, %rsp
        movq %fs:0x28, %rax
        movq %rax, 0x28(%rsp)

        movq 0x28(%rsp), %rax
        xorq %fs:0x28, %rax
        """

    rw = get_instrumented([], [], code, False, True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_regression_leaf_function_1():
    rw = get_instrumented(
        [],
        ["rax", 'r8', 'r9', 'r11', 'rcx', "r10"],
        "mov %rsi, -8(%rsp)",
        True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_regression_leaf_function_2():
    rw = get_instrumented(
        [],
        ["rax", 'r8', 'r9', 'r11', 'rcx', "r10"],
        "leaq -8(%rsp), %rsi\nmovq 0(%rsi), %rdi",
        False)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))


def test_rep_stosq_1():
    code = """ 
    rep stosq
        """

    rw = get_instrumented([], [], code, False, True)
    func = rw.container.functions[0x1000]
    print()
    print(str(func))
