import sys
sys.path.pop(0)
print(sys.path)

from retrowrite.librw.container import Function, Container
from retrowrite.librw.analysis.register import RegisterAnalysis


CODE1 = """
.THIS:
pushq %r12
pushq %rbp
movq %rsi, %r12
pushq %rbx
movslq %edi, %rbx
leaq 0x1000(%rip), %rdi
movl $0x20, %edx
movl $0x28, %esi
callq .THIS
leaq 0x1000(%rip), %rdi
movq %rbx, %rdx
movl $0x29, %esi
movq %rax, %rbp
shlq $2, %rbx
test %rbx, %rbx
jne .THIS
callq .THIS
leaq 0x1000(%rip), %rdi
movq %rbx, %rdx
movq %rax, 8(%rbp)
movl $0x2a, %esi
callq .THIS
leaq 0x1000(%rip), %rdi
movq %rax, 0x10(%rbp)
movq %rbx, %rdx
movl $0x2b, %esi
callq .THIS
movq %rax, 0x18(%rbp)
movq %rbp, 0(%r12)
popq %rbx
movl %r12d, %r12d
popq %rbp
popq %r12
retq
"""


def get_function(code):
    import keystone as ks

    ksa = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    ksa.syntax = ks.KS_OPT_SYNTAX_ATT
    asm, count = ksa.asm(code)

    asm = bytes(asm)

    func = Function("P7AllocTrace", 0x1000, len(asm), asm)
    func.disasm()

    container = Container()
    container.add_function(func)

    return container


def test_simple():
    container = get_function(CODE1)
    nexts = [8, 14, 19, 24]
    func = container.functions[0x1000]

    for idx, inst in enumerate(func.cache):
        if idx in nexts:
            func.nexts[idx].append("call")
        elif idx + 1 < len(func.cache):
            func.nexts[idx].append(idx + 1)
        else:
            func.nexts[idx].append("ret")

    ra = RegisterAnalysis()
    ra.analyze_function(func)
    print("===== FREE REGS:", func.name)
    for idx, instruction in enumerate(func.cache):
        print(instruction, ra.free_regs[idx])


def test_regression_1():
    code = """
    xorl %eax, %eax
    movl 8(%rbx), %ebp
    cmpl $1, %esi
    setne %al
    addl $3, %eax
    ret
    """

    nexts = []
    container = get_function(code)
    func = container.functions[0x1000]

    for idx, inst in enumerate(func.cache):
        if idx in nexts:
            func.nexts[idx].append("call")
        elif idx + 1 < len(func.cache):
            func.nexts[idx].append(idx + 1)
        else:
            func.nexts[idx].append("ret")

    ra = RegisterAnalysis()
    ra.analyze_function(func)
    print("===== FREE REGS:", func.name)
    for idx, instruction in enumerate(func.cache):
        print(instruction, ra.free_regs[idx])

    assert "rax" not in ra.free_regs[1]


def test_regression_1_counter_example():
    code = """
    xorl %eax, %eax
    movl 8(%rbx), %ebp
    cmpl $1, %esi
    setne %al
    mov $3, %eax
    ret
    """

    nexts = []
    container = get_function(code)
    func = container.functions[0x1000]

    for idx, inst in enumerate(func.cache):
        if idx in nexts:
            func.nexts[idx].append("call")
        elif idx + 1 < len(func.cache):
            func.nexts[idx].append(idx + 1)
        else:
            func.nexts[idx].append("ret")

    ra = RegisterAnalysis()
    ra.analyze_function(func)
    print("===== FREE REGS:", func.name)
    for idx, instruction in enumerate(func.cache):
        print(instruction, ra.free_regs[idx])

    assert "rax" in ra.free_regs[1]


def test_regression_2():
    code = """
    popq %rax
    movb %r8b, 0(%rax)
    cmpb %r12b, %bpl
    movl %r12d, %r8d
    ret
    """

    nexts = []
    container = get_function(code)
    func = container.functions[0x1000]

    for idx, inst in enumerate(func.cache):
        if idx in nexts:
            func.nexts[idx].append("call")
        elif idx + 1 < len(func.cache):
            func.nexts[idx].append(idx + 1)
        else:
            func.nexts[idx].append("ret")

    ra = RegisterAnalysis()
    ra.analyze_function(func)
    print("===== FREE REGS:", func.name)
    for idx, instruction in enumerate(func.cache):
        print(instruction, ra.free_regs[idx])

    assert "r8" not in ra.free_regs[0]
