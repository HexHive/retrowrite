from capstone import *
from keystone import *
from librw_arm64.util.logging import *
import subprocess
import sys


# ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
# cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def instr(assembly):
    encoding, count = ks.asm(assembly)
    cs.detail = True
    instructions = list(cs.disasm(bytes(encoding), 0x1000))
    return instructions[0]

def cmd(text):
    try:
        return (False, subprocess.check_output(text, shell=True, stderr=subprocess.STDOUT))
    except subprocess.CalledProcessError as e:
        return (True, e.output)

def gcc(code):
    with open("test.s", "w") as f:
        f.write(code)
    return cmd("gcc -g -fsanitize=address test.s -o test.out")

def retrowrite_and_exec(code):
    err, out = gcc(code)
    if err: print(out); exit(1)
    print(".", end=""); sys.stdout.flush()

    err, out = cmd("python3 -m arm.rwtools.asan.asantool ./test.out ./test_rw.s")
    if err: print(out); exit(1)
    print(".", end=""); sys.stdout.flush()

    err, out = cmd("gcc -g -fsanitize=address test_rw.s -o test_rw.out")
    if err: print(out); exit(1)
    print(".", end=""); sys.stdout.flush()
    return cmd("./test_rw.out")[1]


def run_test(test_func):
    print(f"[{BLUE}TEST{CLEAR}] Testing {test_func.__code__.co_name} ... ", end="")
    sys.stdout.flush()
    # try:
    result = test_func()
    print(f"{GREEN}PASSED{CLEAR}")
    # except AssertionError as e:
        # print(f"{CRITICAL}FAIL{CLEAR}")
        # print(e)

start_main = """
    .global main
    .type main, %function
    main:
       stp x29, x30, [sp, -0x30]!
       mov x29, sp
"""
end_main = """
       ldp x29, x30, [sp], 0x30
       mov x0, 0
       ret
    .size main, .-main
"""

def simple_asan_load8():
    code = start_main + """
           mov x0, 0x100
           bl malloc
           add x0, x0, 0x200
           ldr x1, [x0]
    """ + end_main
    assert b"heap-buffer-overflow" in retrowrite_and_exec(code)


def simple_asan_store8():
    code = start_main + """
           mov x0, 0x100
           bl malloc
           add x0, x0, 0x200
           str x1, [x0]
    """ + end_main
    assert b"heap-buffer-overflow" in retrowrite_and_exec(code)

    code = start_main + """
           mov x0, 0x100
           bl malloc
           str x1, [x0, 0x100]
    """ + end_main
    assert b"heap-buffer-overflow" in retrowrite_and_exec(code)

    code = start_main + """
           mov x0, 0x100
           bl malloc
           mov x1, 0x20
           str x1, [x0, x1, LSL#3]
    """ + end_main
    assert b"heap-buffer-overflow" in retrowrite_and_exec(code)


def asan_load_16():
    code = start_main + """
           mov x0, 0x100
           bl malloc
           ldp x0, x1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"READ of size 16"]])

    code = start_main + """
           mov x0, 0x100
           bl malloc
           ldp x0, x1, [x0, 0xf8]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"READ of size 16"]])


def asan_store_1_2_4_8_16():
    code = start_main + """
           mov x0, 0x100
           bl malloc
           stp x0, x1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 16"]])

    code = start_main + """
           mov x0, 0x100
           bl malloc
           str x1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 8"]])

    code = start_main + """
           mov x0, 0x100
           bl malloc
           strh w1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 2"]])

    code = start_main + """
           mov x0, 0x100
           bl malloc
           str w1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 4"]])

    code = start_main + """
           mov x0, 0x100
           bl malloc
           strb w1, [x0, 0x100]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 1"]])

    code = start_main + """
           mov x0, 0x101
           bl malloc
           strb w1, [x0, 0x101]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 1"]])

    code = start_main + """
           mov x0, 0x104
           bl malloc
           str w1, [x0, 0x104]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 4"]])

    code = start_main + """
           mov x0, 0x102
           bl malloc
           strb w1, [x0, 0x105]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x in output for x in [b"heap-buffer-overflow", b"WRITE of size 1"]])

    code = start_main + """
           mov x0, 0x200
           bl malloc
           strb w1, [x0, 0x105]
    """ + end_main
    output = retrowrite_and_exec(code)
    assert all([x not in output for x in [b"heap-buffer-overflow", b"WRITE of size 1"]])



if __name__ == "__main__":
    run_test(asan_load_16)
    run_test(asan_store_1_2_4_8_16)
    run_test(simple_asan_store8)
    run_test(simple_asan_load8)

