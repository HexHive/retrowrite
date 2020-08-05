from capstone import *
from keystone import *
from arm.librw.util.logging import *
import subprocess
import sys


def cmd(text):
    try:
        return subprocess.check_output(text, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output

def check_arch():
    res = cmd("lscpu")
    if "aarch64" not in res.split()[0]:
        critical("Those tests can only be run on an ARM 64 architecture - exiting")
        exit(1)

def check_files():
    # XXX
    pass


def retrowrite_and_exec(filename):
    cmd(f"python3 -m arm.librw.rw {filename} /tmp/{filename}_rw.s")
    # cmd(f"gcc -g -fsanitize=address /tmp/{filename}_rw.s -o /tmp/{filename}_rw.out")
    cmd(f"gcc -g /tmp/{filename}_rw.s -o /tmp/{filename}_rw.out")
    return cmd(f"/tmp/{filename}_rw.out")
    

def run_test(test_func):
    print(f"[{BLUE}TEST{CLEAR}] Testing {test_func.__code__.co_name} ... ", end="")
    sys.stdout.flush()
    # try:
    result = test_func()
    print(f"{GREEN}PASSED{CLEAR}")
    # except AssertionError as e:
        # print(f"{CRITICAL}FAIL{CLEAR}")
        # print(e)


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





if __name__ == "__main__":
    check_arch()
    check_files()
    run_test(asan_load_16)
    run_test(asan_store_1_2_4_8_16)
    run_test(simple_asan_store8)
    run_test(simple_asan_load8)

