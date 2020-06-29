from capstone import *
from keystone import *
from arm.librw.util.logging import *


ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def instr(assembly):
    encoding, count = ks.asm(assembly)
    cs.detail = True
    instructions = list(cs.disasm(bytes(encoding), 0x1000))
    return instructions[0]

def run_test(test_func):
    print(f"[{BLUE}TEST{CLEAR}] Testing {test_func.__code__.co_name} ... ", end="")
    try:
        result = test_func()
        print(f"{GREEN}PASSED{CLEAR}")
    except AssertionError:
        print(f"{CRITICAL}FAIL{CLEAR}")



def test_reg_size():
    from arm.librw.util.arm_util import get_reg_size_arm
    assert get_reg_size_arm("x0") == 8
    assert get_reg_size_arm("q0") == 16
    assert get_reg_size_arm("h0") == 2


def test_mem_access_size():
    from arm.librw.util.arm_util import get_access_size_arm
    is_load, is_store = (1, 0)
    assert get_access_size_arm(instr("ldr x0, [x0]"))     == (8, is_load)
    assert get_access_size_arm(instr("ldr w0, [x0]"))     == (4, is_load)
    assert get_access_size_arm(instr("strb w0, [x0]"))    == (1, is_store)
    assert get_access_size_arm(instr("stp x0, x1, [x0]")) == (16, is_store)
    assert get_access_size_arm(instr("ldp x0, x1, [x0]")) == (16, is_load)
    assert get_access_size_arm(instr("str q0, [x0]"))     == (16, is_store)

if __name__ == "__main__":
    run_test(test_reg_size)
    run_test(test_mem_access_size)

