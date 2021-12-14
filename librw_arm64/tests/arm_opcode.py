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
    # try:
    result = test_func()
    print(f"{GREEN}PASSED{CLEAR}")
    # except AssertionError as e:
        # print(f"{CRITICAL}FAIL{CLEAR}")
        # print(e)



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
    assert get_access_size_arm(instr("strh w0, [x0]"))    == (2, is_store)


def test_free_registers():
    from arm.librw.analysis.register import RegisterAnalysis
    from arm.librw.container import Container
    from arm.librw.rw import Symbolizer
    from arm.librw.container import Function

    def used_regs(assembly):
        class fake_elf():
            def get_section_by_name(self, secname):
                return {"sh_addr":0, "sh_size": 0xffffffffff}
        encoding, instr_count = ks.asm(assembly)
        byts = bytes(encoding)
        fun = Function("fun", 0x0, len(byts), byts)
        fun.disasm()
        container = Container()
        container.functions[0] = fun
        container.loader = type("fake_text", (object,), {"elffile":fake_elf()})
        rw = Symbolizer()
        rw.symbolize_cf_transfer(container)
        ra = RegisterAnalysis()
        ra.analyze_function(fun)
        return {idx:sorted(regs) for idx,regs in ra.used_regs.items()}, len(fun.cache)

    code = """
    add x0, x1, x1
    add x2, x3, x3
    add x4, x5, x5
    br x11
    """
    regs, instr_cnt = used_regs(code)
    assert regs[3] == sorted(["x11", "w11"])
    assert regs[2] == sorted(["x5", "w5", "x11", "w11"])
    assert regs[1] == sorted(["x3", "w3", "x5", "w5", "x11", "w11"])
    assert regs[0] == sorted(["x1", "w1", "x3", "w3", "x5", "w5", "x11", "w11"])

    code = """
    ldr x10, [x0, 32]
    str x10, [x1, 32]!
    cmp x2, x3
    b.eq .ok
    add x0, x1, x1
    br x11
    .ok:
    br x12
    """
    regs, instr_cnt = used_regs(code)
    #assert all(["x2" in regs[i] for i in [0,1,2]]) XXX: capstone bug
    assert all(["x2" not in regs[i] for i in [3,4,5,6]])
    assert all(["x12" in regs[i] for i in [0,1,2,3,6]])
    assert all(["x12" not in regs[i] for i in [4,5]])
    assert all(["x10" in regs[i] for i in [1]])
    assert all(["x10" not in regs[i] for i in [0,2,3,4,5,6]])

if __name__ == "__main__":
    run_test(test_reg_size)
    run_test(test_mem_access_size)
    run_test(test_free_registers)

