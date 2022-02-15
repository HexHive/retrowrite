from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_REG

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True


# Clobbered registers (reserved by caller, cannot overwrite)
clobbered_registers = ["x" + str(i) for i in range(19, 29)] + ["w" + str(i) for i in range(19, 29)]
# Non-clobbered registers (can be overwritten by a function)
non_clobbered_registers = ["x" + str(i) for i in range(0, 19)] + ["w" + str(i) for i in range(0, 19)]
# Argument registers (used to pass function arguments)
argument_registers = ["x" + str(i) for i in range(0, 8)] + ["w" + str(i) for i in range(0, 8)]


def get_reg_size_arm(regname):
    sizes = {
        "B" : 1,
        "H" : 2,
        "W" : 4,
        "S" : 4,
        "X" : 8,
        "D" : 8,
        "Q" : 16
    }
    return sizes[regname.upper()[0]]

def get_access_size_arm(instruction):
    bool_load = True if instruction.mnemonic.upper().startswith("L") else False
    # here we get the size from the last letter of the instruction
    # horrible hack I know, but capstone is a bad boy and is not reliable
    sizes = {
        "B" : 1,
        "H" : 2,
        "W" : 4,
        "R" : 8,
        "P" : 16
    }
    acsz = sizes[instruction.mnemonic.upper()[-1]]
    if instruction.operands[0].type == CS_OP_REG:
        reg = instruction.reg_name(instruction.operands[0].reg)
        regsz = get_reg_size_arm(reg)
        if regsz < acsz or regsz == 16:
            if acsz == 16: regsz *= 2  #16 means we store a pair, so double the size
            return (regsz, bool_load)
    return (acsz, bool_load)

def is_reg_32bits(reg):
    assert reg[0] in "bhwsxdq"
    return reg[0] == 'w'

def get_64bits_reg(reg):
    assert reg[0] == "w"
    return "x" + reg[1:]


def _is_jump_conditional(opcode):
    return opcode.startswith("b.") or opcode.startswith("cb") or opcode.startswith("tb")

def reg_name(reg):
    return cs.reg_name(reg)

def memory_replace(container, addr, size, value):
    sec = container.section_of_address(addr)
    if sec.name != ".rodata": 
        debug(f"WARNING: changing value not in rodata but in {sec.name}")
    sec.replace(addr, size, value)


def is_stackframe_mov(instr):
    if any([instr.cs.mnemonic.startswith(n) for n in ["ldr", "ldp", "str", "stp"]]):
        mem, mem_op_idx = instr.get_mem_access_op()
        if reg_name(mem.base) == "x29":
            return True
    return False
