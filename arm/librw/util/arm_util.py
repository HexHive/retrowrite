from capstone import CS_OP_REG

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
    assert reg[0] in "wxhq"
    return reg[0] == 'w'


def _is_jump_conditional(opcode):
    return opcode.startswith("b.")
