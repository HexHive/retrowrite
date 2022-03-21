from capstone import *


def disasm_bytes(bytes, addr):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.syntax = CS_OPT_SYNTAX_ATT
    md.detail = True
    return list(md.disasm(bytes, addr))
