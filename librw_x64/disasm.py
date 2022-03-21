from capstone import *


def disasm_bytes(bytes, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_ATT
    md.detail = True
    return list(md.disasm(bytes, addr))
