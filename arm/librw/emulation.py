
from capstone import CS_OP_REG, CS_OP_IMM
from arm.librw.util.arm_util import reg_name, get_access_size_arm
from arm.librw.util.logging import *
import copy


class Expr:
    def __init__(self, left=None, right=None, op=""):
        self.left = left
        self.right = right
        self.operation = op
        self.mem = False

    def replace(self, old, new, d=0):
        # print("  "*d, "left")
        # print("  "*d, self.left, type(self.left))
        # print("  "*d, "right")
        # print("  "*d, self.right, type(self.right))

        if isinstance(self.left, Expr):
            # print("  "*d, "calling left")
            self.left.replace(old, new, d+1)
        elif self.left == old:
            self.left = copy.copy(new)
        if isinstance(self.right, Expr):
            # print("  "*d, "calling right")
            self.right.replace(old, new, d+1)
        elif self.right == old:
            self.right = copy.copy(new)
        # print("  "*d, "exit")

    def simplify(self):
        print("OK", self.left, self.right)
        # if self.left is None or self.right is None: return
        if isinstance(self.left, Expr):
            self.left.simplify()
            if self.left.right == None and not self.left.mem:
                self.left = self.left.left
        if isinstance(self.right, Expr):
            self.right.simplify()
            if self.right.right == None and not self.right.mem:
                self.right = self.right.left
        print("OK", self.left, self.right)
        print("OK", type(self.left), type(self.right))
        if isinstance(self.left, int) and isinstance(self.right, int):
            if self.operation == "+":
                self.left = self.left + self.right
            elif self.operation == "-":
                self.left = self.left - self.right
            elif self.operation == "<<":
                self.left = self.left << self.right
            else:
                critical(f"Operation {self.operation} not supported.")
                exit(1)
            self.right = None



    def __str__(self):
        if self.right == None:
            if self.mem: return "[" + str(self.left) + "]"
            return str(self.left)
        else:
            s = "(" if not self.mem else "["
            s += str(self.left) + " " + self.operation + " " + str(self.right)
            s += ")" if not self.mem else "]"
            return s


class Path:
    def __init__(self, function, address, reg_pool=[], exprvalue=""):
        self.address = address
        self.function = function
        self.reg_pool = set(reg_pool)
        self.inst_idx = 0
        self.expr = Expr(exprvalue)

    def emulate(self, instr):
        if instr.mnemonic in ["cmp", "cmn"]: #skip comparisons
            return

        ops = instr.cs.operands
        regs_written = instr.reg_writes_common()
        for r in regs_written:
            if r not in self.reg_pool: continue
            self.reg_pool.remove(r)

        regs_read = instr.reg_reads()
        for reg in regs_read:
            self.reg_pool.add(reg)

        if instr.cs.mnemonic in ["bl"]:
            return

        if instr.cs.mnemonic == "add" or instr.mnemonic == "sub":
            operation = "+" if instr.mnemonic == "add" else "-"
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = ops[2].reg
            if ops[2].type == CS_OP_REG:
                second = reg_name(second)
            if ops[2].shift.type == 1:
                second = Expr(second, ops[2].shift.value, op="<<")
            self.expr.replace(result, Expr(first, second, op=operation))

        elif instr.cs.mnemonic in ["adr", "adrp"]:
            result = reg_name(ops[0].reg)
            first = ops[1].imm
            self.expr.replace(result, first)

        elif instr.cs.mnemonic in ["mov", "movz"]: #XXX: movz?
            result = reg_name(ops[0].reg)
            first = ops[1].reg
            if instr.mnemonic == "movz" and first != 0: import IPython; IPython.embed() 
            self.expr.replace(result, first if ops[1].type == CS_OP_IMM else reg_name(first))

        elif instr.cs.mnemonic in ["sxtw"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            self.expr.replace(result, first)

        # https://modexp.wordpress.com/2018/10/30/arm64-assembly/
        elif instr.cs.mnemonic in ["sbfiz"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = ops[2].imm
            third = ops[3].imm
            mask = (1 << (third)) - 1
            self.expr.replace(result, Expr(Expr(first, mask, "&"), second, "<<"))


        elif instr.cs.mnemonic in ["lsl"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg) if ops[2].type == CS_OP_REG else ops[2].imm
            self.expr.replace(result, Expr(first, second, op="<<"))

        elif instr.cs.mnemonic in ["stp"]:
            if "]," in instr.op_str: assert False
            if "!" in instr.op_str:
                mem, mem_op_idx = instr.get_mem_access_op()
                mem_op = instr.cs.operands[mem_op_idx]
                if mem.index != 0 or mem_op.shift.type != 0: assert False
                if mem.disp == 0: assert False
                first = reg_name(mem.base)
                self.expr.replace(first, Expr(first, mem.disp, "+"))
            return # we don't care about stores for now, only if they do pre-indexing


        elif instr.cs.mnemonic.startswith("ldp"):
            if "!" in instr.op_str: assert False
            if "]," in instr.op_str: assert False
            results = (reg_name(ops[0].reg), reg_name(ops[1].reg))
            mem, mem_op_idx = instr.get_mem_access_op()
            mem_op = instr.cs.operands[mem_op_idx]
            first = reg_name(mem.base)
            if mem.disp != 0:
                final = Expr(first, mem.disp, op="+")
            else:
                final = Expr(first)
            sz = get_access_size_arm(instr.cs)[0] // 2
            final.mem = sz
            self.expr.replace(results[0], final)  # replace the first register written
            final.mem = False
            final2 = Expr(final, sz, op="+")
            final2.mem = sz
            self.expr.replace(results[1], final2) # replace the second register written

        elif instr.cs.mnemonic.startswith("ldr"):
            if "]," in instr.op_str: assert False
            result = reg_name(ops[0].reg)
            mem, mem_op_idx = instr.get_mem_access_op()
            mem_op = instr.cs.operands[mem_op_idx]
            first = reg_name(mem.base)
            second = reg_name(mem.index) if mem.index != 0 else ""
            if mem_op.shift.type == 1:
                second = Expr(second, mem_op.shift.value, op="<<")
            elif mem.disp != 0:
                if "!" in instr.op_str: 
                    if mem.index != 0 or mem_op.shift.type != 0: assert False
                    self.expr.replace(first, Expr(first, second, "+"))
                second = mem.disp
            if second == "":
                final = Expr(first)
            else:
                final = Expr(first, second, op="+")
            final.mem = get_access_size_arm(instr.cs)[0]
            self.expr.replace(result, final)


        else:
            print("NOT SUPPORTED", instr.cs)
            assert False



