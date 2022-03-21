
from capstone import CS_OP_REG, CS_OP_IMM
from librw_arm64.util.arm_util import reg_name, get_access_size_arm, is_stackframe_mov
from librw_arm64.util.logging import *
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
            self.left = copy.deepcopy(new)
        if isinstance(self.right, Expr):
            # print("  "*d, "calling right")
            self.right.replace(old, new, d+1)
        elif self.right == old:
            self.right = copy.deepcopy(new)
        # print("  "*d, "exit")

    def simplify(self):
        debug("OK" + str(self.left) + "," + str(self.right))
        # if self.left is None or self.right is None: return
        if isinstance(self.left, Expr):
            self.left.simplify()
            if self.left.right == None and not self.left.mem:
                self.left = self.left.left
        if isinstance(self.right, Expr):
            self.right.simplify()
            if self.right.right == None and not self.right.mem:
                self.right = self.right.left
        debug(f"simplifying, {self.left}, {self.right}")
        debug(f"simplifying, {type(self.left)}, {type(self.right)}")
        if isinstance(self.left, int) and isinstance(self.right, int):
            if self.operation == "+":
                self.left = self.left + self.right
            elif self.operation == "-":
                self.left = self.left - self.right
            elif self.operation == "*":
                self.left = self.left * self.right
            elif self.operation == "/":
                self.left = self.left // self.right
            elif self.operation == "<<":
                self.left = self.left << self.right
            elif self.operation == ">>":
                self.left = self.left >> self.right
            elif self.operation == "&":
                self.left = (self.left & self.right)
            elif self.operation == "^":
                self.left = (self.left ^ self.right)
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
    def __init__(self, function, inst_idx, reg_pool=[], exprvalue="", visited=[]):
        self.function = function
        self.reg_pool = set(reg_pool)
        self.inst_idx = inst_idx
        self.expr = Expr(exprvalue)
        self.visited = visited
        self.steps = 0

    def __copy__(self):
        return Path(self.function, self.inst_idx, copy.copy(self.reg_pool),
                    copy.deepcopy(self.expr), self.visited[:])

    def emulate(self, instr):
        if instr.mnemonic in ["cmp", "cmn", "tst", "ccmp"]: #skip comparisons
            return
        if instr.mnemonic in ["tbl", "dup"]: #skip vector instructions
            return
        if instr.mnemonic in ["csinv"]: # skip comparison based instructions
            return
        if instr.mnemonic in ["fcvtzs"]: # skip floating point instructions
            return


        ops = instr.cs.operands
        regs_written = instr.reg_writes_common()
        regs_read = instr.reg_reads()


        if is_stackframe_mov(instr):
            mem, mem_op_idx = instr.get_mem_access_op()
            debug(f"next: {instr.cs}")
            if instr.mnemonic.startswith("st"):
                if f"<x29 + {mem.disp}>" in str(self.expr):
                    self.reg_pool.add(reg_name(ops[0].reg))
                    self.expr.replace(f"<x29 + {mem.disp}>", Expr(reg_name(ops[0].reg)))
                if instr.mnemonic == "stp":
                    if f"<x29 + {mem.disp + 8}>" in str(self.expr):
                        self.reg_pool.add(reg_name(ops[1].reg))
                        self.expr.replace(f"<x29 + {mem.disp + 8}>", Expr(reg_name(ops[1].reg)))
            if instr.mnemonic == "ldr":
                if reg_name(ops[0].reg) in self.reg_pool:
                    self.expr.replace(reg_name(ops[0].reg), Expr(f"<x29 + {mem.disp}>"))
                    self.reg_pool.remove(reg_name(ops[0].reg))
            return

        if not any([reg in self.reg_pool for reg in regs_written]):
            return # not interested in this instruction


        for r in regs_written:
            if r not in self.reg_pool: continue
            self.reg_pool.remove(r)

        for reg in regs_read:
            self.reg_pool.add(reg)

        if instr.cs.mnemonic in ["bl", "blr"]:
            return

        if instr.cs.mnemonic in ["add", "adds"] or instr.cs.mnemonic in ["sub", "subs"]:
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

        elif instr.cs.mnemonic in ["and", "ands"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            assert ops[1].type == CS_OP_REG
            second = ops[2].reg
            if ops[2].type == CS_OP_REG:
                second = reg_name(second)
            self.expr.replace(result, Expr(first, second, op="&"))

        elif instr.cs.mnemonic in ["asr"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            assert ops[1].type == CS_OP_REG
            second = ops[2].reg
            if ops[2].type == CS_OP_REG:
                second = reg_name(second)
            self.expr.replace(result, Expr(first, second, op=">>"))

        elif instr.cs.mnemonic in ["eor"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            if ops[2].type == CS_OP_IMM:
                self.expr.replace(result, Expr(first, second, op="^"))
            else:
                second = reg_name(ops[2].reg)
                shift = ops[2].shift.value
                self.expr.replace(result, Expr(first, Expr(second, shift, op="<<"), op="^"))



        elif instr.cs.mnemonic in ["mov", "movz"]: 
            result = reg_name(ops[0].reg)
            first = ops[1].reg
            if instr.mnemonic == "movz": assert ops[1].type == CS_OP_IMM
            self.expr.replace(result, first if ops[1].type == CS_OP_IMM else reg_name(first))

        elif instr.cs.mnemonic in ["movn"]: 
            result = reg_name(ops[0].reg)
            self.expr.replace(result, ~(ops[1].imm))

        elif instr.cs.mnemonic in ["sxtw"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            self.expr.replace(result, first)

        elif instr.cs.mnemonic in ["sdiv", "udiv"]: #XXX: sdiv should be signed
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg)
            self.expr.replace(result, Expr(first, second, '/'))

        elif instr.cs.mnemonic in ["mul", "smull"]: #XXX: smull should be signed
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg)
            self.expr.replace(result, Expr(first, second, '*'))

        elif instr.cs.mnemonic in ["smaddl", "umaddl", "madd"]: #XXX: smaddl should be signed
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg)
            third = reg_name(ops[3].reg)
            self.expr.replace(result, Expr(Expr(first, second, '*'), third, '+'))

        # https://modexp.wordpress.com/2018/10/30/arm64-assembly/
        elif instr.cs.mnemonic in ["ubfiz", "sbfiz"]: #XXX: sbfiz should be signed
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = ops[2].imm
            size = ops[3].imm
            mask = (1 << (size)) - 1
            self.expr.replace(result, Expr(Expr(first, mask, "&"), second, "<<"))

        elif instr.cs.mnemonic in ["lsl", "lsr"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg) if ops[2].type == CS_OP_REG else ops[2].imm
            operation = "<<"
            if instr.cs.mnemonic == "lsr": operation=">>"
            self.expr.replace(result, Expr(first, second, op=operation))

        elif instr.cs.mnemonic in ["str"]:
            mem, mem_op_idx = instr.get_mem_access_op()
            if "]," in instr.op_str: assert False
            if "!" in instr.op_str:
                mem_op = instr.cs.operands[mem_op_idx]
                if mem.index != 0 or mem_op.shift.type != 0: assert False
                if mem.disp == 0: assert False
                first = reg_name(mem.base)
                self.expr.replace(first, Expr(first, mem.disp, "+"))
            if reg_name(mem.base) == "x29":
                self.expr.replace(f"<x29 + {mem.disp}>", Expr(reg_name(instr.cs.operands[0].reg)))
            return # we don't care about stores for now, only if they do pre-indexing or on stack frames

        elif instr.cs.mnemonic in ["stp"]:
            mem, mem_op_idx = instr.get_mem_access_op()
            if "]," in instr.op_str: assert False
            if "!" in instr.op_str:
                mem_op = instr.cs.operands[mem_op_idx]
                if mem.index != 0 or mem_op.shift.type != 0: assert False
                if mem.disp == 0: assert False
                first = reg_name(mem.base)
                self.expr.replace(first, Expr(first, mem.disp, "+"))
            if reg_name(mem.base) == "x29":
                self.expr.replace(f"<x29 + {mem.disp}>", Expr(reg_name(instr.cs.operands[0].reg)))
                self.expr.replace(f"<x29 + {mem.disp + 8}>", Expr(reg_name(instr.cs.operands[1].reg)))
            return # we don't care about stores for now, only if they do pre-indexing or on stack frames


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

        elif instr.cs.mnemonic.startswith("ldr") or instr.cs.mnemonic.startswith("ldur"):
            result = reg_name(ops[0].reg)
            mem, mem_op_idx = instr.get_mem_access_op()
            mem_op = instr.cs.operands[mem_op_idx]
            first = reg_name(mem.base)
            second = reg_name(mem.index) if mem.index != 0 else ""
            if mem_op.shift.type == 1: # ldr x0, [x1, x2, shift]
                second = Expr(second, mem_op.shift.value, op="<<")
            elif mem.disp != 0:
                if "!" in instr.op_str:  #pre-increment
                    if mem.index != 0 or mem_op.shift.type != 0: assert False
                    self.expr.replace(first, Expr(first, second, "+"))
                    first = Expr(first, second, "+")
                second = mem.disp
            if "]," in instr.op_str: #post-increment
                if mem.index != 0 or mem_op.shift.type != 0: assert False
                self.expr.replace(first, Expr(first, ops[2].imm, "+"))
            if second == "":  # ldr x0, [x1]
                final = Expr(first)
            else:  # ldr x0, [x1, off]
                if first == "x29": # stack-frame based load 
                    final = Expr(f"<x29 + {second}>")
                else:  # normal register based load
                    final = Expr(first, second, op="+")
            final.mem = get_access_size_arm(instr.cs)[0]
            self.expr.replace(result, final)

        elif instr.cs.mnemonic in ["cset"]:
            result = reg_name(ops[0].reg)
            new_path = copy.copy(self)
            self.expr.replace(result, 1)
            new_path.expr.replace(result, 0)
            return [new_path]

        elif instr.cs.mnemonic in ["cinc"]:
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            new_path = copy.copy(self)
            self.expr.replace(result, first)
            new_path.expr.replace(result, Expr(first, 1, "+"))
            return [new_path]

        elif instr.cs.mnemonic.startswith("csel"):
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            second = reg_name(ops[2].reg)
            new_path = copy.copy(self)
            self.expr.replace(result, first)
            new_path.expr.replace(result, second)
            return [new_path]

        elif instr.cs.mnemonic.startswith("cneg"):
            result = reg_name(ops[0].reg)
            first = reg_name(ops[1].reg)
            new_path = copy.copy(self)
            self.expr.replace(result, first)
            new_path.expr.replace(result, Expr(Expr(first, -1, "*"), -1, "+")) # not binary operator
            return [new_path]

        else:
            print("NOT SUPPORTED", instr.cs)
            assert False

        debug(f"step: {instr.cs} - expr: {self.expr}")



