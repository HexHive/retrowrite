"""
Blanket pass to do several function stack frame analyses
"""

from collections import defaultdict

from capstone.x86_const import X86_REG_RSP


class StackFrameAnalysis(object):
    KEY = 'stack_frame'
    KEY_IS_LEAF = 'is_leaf'

    def __init__(self):
        self.analysis = defaultdict(dict)

    @staticmethod
    def analyze(container):
        analyzer = StackFrameAnalysis()
        analyzer.analyze_container(container)
        analyzer.update_results(container)

    def analyze_container(self, container):
        for addr, fn in container.functions.items():
            self.analyze_function(fn, container)

    def analyze_function(self, function, container):
        self.analyze_is_fn_leaf(function, container)

    def analyze_is_fn_leaf(self, function, container):
        is_leaf = True
        for instruction in function.cache:
            if "bl" in instruction.mnemonic: #bl or blr
                target = instruction.cs.operands[-1].imm
                if target != function.start:  # not a recursive call
                    is_leaf = False
                    break

        self.analysis[function.start][
            StackFrameAnalysis.KEY_IS_LEAF] = is_leaf


    def update_results(self, container):
        for key, result in self.analysis.items():
            for rkey, values in result.items():
                container.functions[key].analysis[rkey] = values
