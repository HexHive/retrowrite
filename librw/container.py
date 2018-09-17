

class Container():
    def __init__(self):
        self.functions = dict()
        self.sections = dict()
        self.loader = None

    def add_function(self, function):
        self.functions[function.name] = function

    def add_section(self, section):
        self.sections[section.name] = section

    def attach_loader(self, loader):
        self.loader = loader


class Function():
    def __init__(self, name, start, sz, bytes):
        self.name = name
        self.cache = list()
        self.start = start
        self.sz = sz
        self.bytes = bytes

    def disasm(self):
        pass


class DataSection():
    def __init__(self, name, base, sz, bytes):
        self.cache = list()
        self.base = base
        self.sz = sz
        self.bytes = bytes

    def load(self):
        pass
