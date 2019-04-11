from abc import ABC
from abc import abstractmethod

import claripy


class SensitiveTarget(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def taint_state(self, state):
        pass


class ArgvSensitiveTarget(SensitiveTarget):

    def __init__(self, argv_idx, size=32):
        super().__init__()
        self.argv_idx = argv_idx
        self.size = size

    def taint_state(self, state):
        state.posix.argv[self.argv_idx] = claripy.BVS('sensitive_argv{}'.format(self.argv_idx), self.size)


class FileSensitiveTarget(SensitiveTarget):

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def taint_state(self, state):
        raise NotImplementedError


class AddressSensitiveTarget(SensitiveTarget):

    def __init__(self, start_addr, end_addr):
        super().__init__()
        self.start_addr = start_addr
        self.end_addr = end_addr

    def taint_state(self, state):
        raise NotImplementedError
