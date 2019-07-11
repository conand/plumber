from abc import ABC
from abc import abstractmethod

import claripy
import logging
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream


_l = logging.getLogger(name=__name__)
_l.setLevel(logging.DEBUG)

class SensitiveTarget(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def taint_state(self, state):
        pass


'''
 Set symbolic the arguments passed to the binary.
'''
class ArgvSensitiveTarget(SensitiveTarget):

    def __init__(self, argv_idx):
        super().__init__()
        self.argv_idx = argv_idx

    def taint_state(self, state):
        '''
        state is in _start and the stack points to argv
        '''
        target_argv_address = state.mem[state.regs.rsp + 8 + (self.argv_idx * 8)].long.concrete # .resolved
        original_argv_value = state.mem[target_argv_address].string.concrete
        original_argv_size = len(original_argv_value)

        _l.debug("Storing sensitive data at {}, size of sensitive data is {}".format(hex(target_argv_address), 8*original_argv_size))

        sym_sensitive_argv = claripy.BVS('sensitive_argv{}'.format(self.argv_idx), 8 * original_argv_size)
        state.memory.store(target_argv_address, sym_sensitive_argv)
        # preconstrain sensitive data to original value
        state.preconstrainer.preconstrain(original_argv_value, sym_sensitive_argv)


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
