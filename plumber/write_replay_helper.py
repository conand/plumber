import angr
from trraces.replay_interfaces.angr.symbolic_pointer_replay_helper import SymbolicPointerReplayHelper
from trraces.replay_interfaces.angr.angr_trace_replay_helper import AngrTraceReplayHelper
from trraces.replay_interfaces.angr.setup_state import setup_generic_state
from trraces.replay_interfaces.angr.manipulation_interface import AngrStateManipulationInterface
from trraces.replay_interfaces.angr.symbolic_pointer_manipulation_interface import SymbolicPointerTrackingManipulationInterface

import logging

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


def handle_write(replay_interface):
    s = replay_interface.state
    proc = s.scratch.sim_procedure

    write_len = s.solver.eval_one(proc.cc.arg(s, 2))
    buff_addr = proc.cc.arg(s, 1)
    output = s.memory.load(s.solver.eval(buff_addr.to_claripy()), write_len)

    if output.symbolic:
        l.info("Leak of sensitive data detected in write: {}".format(output))

        start_idx = 0
        end_idx = 0
        for i in range(write_len):
            if s.memory.load(buff_addr.to_claripy() + i, 1).symbolic:
                start_idx = i
                break

        '''
        for i in range(start_idx, write_len):
            if not s.memory.load(buff_addr.to_claripy() + i, 1).symbolic:
                end_idx = i
                break
        '''

        sym_var = s.memory.load(buff_addr.to_claripy() + start_idx, 8)
        leaked_addr = hex(s.solver.eval(sym_var.reversed))

        s.globals["leaks"] = s.globals["leaks"] + ("write", leaked_addr)


class PlumberReplayHelper(AngrTraceReplayHelper):

    def _handle_syscall_write(self, name, replay_interface, enter_frame, exit_frame):
        retval = super()._handle_syscall_write(name, replay_interface, enter_frame, exit_frame)
        handle_write(replay_interface)
        return retval


class PlumberPointerReplayHelper(SymbolicPointerReplayHelper):

    def _handle_syscall_write(self, name, replay_interface, enter_frame, exit_frame):
        # import ipdb; ipdb.set_trace()
        retval = super()._handle_syscall_write(name, replay_interface, enter_frame, exit_frame)
        handle_write(replay_interface)
        return retval


def setup_plumber_state(trace_dir, state, **kwargs):
    return setup_generic_state(trace_dir, state, AngrStateManipulationInterface, PlumberReplayHelper)


def setup_plumber_pointer_state(trace_dir, state, **kwargs):
    return setup_generic_state(trace_dir, state, SymbolicPointerTrackingManipulationInterface, PlumberPointerReplayHelper)
