import angr
from trraces.replay_interfaces.angr.symbolic_pointer_replay_helper import SymbolicPointerReplayHelper
from trraces.replay_interfaces.angr.setup_state import setup_generic_state
from trraces.replay_interfaces.angr.manipulation_interface import AngrStateManipulationInterface


class PlumberTraceReplayHelper(SymbolicPointerReplayHelper):

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return PlumberTraceReplayHelper(self.trrace)

    def _handle_syscall_write(self, name, replay_interface, enter_frame, exit_frame):
        import ipdb; ipdb.set_trace()
        retval = super()._handle_syscall_write(name, replay_interface, enter_frame, exit_frame)

        s = replay_interface.state
        proc = s.scratch.sim_procedure

        write_len = s.solver.eval_one(proc.cc.arg(s, 2))
        buff_addr = proc.cc.arg(s, 1)
        output = s.memory.load(s.solver.eval(buff_addr.to_claripy()), write_len)

        if output.symbolic:
            l.info("Leak of sensitive data detected in write: {}".format(output))
            s.globals["leaks"] = s.globals["leaks"] + ("write",)

        return retval

def setup_plumber_tracking_state(trace_dir, state, **kwargs):
    return setup_generic_state(trace_dir, state, AngrStateManipulationInterface, PlumberTraceReplayHelper)
