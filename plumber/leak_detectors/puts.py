
import logging

l = logging.getLogger(name=__name__)


def taint(fn):

    def tainted_fn(*args, **kwargs):
        current_state = args[0].state

        data_address = current_state.solver.eval(current_state.regs.rsi)
        data_value = current_state.memory._read_from(data_address, 8)

        if data_value.symbolic:
            # leaks['printf'] = True  # registering the leak
            print("Leak of sensitive data detected! {}".format(data_value))

        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
