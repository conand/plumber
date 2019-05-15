
import logging

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


def taint(fn):

    def tainted_fn(*args, **kwargs):
        simproc_obj = args[0]
        current_state = simproc_obj.state
        string_address = simproc_obj.arg(0).to_claripy()
        data_value = current_state.memory._read_from(current_state.solver.eval(string_address), 8)

        l.info("Checking argument of puts")

        if data_value.symbolic:
            # leaks['printf'] = True  # registering the leak
            l.info("Leak of sensitive data detected on puts")
            current_state.globals["leaks"] = current_state.globals["leaks"] + (__name__,)

        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
