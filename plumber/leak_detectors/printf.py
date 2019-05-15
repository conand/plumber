
import logging

l = logging.getLogger(name=__name__)


# TODO: generalize to 32/64 bits
def taint(fn):

    def tainted_fn(*args, **kwargs):
        simproc_obj = args[0]
        current_state = simproc_obj.state
        fmt_str = simproc_obj._parse(0)

        argpos = 1

        for c in fmt_str.components:
            l.warn("Checking argument {} of printf, format string is {}".format(str(argpos), str(c)))
            string_address = simproc_obj.arg(argpos).to_claripy()
            data_value = current_state.memory._read_from(current_state.solver.eval(string_address), 8)

            if data_value.symbolic:
                # leaks['printf'] = True  # registering the leak
                l.warn("Leak of sensitive data detected on argument {} of printf".format(str(argpos)))
                current_state.globals["leaks"] = current_state.globals["leaks"] + (__name__ + ".argument." + str(argpos),)

            argpos += 1

        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
