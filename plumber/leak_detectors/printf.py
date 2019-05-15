
import logging

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


def taint(fn):

    def tainted_fn(*args, **kwargs):
        simproc_obj = args[0]
        current_state = simproc_obj.state
        fmt_str = simproc_obj._parse(0)

        argpos = 1

        for c in fmt_str.components:
            l.info("Checking argument %s of printf, format string is %s" % (str(argpos), str(c)))
            string_address = simproc_obj.arg(argpos).to_claripy()
            data_value = current_state.memory._read_from(current_state.solver.eval(string_address), 8)

            if data_value.symbolic:
                # leaks['printf'] = True  # registering the leak
                l.info("Leak of sensitive data detected on argument %s of printf" % (str(argpos)))
                current_state.globals["leaks"] = current_state.globals["leaks"] + (__name__ + ".argument." + str(argpos),)

            argpos += 1

        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
