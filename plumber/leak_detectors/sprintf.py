
import logging

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


def taint(fn):

    def tainted_fn(*args, **kwargs):
        simproc_obj = args[0]
        current_state = simproc_obj.state

        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
