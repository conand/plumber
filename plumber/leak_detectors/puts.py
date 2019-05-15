
import logging

l = logging.getLogger(name=__name__)


def taint(fn):

    def tainted_fn(*args, **kwargs):
        current_state = args[0].state
        fn(*args, **kwargs) # execute normal SimProc.

    return tainted_fn
