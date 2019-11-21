import archr
import os
import plumber


def test_leak_detection(leak_input):
    path = os.path.dirname(os.path.abspath(__file__)) + "/irving.bin"
    sensitive = [plumber.AllPointersSensitiveTarget()]

    with archr.targets.LocalTarget([path, '-s'], target_os='linux', target_arch='x86_64') as target:
        import ipdb; ipdb.set_trace()
        p = plumber.Plumber(target, leak_input, sensitive) # initialize the plumber
        p.run() # Go!

    if p.exploitable():
        p.pov()


if __name__ == "__main__":
    import sys
    import logging
    logging.getLogger('rex').setLevel('DEBUG')
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    leak_input = b"A"*254 + b";B"
    test_leak_detection(leak_input)

