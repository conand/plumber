
import archr
import os
import plumber

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
cache_location = str(os.path.join(bin_location, 'tests_data/rop_gadgets_cache'))

def test_leak_detection():
    """
    Test that our write what where exploit can leak, and works in the presence of a shadowstack
    """
    leak_input = b"A"*66

    path = os.path.join("/home/degrigis/Projects/CHESS-hackathon/leak_mid")

    argv_sensitive_idx = 1
    argv_sensitive_target = plumber.ArgvSensitiveTarget(argv_sensitive_idx)
    sensitive = [argv_sensitive_target]

    with archr.targets.LocalTarget([path, 'secret', 'superstrongpassword'], target_os='linux', target_arch='x86_64') as target:
        plumber.Plumber(target, leak_input, sensitive)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    import logging
    logging.getLogger('rex').setLevel('DEBUG')
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
