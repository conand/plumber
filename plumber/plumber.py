import logging
import archr

from angr import sim_options as so
from angr.procedures.stubs.format_parser import FormatParser

from .write_replay_helper import setup_plumber_state, setup_plumber_pointer_state
from .sensitive_targets import AllPointersSensitiveTarget

_l = logging.getLogger(name=__name__)
_l.setLevel(logging.INFO)

# run the tracer, grabbing the crash state
remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                  so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                  so.ALL_FILES_EXIST}
add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
               so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS, so.TRACK_SOLVER_VARIABLES}


class Plumber(object):
    '''
     Plumber will look for potential memory leaks of sensitive data
     inside the output of the program.

     The sensitive data we are looking for are specified inside the sensitive object.

     f.i. we want to see if argv[1] is inside the final output of the program, or a particular memory
     address content is disclosed inside the output. We are doing this by tracing the program inside
     its environment and tuning up the QEMUTracer exploration technique according to what we are looking for.

    '''
    def __init__(self, target, payload, sensitive):
        self.target = target  # type: archr.targets.Target
        self.payload = payload  # interesting input that we believe will trigger the memory leak.
        self.sensitive = sensitive  # specification of what is considered sensitive in our binary ( f.i. argv[2], access to a file called /token, ... )

        # flag to detect if we generated a valid leak and so if we should generate a pov
        self._exploitable = False

        # First thing, let's create a trace of the program under the concrete input we received.
        # If there are any command line arguments to the program they have been included during the
        # Creation of the target.
        self.tracer_bow = archr.arsenal.RRTracerBow(self.target)

    def run(self):
        if self.payload:
            r = self.tracer_bow.fire(testcase=self.payload, save_core=False)
        else:
            r = self.tracer_bow.fire(save_core=False)

        # Now we have to setup an angr project using the info we have in the archr environment.
        dsb = archr.arsenal.DataScoutBow(self.target)
        self.angr_project_bow = archr.arsenal.angrProjectBow(self.target, dsb)
        self.project = self.angr_project_bow.fire()

        # Let's get our initial state
        state_bow = archr.arsenal.angrStateBow(self.target, self.angr_project_bow)

        # Let's create an initial state
        initial_state = state_bow.fire(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options,
        )

        # Initialize the global tuple of leaks detected!
        # This will be populated by the leak_detectors decorators.
        initial_state.globals["leaks"] = ()

        simgr = self.project.factory.simulation_manager(
            initial_state,
            save_unsat=False,
            hierarchy=False,
        )

        if any([isinstance(sensitive_target, AllPointersSensitiveTarget) for sensitive_target in self.sensitive]):
            _l.info("All pointers will be made symbolic (this can be slow!)")
            plumber_state_setup_func = setup_plumber_pointer_state
        else:
            plumber_state_setup_func = setup_plumber_state

        # Using the tracer exploration technique by following the RR trace
        # collected before.
        self._t = r.tracer_technique(keep_predecessors=2, state_setup_func=plumber_state_setup_func)
        simgr.use_technique(self._t)

        # Now, since we want to detect leaks in the output of the program, we have to define as symbolic
        # the data that we received as Sensitive from REX.
        # This is done using the taint_state method of the SensitiveTarget object, that will make sure
        # that something sensitive will be marked as symbolic.
        for sensitive_target in self.sensitive:
            sensitive_target.taint_state(simgr.one_active)

        # try:
        simgr.run()
        # except Exception:  # remember to check the "No more successors bug"
        #     pass

        last_state = simgr.traced[0]

        #print(last_state)

        # If we have any kind of leak this is exploitable!
        self._exploitable = any(last_state.globals["leaks"])

        if self._exploitable:
            self._leaked = last_state.globals["leaks"][-1]


    def exploitable(self):
        return self._exploitable

    def pov(self):
        if isinstance(self.target, archr.targets.DockerImageTarget):

            pov = """
from subprocess import Popen, PIPE

def main():
    p = Popen(["docker", "run", "-i", "{}" ], stdin=PIPE, stdout=PIPE)
    out = p.communicate(input={})[0]

    print('PRIVDATA=' + out.decode('utf-8').split("\\n")[-1])

if __name__ == '__main__':
    main()
            """.format(self.target.image_id, self.payload)
        else:

            pov = """
from subprocess import Popen, PIPE
def main():
    p = Popen(['{}', '{}', '{}'], stdout=PIPE, stdin=PIPE)
    out = p.communicate(input={})[0]
    print('PRIVDATA=' + out.decode('utf-8').split("\\n")[-1])
if __name__ == '__main__':
    main()
            """.format(self.target.target_path, self.target.main_binary_args[1], self.target.main_binary_args[2],
                       self.payload)

        with open("./pov.py", "w") as pov_poc:
            pov_poc.write(pov)

        return pov
