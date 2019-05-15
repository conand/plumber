import logging
import archr

from angr import sim_options as so
from angr.procedures.stubs.format_parser import FormatParser


# List of SimProc we want to taint, we want to this dynamically based on
# some sort of Plumber config file.
from angr.procedures.libc.printf import printf
from angr.procedures.libc.fprintf import fprintf
from angr.procedures.libc.sprintf import sprintf
from angr.procedures.libc.snprintf import snprintf
from angr.procedures.libc.vsnprintf import vsnprintf
from angr.procedures.libc.puts import puts
from angr.procedures.libc.fputs import fputs

from angr.procedures.posix.send import send


import plumber.leak_detectors

_l = logging.getLogger(name=__name__)
_l.setLevel(logging.WARNING)

# run the tracer, grabbing the crash state
remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                  so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                  so.ALL_FILES_EXIST}
add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
               so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS}


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
        self.tracer_bow = archr.arsenal.QEMUTracerBow(self.target)

        # Let's initialize all the leak_detector_decorators for all the function we are interested on.
        # TODO: We will automatize this based on a Plumber configuration file.
        printf.run = plumber.leak_detectors.printf.taint(printf.run)
        puts.run = plumber.leak_detectors.puts.taint(puts.run)

        # TODO: implement these leak_detectors
        send.run = plumber.leak_detectors.send.taint(send.run)
        fprintf.run = plumber.leak_detectors.fprintf.taint(fprintf.run)
        sprintf.run = plumber.leak_detectors.sprintf.taint(sprintf.run)
        snprintf.run = plumber.leak_detectors.snprintf.taint(snprintf.run)
        vsnprintf.run = plumber.leak_detectors.vsnprintf.taint(vsnprintf.run)
        fputs.run = plumber.leak_detectors.fputs.taint(fputs.run)


    def run(self):
        r = self.tracer_bow.fire(testcase=self.payload, save_core=False)

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

        # Now, since we want to detect leaks in the output of the program, we have to define as symbolic
        # the data that we received as Sensitive from REX.
        # This is done using the taint_state method of the SensitiveTarget object, that will make sure
        # that something sensitive will be marked as symbolic.
        for sensitive_target in self.sensitive:
            sensitive_target.taint_state(initial_state)

        # Initialize the global tuple of leaks detected!
        # This will be populated by the leak_detectors decorators.
        initial_state.globals["leaks"] = ()

        simgr = self.project.factory.simulation_manager(
            initial_state,
            save_unsat=False,
            hierarchy=False,
        )

        # Using the tracer exploration technique by following the QEMU trace
        # collected before.
        self._t = r.tracer_technique(keep_predecessors=2)
        simgr.use_technique(self._t)

        try:
            simgr.run()
        except Exception:  # remember to check the "No more successors bug"
            pass

        last_state = simgr.active[0]

        # If we have any kind of leak this is exploitable!
        self._exploitable = any(last_state.globals["leaks"])


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
