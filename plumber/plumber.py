
import os
import struct
import tracer
import random
import logging
from itertools import groupby
import binascii

import claripy
import angr
import archr

from angr import sim_options as so
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream



# run the tracer, grabbing the crash state
remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                  so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                  so.ALL_FILES_EXIST}
add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
               so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS}


'''
 Plumber will look for potential memory leaks of sensitive data 
 inside the output of the program.
 
 The sensitive data we are looking for are specified inside the sensitive object.
 
 f.i. we want to see if argv[1] is inside the final output of the program, or a particular memory
 address content is disclosed inside the output. We are doing this by tracing the program inside 
 its environment and tuning up the QEMUTracer exploration technique according to what we are looking for.
 
'''
class Plumber(object):

    def __init__(self, target, payload, sensitive):

        self.target = target  # type: archr.targets.Target
        self.payload = payload # interesting input that we believe will trigger the memory leak.
        self.sensitive = sensitive # specification of what is considered sensitive in our binary ( f.i. argv[2], access to a file called /token, ... )

        # First thing, let's create a trace of the program under the concrete input we received.
        # If there are any command line arguments to the program they have been included during the
        # Creation of the target.
        self.tracer_bow = archr.arsenal.QEMUTracerBow(self.target)
        r = self.tracer_bow.fire(testcase=self.payload, save_core=False)


        # Now we have to setup a an angr project based on the concrete target.
        dsb = archr.arsenal.DataScoutBow(self.target)
        self.angr_project_bow = archr.arsenal.angrProjectBow(self.target, dsb)
        self.project = self.angr_project_bow.fire()
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
        for sensitive_target in sensitive:
            sensitive_target.taint_state(initial_state)

        simgr = self.project.factory.simulation_manager(
            initial_state,
            save_unsat=False,
            hierarchy=False,
        )

        self._t = r.tracer_technique(keep_predecessors=2)
        simgr.use_technique(self._t)

        simgr.run()

        print("LOL")

        #found = simgr.found[0]

        #stdout1 = found.posix.dumps(1)

        # Here check if the stdout contains something symbolic, if yes, well we have
        # a leak.
        # If there are multiple symbolic sources we have to understand what are we leaking.

        # TODO




        

