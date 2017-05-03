import sys

from tests.Test import Test

# A test instance must define a name and its conditions
TEST_NAME = "GEN001 Sanity Test"

# Conditions are the tagged data retrieved from the plan that must be present for validation
conditions = [
    "root_processes"
]

# The number of actions that must fail for the test to fails
MAXIMUM_ACTION_FAILURE_COUNT = 1

# This is a sample derived test case which has preconditions, performs two validations actions, stores the results,
# and checks the results against the postcondition policy


class SanityTest(Test):

    def __init__(self, logger):
        self.name = TEST_NAME
        self.threshold = MAXIMUM_ACTION_FAILURE_COUNT
        self.report = None
        self.conditions = conditions
        self.conditions_met = False
        self.logger = logger
        self.action_results = []
        return

    # Preconditions determine if the requisite data is available from the the executed plan to validate this test
    # If a required precondition is not met, the test can report to the caller via returning False
    def preconditions(self, report):

        for condition in self.conditions:
            if condition not in report.keys():
                self.logger.error("%s condition not met for test %s", condition, self.name)
                return False

        self.report = report
        return True

    # Actions are the implemented validations for security policies
    # Action tagged results are stored in the member "action_results" as dictionaries
    def actions(self):
        root_processes = self.report["root_processes"]

        # Action 1: Check number of root processes, more than 5 is too many
        if len(root_processes.keys()) > 5:
            self.action_results.append({"few_root_processes": False})
        else:
            self.action_results.append({"few_root_processes": True})

        # Action 2: Check for sshd or dropbear, the existence of either is a failure
        ssh_daemon_not_running = True
        for pid in root_processes.keys():
            if "sshd" in root_processes[pid] or "dropbear" in root_processes[pid]:
                ssh_daemon_not_running = False
        self.action_results.append(dict(ssh_daemon_not_running=ssh_daemon_not_running))

        return

    # Post conditions evaluate the results of validation actions
    # Failures are reported and the action results are returned to the caller
    # Total test case failure can be handled via threshold, reported in action_results
    def postconditions(self):
        false_count = 0
        for action in self.action_results:
            for key in action.keys():
                result = action[key]
                if not result:
                    self.logger.error("%s: Action %s was false", self.name, key)
                    sys.stdout.flush()
                    false_count += 1
        if self.threshold and false_count >= self.threshold:
            self.logger.error("%s: Exceeded failure threshold [TEST FAILURE]", self.name)
            self.action_results.append(dict(threshold_reached=True))
        return self.action_results

    def get_name(self):
        return self.name
