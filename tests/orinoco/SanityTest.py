import sys

from tests.Test import Test

TEST_NAME = "GEN001 Sanity Test"
conditions = [
    "root_processes"
]


class SanityTest(Test):

    def __init__(self, logger):
        self.name = TEST_NAME
        self.report = None
        self.conditions = conditions
        self.conditions_met = False
        self.logger = logger
        self.action_results = []
        return

    def preconditions(self, report):

        for condition in self.conditions:
            if condition not in report.keys():
                self.logger.error("%s condition not met for test %s", condition, self.name)
                return False

        self.report = report
        return True

    def actions(self):
        root_processes = self.report["root_processes"]

        # Action 1: Check number of root processes, more than 5 is too many
        if len(root_processes) > 5:
            self.action_results.append({"few_root_processes": False})
        else:
            self.action_results.append({"few_root_processes": True})

        # Action 2: Check sshd or dropbear
        ssh_daemon_not_running = True
        for process in root_processes:
            if "sshd" in process or "dropbear" in process:
                ssh_daemon = False
        self.action_results.append({"ssh_daemon_not_running": ssh_daemon})

        return

    def postconditions(self):
        for action in self.action_results:
            for key in action.keys():
                result = action[key]
                if not result:
                    self.logger.error("%s: Action %s was false", self.name, key)
                    sys.stdout.flush()
        return self.action_results

    def get_name(self):
        return self.name
