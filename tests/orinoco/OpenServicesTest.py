import sys

from tests.Test import Test

# A test instance must define a name and its conditions
TEST_NAME = "GEN002 Privileged Network Services Test"

# Conditions are the tagged data retrieved from the plan that must be present for validation
conditions = [
    "root_processes",
    "listening_ipv4_tcp_sockets",
    "listening_ipv6_tcp_sockets",
    "listening_ipv4_udp_sockets",
    "listening_ipv4_tcp_sockets"
]

# The number of actions that must fail for the test to fails
MAXIMUM_ACTION_FAILURE_COUNT = 1

# This is a sample derived test case which has preconditions, performs two validations actions, stores the results,
# and checks the results against the postcondition policy


class OpenServicesTest(Test):

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
        root_processes_pids = list(self.report["root_processes"].copy().keys())
        tcp4sockets = self.report["listening_ipv4_tcp_sockets"]
        tcp6sockets = self.report["listening_ipv6_tcp_sockets"]
        udp4sockets = self.report["listening_ipv4_udp_sockets"]
        udp6sockets = self.report["listening_ipv6_udp_sockets"]

        # Action 1: Check to see if any tcp4 sockets are held by privileged processes
        for socket in tcp4sockets.keys():
            pids = tcp4sockets[socket]

            last_colon = socket.rfind(":")
            address = socket[:last_colon].strip()
            port = socket[last_colon+1:].strip()
            if address != "127.0.0.1":
                for pid in pids:
                    if pid == "":
                        self.action_results.append({"tcp4_socket_port_" + port + "_kernel_module": False})
                        continue

                    for rpid in root_processes_pids:
                        if str(pid) == str(rpid):
                            self.action_results.append({"tcp4_pid_"+pid+"_listening_local": False})

        # Action 2: Check to see if any tcp6 sockets are held by privileged processes
        for socket in tcp6sockets.keys():
            pids = tcp6sockets[socket]

            last_colon = socket.rfind(":")
            address = socket[:last_colon].strip()
            port = socket[last_colon + 1:].strip()
            if address != "::1":
                for pid in pids:
                    if pid == "":
                        self.action_results.append({"tcp6_socket_port_" + port + "_kernel_module": False})
                        continue

                    for rpid in root_processes_pids:
                        if str(pid) == str(rpid):
                            self.action_results.append({"tcp6_pid_" + pid + "_listening_local": False})

        # Action 3: Check to see if any udp4 sockets are held by privileged processes
        for socket in udp4sockets.keys():
            pids = udp4sockets[socket]

            last_colon = socket.rfind(":")
            address = socket[:last_colon].strip()
            port = socket[last_colon + 1:].strip()
            if address != "127.0.0.1":
                for pid in pids:
                    if pid == "":
                        # There is a race condition here, UDP sockets are sometimes open temporarily
                        # self.action_results.append({"udp4_socket_port_" + port + "_kernel_module": False})
                        continue

                    for rpid in root_processes_pids:
                        if str(pid) == str(rpid):
                            self.action_results.append({"udp4_pid_" + pid + "_listening_local": False})

        # Action 4: Check to see if any udp6 sockets are held by privileged processes
        for socket in udp6sockets.keys():
            pids = udp6sockets[socket]

            last_colon = socket.rfind(":")
            address = socket[:last_colon].strip()
            port = socket[last_colon + 1:].strip()
            if address != "::1":
                for pid in pids:
                    if pid == "":
                        # There is a race condition here, UDP sockets are sometimes open temporarily
                        # self.action_results.append({"udp6_socket_port_" + port + "_kernel_module": False})
                        continue

                    for rpid in root_processes_pids:
                        if str(pid) == str(rpid):
                            self.action_results.append({"udp6_pid_" + pid + "_listening_local": False})
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
            self.logger.error("%s: Exceeded failure threshold [TEST FAILED]", self.name)
            self.action_results.append(dict(threshold_reached=True))
        return self.action_results

    def get_name(self):
        return self.name
