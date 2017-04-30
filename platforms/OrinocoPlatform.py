from tests.orinoco.OrinocoTestSet import OrinocoTestSet
from platforms.Platform import Platform
from common import *

import json


class OrinocoPlatform(Platform):
    expected_os = OS_LINUX

    def __init__(self, logger):
        self.logger = logger
        self.verified = False
        self.tests = {}
        return

    def check(self, os_id):
        if os_id == self.expected_os:
            self.verified = True
            return True
        return False

    def validate(self, report):
        self.logger.info("Begin validation of ORINOCO")
        test_set = OrinocoTestSet(self.logger)

        for test in test_set:
            name = test.get_name()
            self.tests[name] = {}

            if test.preconditions(report):
                self.tests[name]["preconditions"] = True
            else:
                self.tests[name]["preconditions"] = False
                continue

            test.actions()

            self.tests[name]["postconditions"] = test.postconditions()
        return

    def report(self):
        self.logger.info("Reporting validation results")
        print(json.dumps(self.tests, indent=4, sort_keys=True))
        return

