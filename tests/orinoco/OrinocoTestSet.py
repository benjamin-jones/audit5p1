import importlib

from tests.TestSet import TestSet

TEST_SET = [
    "SanityTest",
    "OpenServicesTest"
]


class OrinocoTestSet(TestSet):

    def __init__(self, logger):
        self.tests =[]
        self.logger = logger
        for i in TEST_SET:
            self.add_test(i)
        return

    def add_test(self, test):
        i = importlib.import_module("tests.orinoco." + test)
        test_object = getattr(i, test)(self.logger)
        self.tests.append(test_object)
        return

    def __iter__(self):
        for i in self.tests:
            yield i
