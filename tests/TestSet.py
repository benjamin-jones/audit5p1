import abc


class TestSet(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def add_test(self):
        return True

    @abc.abstractmethod
    def __iter__(self):
        yield None

