import abc


class Plan(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def load(self, config):
        return

    @abc.abstractmethod
    def run(self):
        return

    @abc.abstractmethod
    def report(self):
        return
