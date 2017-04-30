import abc


class Platform(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def check(self, id):
        return

    @abc.abstractmethod
    def validate(self, report):
        return

    @abc.abstractmethod
    def report(self):
        return
