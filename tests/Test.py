import abc


class Test(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def preconditions(self, report):
        return True

    @abc.abstractmethod
    def actions(self):
        return

    @abc.abstractmethod
    def postconditions(self):
        return True

    @abc.abstractmethod
    def get_name(self):
        return None
