import abc


class Interrogator(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def connect(self, target, options):
        """Connect to the target with the given options"""
        return

    @abc.abstractmethod
    def login(self, username, password):
        """Login to the system with the provided credentials"""
        return

    @abc.abstractmethod
    def run_command(self, command, options):
        """Run the given command on the target with the given options"""
        return

    @abc.abstractmethod
    def disconnect(self):
        """ Disconnect from the target"""
        return
