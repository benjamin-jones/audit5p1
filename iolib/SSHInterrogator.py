from paramiko import *

from iolib.Interrogator import Interrogator


class SSHInterrogator(Interrogator):

    def __init__(self):
        self.hostname = None
        self.port = None
        self.client = SSHClient()
        self.username = None
        self.password = None
        self.connected = False
        self.client.set_missing_host_key_policy(AutoAddPolicy())

    def connect(self, target, options=None):
        if not target:
            raise ConnectionError

        target = target.split(":")
        if len(target) != 2:
            raise ValueError

        self.hostname = target[0]
        self.port = int(target[1])
        return

    def login(self, username, password):
        if not username:
            raise UserWarning
        self.password = password
        self.client.load_system_host_keys()
        if self.client.connect(hostname=self.hostname, port=self.port, username=username, password=password):
            raise UserWarning
        self.connected = True
        return

    def run_command(self, command, options=None):
        if not self.connected:
            raise ConnectionError
        return self.client.exec_command(command)

    def run_command_as_root(self, command):
        if not self.connected:
            raise ConnectionError
        return self.client.exec_command("echo " + str(self.password) + " | sudo -S " + command)

    @staticmethod
    def read_stdout(stream_tuple):
        stdin, stdout, stderr = stream_tuple
        return stdout.read()

    @staticmethod
    def read_stderr(stream_tuple):
        stdin, stdout, stderr = stream_tuple
        return stderr.read()

    @staticmethod
    def get_line_ending():
        return "\n"

    def disconnect(self):
        if not self.connected:
            raise ConnectionError
        self.client.close()
        return

