import serial
import json

from iolib.Interrogator import Interrogator


class SerialInterrogator(Interrogator):

    def __init__(self, config, logger):
        self.serial = serial.Serial()
        self.logger = logger
        self.username = None
        self.password = None
        config = json.loads(config)
        if "serial_baudrate" in config.keys():
            self.baudrate = int(config["serial_baudrate"])
        else:
            self.baudrate = 115200
        return

    def connect(self, target, options=None):
        if not target:
            raise ConnectionError
        try:
            self.serial = serial.Serial(target, self.baudrate, timeout=10)
        except:
            raise ConnectionError
        return

    def login(self, username, password):
        self.logger.info("Attempting serial login")
        if not username or not self.serial:
            raise UserWarning
        self.serial.write(b'\r\n')
        self.serial.read_until(b"login: ")
        self.serial.write(bytes(username, 'utf-8')+b'\r\n')
        self.serial.read_until(b"Password:")
        self.serial.write(bytes(password, 'utf-8')+b'\r\n')
        if username != "root":
            output = self.serial.read_until(b"$ ")
        else:
            output = self.serial.read_until(b"# ")
        if b'$ ' not in output and b'# ' not in output:
            raise UserWarning
        self.logger.info("Serial login successful")
        self.username = username
        self.password = password
        return

    def run_command(self, command, options=None):
        if not self.serial:
            raise ConnectionError
        if not command:
            raise ValueError
        self.serial.write(bytes(command, 'utf-8')+b'\r\n')
        self.serial.read_until(bytes(command, "utf-8")+b'\r\n').decode("ascii")
        if self.username != "root":
            command_output = self.serial.read_until(b"$ ").decode("ascii")
        else:
            command_output = self.serial.read_until(b"# ").decode("ascii")
        command_output = command_output[:command_output.rfind("\r\n")]

        return bytes(command_output, "utf-8")

    def run_command_as_root(self, command):
        if self.username == "root":
            return self.run_command(command)
        else:
            return self.run_command("echo " + str(self.password) + " | sudo -S " + command)

    @staticmethod
    def read_stdout(streamable):
        return streamable

    @staticmethod
    def read_stderr(streamable):
        return bytes("", "utf-8") # can't determine stderr on serial mode

    @staticmethod
    def get_line_ending():
        return "\r\n"

    def disconnect(self):
        self.serial.write(b"exit\r\n")
        return

