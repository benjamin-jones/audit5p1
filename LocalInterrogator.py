from Interrogator import Interrogator


class LocalInterrogator(Interrogator):

    def connect(self, target, options):
        if not target:
            raise ConnectionError
        return

    def login(self, username, password):
        if not username:
            raise UserWarning
        return

    def run_command(self, command, options):
        return

    def disconnect(self):
        return

