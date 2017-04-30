from common import *


def get_operating_system(interrogator):
    streamable = interrogator.run_command("uname")
    raw_result = interrogator.read_stdout(streamable)

    os = None
    if "Linux" in str(raw_result):
        os = OS_LINUX

    return os
