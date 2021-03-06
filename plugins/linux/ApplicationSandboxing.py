import re

from commonlib.Common import *

SHELL = SHELL_BASH

PLUGIN_NAME = "ApplicationSandboxing"
actions = [
    # Get all the processes running as root
    ("root_processes", "get_root_processes"),
    ("mounts", "get_mounts")
]

required_binaries = []

def load(register_callback):
    for key, callback in actions:
        register_callback(key, callback, PLUGIN_NAME)
    return


def set_shell(c_shell):
    global SHELL
    global required_binaries

    SHELL = c_shell

    if SHELL == SHELL_BASH or SHELL == SHELL_BUSYBOX:
        required_binaries.append("ps")
        required_binaries.append("grep")
        required_binaries.append("mount")
    return required_binaries


def get_ps_fields(interrogator):

    streamable = interrogator.run_command_as_root("ps aux | grep USER")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamable).decode("ascii").strip().split(line_ending)

    result = " ".join([re.sub(r' {2,}', " ", a) for a in result if "grep" not in a])
    result = result.split(" ")

    pid_idx = result.index("PID")
    command_idx = result.index("COMMAND")

    return pid_idx, command_idx

def get_root_processes(interrogator):
    global SHELL
    pid_idx, command_idx = get_ps_fields(interrogator)
    streamable = interrogator.run_command_as_root("ps aux | grep root")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamable).decode("ascii").strip().split(line_ending)
    result = [str(a).strip() for a in result if len(a) > 2 and "[" not in a and "grep" not in a]

    if SHELL == SHELL_BASH:
        result = [{int(re.sub(r' {2,}', " ", a).split(" ")[pid_idx]): " ".join(re.sub(r' {2,}', " ", a).split(" ")[10:])}
                  for a in result]

    elif SHELL == SHELL_BUSYBOX:
        result = [{int(re.sub(r' {2,}', " ", a).split(" ")[pid_idx]):" ".join(re.sub(r' {2,}', " ", a).split(" ")[3:])}
                  for a in result]
    result_dict = {}

    for process in result:
        for key in process.keys():
            result_dict[key] = process[key]
    return result_dict


def get_mounts(interrogator):
    streamable = interrogator.run_command_as_root("mount")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamable).decode("ascii").strip().split(line_ending)
    return result


