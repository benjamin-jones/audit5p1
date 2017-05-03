import re

from commonlib.Common import *

PLUGIN_NAME = "NetworkProtection"
SHELL = SHELL_BASH
actions = [
    # Get all the listening IPV4 TCP Sockets that are listening
    ("listening_ipv4_tcp_sockets", "get_listening_ipv4_tcp_sockets"),
    # Get all the listening IPV6 TCP Sockets that are listening
    ("listening_ipv6_tcp_sockets", "get_listening_ipv6_tcp_sockets"),
    # Get all the listening IPV4 UDP Sockets that are listening
    ("listening_ipv4_udp_sockets", "get_listening_ipv4_udp_sockets"),
    # Get all the listening IPV6 UDP Sockets that are listening
    ("listening_ipv6_udp_sockets", "get_listening_ipv6_udp_sockets"),
    # Pull the iptables filter table rules
    ("iptables_filter_table", "get_filter_iptables"),
    # Pull the iptables filter table rules
    ("iptables_security_table", "get_security_iptables"),
]

required_binaries = []


def get_filter_iptables(interrogator):
    streamable = interrogator.run_command_as_root("iptables -L")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamable).decode("ascii").strip()

    chains = {}

    result = result.split("Chain")[1:]
    chains["INPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[0].split(line_ending)[2:] if len(a) > 2]
    chains["FORWARD"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[1].split(line_ending)[2:] if len(a) > 2]
    chains["OUTPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[2].split(line_ending)[2:] if len(a) > 2]

    return chains


def get_security_iptables(interrogator):
    streamable = interrogator.run_command_as_root("iptables -t security -L")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamable).decode("ascii").strip()
    errors = interrogator.read_stderr(streamable).decode("ascii").strip()

    if "does not exist" in errors:
        return False

    chains = {}

    result = result.split("Chain")[1:]
    chains["INPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[0].split(line_ending)[2:] if len(a) > 2]
    chains["FORWARD"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[1].split(line_ending)[2:] if len(a) > 2]
    chains["OUTPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[2].split(line_ending)[2:] if len(a) > 2]

    return chains


def get_listening_ipv4_tcp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep tcp | grep 0.0.0.0")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split(line_ending)
    if len(result) < 1:
        return {}
    result = [str(a).strip() for a in result if len(a) > 2]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[8:].split(" ")[0] for a in result]
    result = get_pids_for_nonlocal_sockets(interrogator, result,"tcp")
    return result


def get_listening_ipv4_udp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep udp | grep 0.0.0.0 ")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split(line_ending)
    if len(result) < 1:
        return {}
    result = [str(a).strip() for a in result if len(a) > 2]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[8:].split(" ")[0] for a in result]
    result = get_pids_for_nonlocal_sockets(interrogator, result,"udp")
    return result


def get_listening_ipv6_udp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep udp | grep ::: ")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split(line_ending)
    if len(result) < 1:
        return {}
    result = [str(a).strip() for a in result if len(a) > 2]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    if result[0][3] == "6":
        result = [a[9:].split(" ")[0] for a in result]
    else:
        result = [a[8:].split(" ")[0] for a in result]
    result = get_pids_for_nonlocal_sockets(interrogator, result,"udp")
    return result


def get_listening_ipv6_tcp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep tcp | grep ::: ")
    line_ending = interrogator.get_line_ending()
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split(line_ending)

    if len(result) < 1:
        return {}

    result = [str(a).strip() for a in result if len(a) > 2]
    result = [re.sub(r' {2,}', " ", a) for a in result]

    if result[0][3] == "6":
        result = [a[9:].split(" ")[0] for a in result]
    else:
        result = [a[8:].split(" ")[0] for a in result]
    result = get_pids_for_nonlocal_sockets(interrogator, result, "tcp")
    return result


def get_pids_for_nonlocal_sockets(interrogator, list_of_sockets, protocol):

    new_dict = {}
    if len(list_of_sockets) < 1:
        return new_dict
    for socket in list_of_sockets:
        last_colon = socket.rfind(":")
        port = socket[last_colon+1:]
        streamable = interrogator.run_command_as_root("fuser " + port + "/" + protocol)
        result = interrogator.read_stdout(streamable).decode("ascii").strip()
        result = re.sub(r' {2,}', " ", result).split(" ")

        result = [a for a in result if protocol not in a]
        if len(result) >= 1:
            new_dict[socket] = result
    return new_dict


def load(register_callback):
    for key, callback in actions:
        register_callback(key, callback, PLUGIN_NAME)
    return


def set_shell(c_shell):
    global SHELL
    global required_binaries
    SHELL = c_shell

    if SHELL == SHELL_BASH or SHELL == SHELL_BUSYBOX:
        required_binaries.append("netstat")
        required_binaries.append("grep")
        required_binaries.append("iptables")
        required_binaries.append("fuser")
    return required_binaries
