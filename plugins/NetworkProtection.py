import re

PLUGIN_NAME = "NetworkProtection"
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


def get_filter_iptables(interrogator):
    streamable = interrogator.run_command_as_root("iptables -L")
    result = interrogator.read_stdout(streamable).decode("ascii").strip()

    chains = {}

    result = result.split("Chain")[1:]
    chains["INPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[0].split("\n")[2:] if len(a) > 2]
    chains["FORWARD"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[1].split("\n")[2:] if len(a) > 2]
    chains["OUTPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[2].split("\n")[2:] if len(a) > 2]

    return chains


def get_security_iptables(interrogator):
    streamable = interrogator.run_command_as_root("iptables -t security -L")
    result = interrogator.read_stdout(streamable).decode("ascii").strip()

    chains = {}

    result = result.split("Chain")[1:]
    chains["INPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[0].split("\n")[2:] if len(a) > 2]
    chains["FORWARD"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[1].split("\n")[2:] if len(a) > 2]
    chains["OUTPUT"] = [re.sub(r' {2,}', " ", a.strip()) for a in result[2].split("\n")[2:] if len(a) > 2]

    return chains


def get_listening_ipv4_tcp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep LISTEN\ | grep tcp\ ")
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split("\n")
    result = [str(a).strip() for a in result]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[8:].split(" ")[0] for a in result]
    return result


def get_listening_ipv4_udp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep udp\ ")
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split("\n")
    result = [str(a).strip() for a in result]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[8:].split(" ")[0] for a in result]
    return result


def get_listening_ipv6_udp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep udp6\ ")
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split("\n")
    result = [str(a).strip() for a in result]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[9:].split(" ")[0] for a in result]
    return result


def get_listening_ipv6_tcp_sockets(interrogator):
    streamble = interrogator.run_command("netstat -ln | grep LISTEN\ | grep tcp6\ ")
    result = interrogator.read_stdout(streamble).decode("ascii").strip().split("\n")
    result = [str(a).strip() for a in result]
    result = [re.sub(r' {2,}', " ", a) for a in result]
    result = [a[9:].split(" ")[0] for a in result]
    return result


def load(register_callback):
    for key, callback in actions:
        register_callback(key, callback, PLUGIN_NAME)
    return
