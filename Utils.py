import json
import importlib

from Common import *


def get_operating_system(interrogator):
    streamable = interrogator.run_command("uname")
    raw_result = interrogator.read_stdout(streamable)

    os = None
    if "Linux" in str(raw_result):
        os = OS_LINUX

    return os


def get_platform_module(config):
    config = json.loads(config)

    if "platform" in config.keys():
        i = importlib.import_module("platforms." + config["platform"])
        method = getattr(i, config["platform"])

        return method
    return None

def get_plan_module(config):

    config = json.loads(config)

    if "plan" in config.keys():
        i = importlib.import_module("plans." + config["plan"])
        method = getattr(i, config["plan"])

        return method
    return None