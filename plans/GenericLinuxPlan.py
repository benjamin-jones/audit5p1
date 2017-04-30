import importlib
import json
import sys

from common import *
from plans.Plan import Plan


class GenericLinuxPlan(Plan):

    def __init__(self, interrogator, logger):
        self.config = {}
        self.interrogator = interrogator
        self.logger = logger
        self.tasks = []
        self.results = {}
        self.plugins = {}
        self.verified_binaries = []
        return

    def register(self, key, callback, plugin):
        self.tasks.append((key, callback, plugin))

    def have_which(self):
        streamable = self.interrogator.run_command("which which")
        result = self.interrogator.read_stderr(streamable)
        if len(result) > 1:
            return False
        return True

    def have_binary(self, binary):
        streamable = self.interrogator.run_command("which " + binary)
        result = self.interrogator.read_stdout(streamable)
        if len(result) > 1:
            return True
        return False

    def prereqs_met(self, required_binaries):
        return_value = True
        if not self.have_which():
            self.logger.warn("Which not found!")
            return_value = False
        for binary in required_binaries:
            if binary in self.verified_binaries:
                continue
            if not self.have_binary(binary):
                self.logger.warn("%s not found on target", binary)
                return_value = False
            else:
                self.verified_binaries.append(binary)
        return return_value

    def load(self, config):
        if config:
            self.config = json.loads(config)
        if "plan_plugins" in self.config.keys():
            for plugin in self.config["plan_plugins"]:
                i = importlib.import_module("plugins." + plugin)
                if "shell" in self.config.keys():
                    if self.config["shell"] not in SUPPORTED_SHELL:
                        raise ValueError
                    shell = SUPPORTED_SHELL[self.config["shell"]]
                    required_binaries = i.set_shell(shell)

                    if self.prereqs_met(required_binaries):
                        self.logger.info("Required binaries found on target")
                        i.load(self.register)
                        self.plugins[plugin] = i
                else:
                    raise ValueError
        return

    def run(self):
        for task in self.tasks:
            key, callback, plugin = task
            i = self.plugins[plugin]
            method_to_call = getattr(i, callback)
            self.logger.info("Running %s:%s", plugin, callback)
            self.results[key] = method_to_call(self.interrogator)
        return

    def report(self):
        self.logger.info("Generating JSON plan results")
        sys.stdout.flush()
        print(json.dumps(self.results, indent=4, sort_keys=True))
        sys.stdout.flush()
        return self.results
