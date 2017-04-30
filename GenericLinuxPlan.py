from Plan import Plan
import json
import importlib


class GenericLinuxPlan(Plan):

    def __init__(self, interrogator, logger):
        self.config = {}
        self.interrogator = interrogator
        self.logger = logger
        self.tasks = []
        self.results = {}
        self.plugins = {}
        return

    def register(self, key, callback, plugin):
        self.tasks.append((key, callback, plugin))

    def load(self, config):
        if config:
            self.config = json.loads(config)
        if "plan_plugins" in self.config.keys():
            for plugin in self.config["plan_plugins"]:
                i = importlib.import_module("plugins." + plugin)
                i.load(self.register)
                self.plugins[plugin] = i
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
        self.logger.info("Generating JSON report")
        print(json.dumps(self.results, indent=4, sort_keys=True))
        return
