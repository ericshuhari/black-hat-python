import my_imports

# create class to inherit from PluginInterface
class CmdLine(interfaces.plugin.PluginInterface):
    @classmethod
    # define the requirements
    def get_requirements(cls):
        pass
    # define run method
    def run(self):
        pass
    # optionally define generator method
    def generator(self, procs):
        pass

