import yaml
import os
from contextlib import contextmanager

class ConfigManager:
    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self.config = self.load_config()

    def recreate_config(self):
        """
        Recreates the config file by overwriting it with an empty structure.
        """
        config_structure = {
            'rules': {}  # Start with an empty rules section
        }
        self.config = config_structure
        self.save_config()

    def load_config(self):
        """
        Loads the configuration from the file.
        """
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as file:
                return yaml.safe_load(file)
        else:
            return {'rules': {}}  # Return default empty structure if config doesn't exist

    def save_config(self, new_config=None):
        """
        Saves the current config or a new config to the config file.
        """
        if new_config is not None:
            self.config = new_config
        with open(self.config_file, 'w') as file:
            yaml.dump(self.config, file)

@contextmanager
def config_manager_context(config_file='config.yaml'):
    config_manager = ConfigManager(config_file)
    try:
        yield config_manager
    finally:
        config_manager.save_config()
