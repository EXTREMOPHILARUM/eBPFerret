import logging
import os

class RuleEngine:
    def __init__(self, config):
        self.config = config if config else {'rules': {}}
        if 'rules' not in self.config:
            self.config['rules'] = {}
        self.logger = logging.getLogger(__name__)

        # Create a syscall number-to-name mapping
        self.syscall_table = self._load_syscall_table()

    def _load_syscall_table(self):
        """
        Loads a syscall number-to-name mapping from a local file.
        This can be based on the syscall table for the system's architecture.
        """
        # Mapping of some syscalls, extend as necessary for your system
        return {
            0: "read", 1: "write", 2: "open", 3: "close", 59: "execve", 90: "mmap",
            # Add more syscalls as needed
        }

    def _syscall_number_to_name(self, syscall_nr):
        """
        Converts syscall number to its name using the syscall table.
        If the syscall number is not found, return the number as a string.
        """
        return self.syscall_table.get(syscall_nr, f"syscall_{syscall_nr}")

    def add_allowed_value(self, event, detected_value):
        uid = detected_value['uid']
        if uid not in self.config['rules']:
            self.config['rules'][uid] = {}

        key = self._get_key_for_event(event)
        value = self._get_value_for_event(event, detected_value)

        if key and value:
            if key not in self.config['rules'][uid]:
                self.config['rules'][uid][key] = []

            if value not in self.config['rules'][uid][key]:
                self.config['rules'][uid][key].append(value)
                self.logger.debug(f"Added allowed value: {value} for event: {event}, uid: {uid}")

    def is_value_allowed(self, event, detected_value):
        uid = detected_value['uid']
        if uid not in self.config['rules']:
            self.logger.warning(f"No rules exist for UID: {uid} and event: {event}")
            return False

        key = self._get_key_for_event(event)
        value = self._get_value_for_event(event, detected_value)

        if key and value and key in self.config['rules'][uid]:
            if value in self.config['rules'][uid][key]:
                self.logger.debug(f"Value {value} is allowed for event: {event}, uid: {uid}")
                return True

        self.logger.warning(f"Value {value} is NOT allowed for event: {event}, uid: {uid}")
        return False

    def _get_key_for_event(self, event):
        # This method maps events to their corresponding keys in the config
        return event  # In this case, the event name is the same as the key

    def _get_value_for_event(self, event, detected_value):
        # This method extracts the relevant value from the detected_value dictionary based on the event type
        if event == 'process_launch':
            return detected_value.get('comm')
        elif event == 'ld_preload':
            return detected_value.get('lib_name')
        elif event == 'ebpf_program_load':
            return detected_value.get('comm')
        elif event == 'file_access' or event == 'exec_from_mount':
            return detected_value.get('filename')
        elif event == 'capability_use':
            return detected_value.get('cap_name', str(detected_value.get('cap')))
        elif event == 'kernel_module_load':
            return detected_value.get('module_name')
        elif event == 'symlink_creation' or event == 'hardlink_creation':
            return detected_value.get('target')
        elif event == 'domain_request':
            return detected_value.get('saddr')
        elif event == 'read_env_vars':
            return detected_value.get('var')
        elif event == 'syscall':
            return self._syscall_number_to_name(detected_value.get('syscall_nr'))
        else:
            return None
