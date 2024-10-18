from bcc import BPF
import logging
import asyncio

class BPFManager:
    def __init__(self):
        self.bpf_programs = {}
        self.event_queues = {}
        self.logger = logging.getLogger(__name__)
        self.event_handlers = {
            'process_launch': self._handle_process_launch,
            'file_access': self._handle_file_access,
            'kernel_module_load': self._handle_kernel_module_load,
            'ebpf_program_load': self._handle_ebpf_program_load,
            'ld_preload': self._handle_ld_preload,
            'syscall': self._handle_syscall,
            'exec_from_mount': self._handle_exec_from_mount,
            'hardlink_creation': self._handle_hardlink_creation,
            'symlink_creation': self._handle_symlink_creation,
            'capability_use': self._handle_capability_use,
            'read_env_vars': self._handle_read_env_vars
        }

    async def load_program(self, name, source_file, func_name, event, event_type='kprobe'):
        if name in self.bpf_programs:
            return

        try:
            with open(source_file, "r") as f:
                bpf_code = f.read()

            b = BPF(text=bpf_code)

            if event_type == 'kprobe':
                b.attach_kprobe(event=event, fn_name=func_name)
            elif event_type == 'tracepoint':
                b.attach_tracepoint(tp=event, fn_name=func_name)
            else:
                raise ValueError(f"Unsupported event type: {event_type}")

            b["events"].open_perf_buffer(self._create_callback(name))
            self.bpf_programs[name] = b
            self.logger.info(f"Loaded and attached {name} to event {event}")
        except Exception as e:
            self.logger.error(f"Failed to load and attach {name}: {e}")

    async def load_all_programs(self):
        programs = [
            ('process_launch', 'ebpf_programs/process_launch.c', 'trace_process_launch', 'sched:sched_process_exec', 'tracepoint'),
            ('file_access', 'ebpf_programs/file_access.c', 'trace_file_open', 'do_sys_open'),
            ('kernel_module_load', 'ebpf_programs/kernel_module_load.c', 'trace_kernel_module_load', 'do_init_module'),
            ('ebpf_program_load', 'ebpf_programs/ebpf_program_load.c', 'trace_ebpf_program_load', 'bpf_prog_load'),
            ('ld_preload', 'ebpf_programs/ld_preload_hook.c', 'trace_ld_preload', '__x64_sys_execve'),
            ('syscall', 'ebpf_programs/syscall.c', 'trace_syscall', '__x64_sys_execve'),
            ('exec_from_mount', 'ebpf_programs/exec_from_mount.c', 'trace_exec_from_mount', '__x64_sys_execve'),
            ('hardlink_creation', 'ebpf_programs/hardlink_over_sensitive_file.c', 'trace_hardlink', 'vfs_link'),
            ('symlink_creation', 'ebpf_programs/symlink_over_sensitive_file.c', 'trace_symlink', 'vfs_symlink'),
            ('capability_use', 'ebpf_programs/capability_use.c', 'trace_capability_use', 'cap_capable'),
            ('read_env_vars', 'ebpf_programs/read_env_variables.c', 'trace_read_env_var', 'do_sys_open')
        ]
        await asyncio.gather(*[self.load_program(*prog) for prog in programs])

    def _create_callback(self, event_name):
        def callback(cpu, data, size):
            event = self.bpf_programs[event_name]["events"].event(data)
            detected_value = self.event_handlers[event_name](event)
            if detected_value:
                self.event_queues.setdefault(event_name, []).append(detected_value)
        return callback

    def _handle_process_launch(self, event):
        return {
            'event': 'process_launch',
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_file_access(self, event):
        return {
            'event': 'file_access',
            'filename': event.filename.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_kernel_module_load(self, event):
        return {
            'event': 'kernel_module_load',
            'module_name': event.module_name.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_ebpf_program_load(self, event):
        return {
            'event': 'ebpf_program_load',
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_ld_preload(self, event):
        return {
            'event': 'ld_preload',
            'lib_name': event.lib_name.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_syscall(self, event):
        return {
            'event': 'syscall',
            'syscall_nr': event.syscall_nr,
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_exec_from_mount(self, event):
        return {
            'event': 'exec_from_mount',
            'filename': event.filename.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_hardlink_creation(self, event):
        return {
            'event': 'hardlink_creation',
            'target': event.target.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_symlink_creation(self, event):
        return {
            'event': 'symlink_creation',
            'target': event.target.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_capability_use(self, event):
        return {
            'event': 'capability_use',
            'capability': event.cap,
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    def _handle_read_env_vars(self, event):
        return {
            'event': 'read_env_vars',
            'var': event.var.decode('utf-8', 'replace'),
            'comm': event.comm.decode('utf-8', 'replace'),
            'pid': event.pid,
            'uid': event.uid
        }

    async def monitor_events(self):
        while True:
            for bpf_prog in self.bpf_programs.values():
                bpf_prog.perf_buffer_poll(timeout=100)
            for event_name, queue in self.event_queues.items():
                while queue:
                    yield event_name, queue.pop(0)
            await asyncio.sleep(0.1)

    def unload_all(self):
        for name, bpf_prog in self.bpf_programs.items():
            bpf_prog.cleanup()
        self.logger.info("Unloaded all eBPF programs.")
