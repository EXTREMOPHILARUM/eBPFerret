import argparse
import time
import yaml
from collections import Counter, defaultdict
from bcc import BPF
import socket
import struct
import ctypes as ct

# Define constants for event types
EVENT_EXECVE = 1
EVENT_OPEN = 2
EVENT_CONNECT = 3
EVENT_SYSCALL = 4
EVENT_CAPABILITY = 5
EVENT_KERNEL_MODULE_LOAD = 6

def parse_arguments():
    parser = argparse.ArgumentParser(description="eBPF-based Threat Detection Engine")
    parser.add_argument("--mode", choices=["learning", "enforcement"], required=True, help="Mode of operation")
    parser.add_argument("--config", required=True, help="Path to the YAML config file")
    parser.add_argument("--duration", type=int, default=60, help="Learning duration in seconds")
    return parser.parse_args()

def load_ebpf_program():
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <linux/fs.h>
    #include <linux/sched.h>
    #include <linux/blkdev.h>

    BPF_PERF_OUTPUT(events);

    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        u32 event_type;
        union {
            char filename[128];  // Used for EVENT_EXECVE, EVENT_OPEN
            struct {
                u16 dport;
                u32 daddr;
            };
            u64 syscall;         // Used for EVENT_SYSCALL
            int capability;      // Used for EVENT_CAPABILITY
            char module[128];    // Used for EVENT_KERNEL_MODULE_LOAD
            // Add other event-specific fields as needed
        };
    };

    enum event_types {
        EVENT_EXECVE = 1,
        EVENT_OPEN,
        EVENT_CONNECT,
        EVENT_SYSCALL,
        EVENT_CAPABILITY,
        EVENT_KERNEL_MODULE_LOAD,
        // Add other event types as needed
    };

    // Trace execve syscalls
    TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
        struct data_t data = {};
        data.event_type = EVENT_EXECVE;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    // Trace file open syscalls
    TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
        struct data_t data = {};
        data.event_type = EVENT_OPEN;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    // Trace network connect syscalls
    int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
        struct data_t data = {};
        u16 family = 0;
        data.event_type = EVENT_CONNECT;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &sk->__sk_common.skc_dport);
            events.perf_submit(ctx, &data, sizeof(data));
        }
        return 0;
    }

    // Trace syscalls
    TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
        struct data_t data = {};
        data.event_type = EVENT_SYSCALL;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.syscall = args->id;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    // Trace capability checks
    int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *ns, int cap, int audit) {
        struct data_t data = {};
        data.event_type = EVENT_CAPABILITY;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.capability = cap;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }

    // Trace kernel module loads
    int kprobe__security_kernel_module_request(struct pt_regs *ctx, char *kmod_name) {
        struct data_t data = {};
        data.event_type = EVENT_KERNEL_MODULE_LOAD;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_probe_read_kernel_str(&data.module, sizeof(data.module), kmod_name);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }

    // Additional probes would be added here, following the same pattern.

    """
    return BPF(text=bpf_text)

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack('!I', ip))

# Define the ctypes structure matching data_t
class Data(ct.Structure):
    _fields_ = [
        ('pid', ct.c_uint32),
        ('comm', ct.c_char * 16),
        ('event_type', ct.c_uint32),
        ('data', ct.c_byte * 128),  # Maximum size of the union fields
    ]

def learning_mode(b, duration, config_path):
    events = defaultdict(list)
    start_time = time.time()

    def collect_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        if event.event_type == EVENT_EXECVE:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            events['execve'].append(filename)
        elif event.event_type == EVENT_OPEN:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            events['open'].append(filename)
        elif event.event_type == EVENT_CONNECT:
            dport = ct.cast(event.data, ct.POINTER(ct.c_uint16)).contents.value
            daddr = ct.cast(ct.byref(event.data, 2), ct.POINTER(ct.c_uint32)).contents.value
            daddr_str = ip_to_str(daddr)
            dport = socket.ntohs(dport)
            dest = f"{daddr_str}:{dport}"
            events['connect'].append(dest)
        elif event.event_type == EVENT_SYSCALL:
            syscall = ct.cast(event.data, ct.POINTER(ct.c_uint64)).contents.value
            events['syscall'].append(syscall)
        elif event.event_type == EVENT_CAPABILITY:
            capability = ct.cast(event.data, ct.POINTER(ct.c_int)).contents.value
            events['capability'].append(capability)
        elif event.event_type == EVENT_KERNEL_MODULE_LOAD:
            module = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            events['kernel_module_load'].append(module)
        # Handle other event types as needed

    b["events"].open_perf_buffer(collect_event)

    while time.time() - start_time < duration:
        b.perf_buffer_poll(timeout=100)

    # Generate allowlist
    allowlist = {"allowlist": {}}

    # Execve allowlist
    execve_counts = Counter(events['execve'])
    execve_common = [fname for fname, count in execve_counts.items() if count > 1]
    allowlist["allowlist"]["execve"] = {"paths": execve_common}

    # Open allowlist
    open_counts = Counter(events['open'])
    open_common = [fname for fname, count in open_counts.items() if count > 1]
    allowlist["allowlist"]["open"] = {"paths": open_common}

    # Connect allowlist
    connect_counts = Counter(events['connect'])
    connect_common = [dest for dest, count in connect_counts.items() if count > 1]
    allowlist["allowlist"]["connect"] = {"destinations": connect_common}

    # Syscall allowlist
    syscall_counts = Counter(events['syscall'])
    syscall_common = [syscall for syscall, count in syscall_counts.items() if count > 1]
    allowlist["allowlist"]["syscalls"] = syscall_common

    # Capability allowlist
    capability_counts = Counter(events['capability'])
    capability_common = [capability for capability, count in capability_counts.items() if count > 1]
    allowlist["allowlist"]["capabilities"] = capability_common

    # Kernel module load allowlist
    kernel_module_load_counts = Counter(events['kernel_module_load'])
    kernel_module_load_common = [module for module, count in kernel_module_load_counts.items() if count > 1]
    allowlist["allowlist"]["kernel_modules"] = kernel_module_load_common

    # Save allowlist to YAML
    with open(config_path, "w") as f:
        yaml.dump(allowlist, f)

    print(f"Learning completed. Allowlist saved to {config_path}")

def enforcement_mode(b, config_path):
    # Load allowlist
    with open(config_path, "r") as f:
        allowlist = yaml.safe_load(f)

    execve_allowed = set(allowlist["allowlist"].get("execve", {}).get("paths", []))
    open_allowed = set(allowlist["allowlist"].get("open", {}).get("paths", []))
    connect_allowed = set(allowlist["allowlist"].get("connect", {}).get("destinations", []))
    allowed_syscalls = set(allowlist["allowlist"].get("syscalls", []))
    allowed_capabilities = set(allowlist["allowlist"].get("capabilities", []))
    allowed_kernel_modules = set(allowlist["allowlist"].get("kernel_modules", []))

    def enforce_policy(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        if event.event_type == EVENT_EXECVE:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            if filename not in execve_allowed:
                print(f"ALERT: Unexpected process launched: {filename}")
        elif event.event_type == EVENT_OPEN:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            if filename not in open_allowed:
                print(f"ALERT: Unexpected file access: {filename}")
        elif event.event_type == EVENT_CONNECT:
            dport = ct.cast(event.data, ct.POINTER(ct.c_uint16)).contents.value
            daddr = ct.cast(ct.byref(event.data, 2), ct.POINTER(ct.c_uint32)).contents.value
            daddr_str = ip_to_str(daddr)
            dport = socket.ntohs(dport)
            dest = f"{daddr_str}:{dport}"
            if dest not in connect_allowed:
                print(f"ALERT: Unexpected network connection: {dest}")
        elif event.event_type == EVENT_SYSCALL:
            syscall = ct.cast(event.data, ct.POINTER(ct.c_uint64)).contents.value
            if syscall not in allowed_syscalls:
                print(f"ALERT: Unexpected system call: {syscall}")
        elif event.event_type == EVENT_CAPABILITY:
            capability = ct.cast(event.data, ct.POINTER(ct.c_int)).contents.value
            if capability not in allowed_capabilities:
                print(f"ALERT: Unexpected capability used: {capability}")
        elif event.event_type == EVENT_KERNEL_MODULE_LOAD:
            module = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            if module not in allowed_kernel_modules:
                print(f"ALERT: Unauthorized kernel module load: {module}")
        # Handle other event types as needed

    b["events"].open_perf_buffer(enforce_policy)

    print("Enforcement mode active. Monitoring for unauthorized events.")

    while True:
        b.perf_buffer_poll(timeout=100)

def main():
    args = parse_arguments()
    b = load_ebpf_program()

    if args.mode == "learning":
        learning_mode(b, args.duration, args.config)
    elif args.mode == "enforcement":
        enforcement_mode(b, args.config)

if __name__ == "__main__":
    main()
