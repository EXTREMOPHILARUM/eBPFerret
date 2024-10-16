import argparse
import time
import yaml
from collections import Counter
from bcc import BPF
import socket
import struct

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

    BPF_PERF_OUTPUT(events);

    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        u32 event_type;
        char filename[256];
        u16 dport;
        u32 daddr;
    };

    enum event_types {
        EVENT_EXECVE = 1,
        EVENT_OPEN,
        EVENT_CONNECT,
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
        bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            data.event_type = EVENT_CONNECT;
            data.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
            bpf_probe_read(&data.dport, sizeof(data.dport), &sk->__sk_common.skc_dport);
            events.perf_submit(ctx, &data, sizeof(data));
        }
        return 0;
    }
    """
    return BPF(text=bpf_text)

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack('!I', ip))

def learning_mode(b, duration, config_path):
    execve_events = []
    open_events = []
    connect_events = []
    start_time = time.time()

    def collect_event(cpu, data, size):
        event = b["events"].event(data)
        if event.event_type == 1:  # EVENT_EXECVE
            filename = event.filename.decode('utf-8', 'replace')
            execve_events.append(filename)
        elif event.event_type == 2:  # EVENT_OPEN
            filename = event.filename.decode('utf-8', 'replace')
            open_events.append(filename)
        elif event.event_type == 3:  # EVENT_CONNECT
            daddr = ip_to_str(event.daddr)
            dport = socket.ntohs(event.dport)
            connect_events.append(f"{daddr}:{dport}")

    b["events"].open_perf_buffer(collect_event)

    while time.time() - start_time < duration:
        b.perf_buffer_poll(timeout=100)

    # Generate allowlist
    allowlist = {"allowlist": {}}

    # Execve allowlist
    execve_counts = Counter(execve_events)
    execve_common = [fname for fname, count in execve_counts.items() if count > 1]
    allowlist["allowlist"]["execve"] = {"paths": execve_common}

    # Open allowlist
    open_counts = Counter(open_events)
    open_common = [fname for fname, count in open_counts.items() if count > 1]
    allowlist["allowlist"]["open"] = {"paths": open_common}

    # Connect allowlist
    connect_counts = Counter(connect_events)
    connect_common = [dest for dest, count in connect_counts.items() if count > 1]
    allowlist["allowlist"]["connect"] = {"destinations": connect_common}

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

    def enforce_policy(cpu, data, size):
        event = b["events"].event(data)
        if event.event_type == 1:  # EVENT_EXECVE
            filename = event.filename.decode('utf-8', 'replace')
            if filename not in execve_allowed:
                print(f"ALERT: Unauthorized execve call detected: {filename}")
                # Implement blocking or alerting mechanisms here
        elif event.event_type == 2:  # EVENT_OPEN
            filename = event.filename.decode('utf-8', 'replace')
            if filename not in open_allowed:
                print(f"ALERT: Unauthorized file open detected: {filename}")
                # Implement blocking or alerting mechanisms here
        elif event.event_type == 3:  # EVENT_CONNECT
            daddr = ip_to_str(event.daddr)
            dport = socket.ntohs(event.dport)
            dest = f"{daddr}:{dport}"
            if dest not in connect_allowed:
                print(f"ALERT: Unauthorized network connection detected: {dest}")
                # Implement blocking or alerting mechanisms here

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
