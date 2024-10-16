import argparse
import time
import yaml
import json
from collections import Counter
from bcc import BPF

def parse_arguments():
    parser = argparse.ArgumentParser(description="eBPF-based Threat Detection Engine")
    parser.add_argument("--mode", choices=["learning", "enforcement"], required=True, help="Mode of operation")
    parser.add_argument("--config", required=True, help="Path to the YAML config file")
    parser.add_argument("--duration", type=int, default=60, help="Learning duration in seconds")
    return parser.parse_args()

def load_ebpf_program():
    bpf_text = """
    BPF_PERF_OUTPUT(events);

    struct data_t {
        u32 pid;
        char comm[16];
        char filename[256];
    };

    TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
        struct data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    """
    return BPF(text=bpf_text)

def learning_mode(b, duration, config_path):
    events = []
    start_time = time.time()

    def collect_event(cpu, data, size):
        event = b["events"].event(data)
        filename = event.filename.decode('utf-8', 'replace')
        events.append(filename)

    b["events"].open_perf_buffer(collect_event)

    while time.time() - start_time < duration:
        b.perf_buffer_poll(timeout=100)

    # Generate allowlist
    filename_counts = Counter(events)
    common_filenames = [fname for fname, count in filename_counts.items() if count > 1]

    allowlist = {
        "allowlist": {
            "execve": {
                "paths": common_filenames
            }
        }
    }

    # Save allowlist to YAML
    with open(config_path, "w") as f:
        yaml.dump(allowlist, f)

    print(f"Learning completed. Allowlist saved to {config_path}")

def enforcement_mode(b, config_path):
    # Load allowlist
    with open(config_path, "r") as f:
        allowlist = yaml.safe_load(f)

    allowed_paths = set(allowlist["allowlist"]["execve"]["paths"])

    def enforce_policy(cpu, data, size):
        event = b["events"].event(data)
        filename = event.filename.decode('utf-8', 'replace')
        if filename not in allowed_paths:
            print(f"ALERT: Unauthorized execve call detected: {filename}")
            # Implement blocking or alerting mechanisms here

    b["events"].open_perf_buffer(enforce_policy)

    print("Enforcement mode active. Monitoring for unauthorized execve calls.")

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
