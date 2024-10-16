import argparse
import time
import yaml
from collections import Counter, defaultdict
from bcc import BPF
import socket
import struct
import ctypes as ct
import os

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
    with open("ebpf_program.c", "r") as f:
        bpf_text = f.read()
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
        ('flags', ct.c_int),
    ]

def capability_name(cap):
    cap_names = {
        0: 'CAP_CHOWN',
        1: 'CAP_DAC_OVERRIDE',
        2: 'CAP_DAC_READ_SEARCH',
        3: 'CAP_FOWNER',
        4: 'CAP_FSETID',
        5: 'CAP_KILL',
        6: 'CAP_SETGID',
        7: 'CAP_SETUID',
        8: 'CAP_SETPCAP',
        9: 'CAP_LINUX_IMMUTABLE',
        10: 'CAP_NET_BIND_SERVICE',
        11: 'CAP_NET_BROADCAST',
        12: 'CAP_NET_ADMIN',
        13: 'CAP_NET_RAW',
        14: 'CAP_IPC_LOCK',
        15: 'CAP_IPC_OWNER',
        16: 'CAP_SYS_MODULE',
        17: 'CAP_SYS_RAWIO',
        18: 'CAP_SYS_CHROOT',
        19: 'CAP_SYS_PTRACE',
        20: 'CAP_SYS_PACCT',
        21: 'CAP_SYS_ADMIN',
        22: 'CAP_SYS_BOOT',
        23: 'CAP_SYS_NICE',
        24: 'CAP_SYS_RESOURCE',
        25: 'CAP_SYS_TIME',
        26: 'CAP_SYS_TTY_CONFIG',
        27: 'CAP_MKNOD',
        28: 'CAP_LEASE',
        29: 'CAP_AUDIT_WRITE',
        30: 'CAP_AUDIT_CONTROL',
        31: 'CAP_SETFCAP',
        32: 'CAP_MAC_OVERRIDE',
        33: 'CAP_MAC_ADMIN',
        34: 'CAP_SYSLOG',
        35: 'CAP_WAKE_ALARM',
        36: 'CAP_BLOCK_SUSPEND',
        37: 'CAP_AUDIT_READ',
    }
    return cap_names.get(cap, f'UNKNOWN({cap})')

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
            flags = event.flags
            events['open'].append((filename, flags))
        elif event.event_type == EVENT_CONNECT:
            dport = ct.cast(event.data, ct.POINTER(ct.c_uint16)).contents.value
            daddr = ct.cast(ct.byref(event.data, 2), ct.POINTER(ct.c_uint32)).contents.value
            daddr_str = ip_to_str(daddr)
            dport = socket.ntohs(dport)
            dest = {'ip': daddr_str, 'port': dport}
            events['connect'].append(dest)
        elif event.event_type == EVENT_CAPABILITY:
            capability = ct.cast(event.data, ct.POINTER(ct.c_int)).contents.value
            events['capability'].append(capability)
        elif event.event_type == EVENT_KERNEL_MODULE_LOAD:
            module = bytes(event.data[:56]).rstrip(b'\x00').decode('utf-8', 'replace')
            events['kernel_module_load'].append(module)
        # Handle other event types as needed

    b["events"].open_perf_buffer(collect_event)

    while time.time() - start_time < duration:
        b.perf_buffer_poll(timeout=100)

    # Generate allowlist
    allowlist = {"allowlist": {}}

    # Syscalls allowlist
    syscalls = []
    execve_counts = Counter(events['execve'])
    execve_common = [fname for fname, count in execve_counts.items() if count > 1]
    if execve_common:
        syscalls.append({
            'name': 'execve',
            'paths': execve_common
        })

    # Filesystem allowlist
    filesystem = {'read': set(), 'write': set()}
    open_counts = Counter(events['open'])
    for (fname, flags), count in open_counts.items():
        if count > 1:
            # Determine if it's a read or write based on flags
            if flags & os.O_WRONLY or flags & os.O_RDWR:
                filesystem['write'].add(fname)
            else:
                filesystem['read'].add(fname)

    # Convert sets to lists
    filesystem['read'] = list(filesystem['read'])
    filesystem['write'] = list(filesystem['write'])

    # Network allowlist
    network = {'outbound': [], 'inbound': []}
    # For outbound connections
    connect_counts = Counter([ (dest['ip'], dest['port']) for dest in events['connect'] ])
    outbound_dict = {}
    for (ip, port), count in connect_counts.items():
        if count > 1:
            if ip not in outbound_dict:
                outbound_dict[ip] = set()
            outbound_dict[ip].add(port)
    for ip, ports in outbound_dict.items():
        network['outbound'].append({
            'destination_ip': ip,
            'ports': list(ports)
        })

    # Capabilities allowlist
    capability_counts = Counter(events['capability'])
    capabilities_common = [cap for cap, count in capability_counts.items() if count > 1]
    capabilities_names = [capability_name(cap) for cap in capabilities_common]
    allowlist['allowlist']['capabilities'] = capabilities_names

    # Kernel modules allowlist
    module_counts = Counter(events['kernel_module_load'])
    modules_common = [module for module, count in module_counts.items() if count > 1]
    allowlist['allowlist']['kernel_modules'] = modules_common

    # Assemble the allowlist
    allowlist['allowlist']['syscalls'] = syscalls
    allowlist['allowlist']['filesystem'] = filesystem
    allowlist['allowlist']['network'] = network

    # Save allowlist to YAML
    with open(config_path, "w") as f:
        yaml.dump(allowlist, f)

    print(f"Learning completed. Allowlist saved to {config_path}")

def enforcement_mode(b, config_path):
    # Load allowlist
    with open(config_path, "r") as f:
        allowlist = yaml.safe_load(f)

    # Extract allowed syscalls
    allowed_syscalls = {}
    for syscall in allowlist['allowlist'].get('syscalls', []):
        name = syscall['name']
        paths = set(syscall.get('paths', []))
        allowed_syscalls[name] = paths

    # Extract allowed filesystem accesses
    fs_read_allowed = set(allowlist['allowlist'].get('filesystem', {}).get('read', []))
    fs_write_allowed = set(allowlist['allowlist'].get('filesystem', {}).get('write', []))

    # Extract allowed network connections
    outbound_allowed = []
    for entry in allowlist['allowlist'].get('network', {}).get('outbound', []):
        ip = entry.get('destination_ip')
        ports = set(entry.get('ports', []))
        outbound_allowed.append({'ip': ip, 'ports': ports})

    # Extract allowed capabilities
    allowed_capabilities = set(allowlist['allowlist'].get('capabilities', []))

    # Extract allowed kernel modules
    allowed_kernel_modules = set(allowlist['allowlist'].get('kernel_modules', []))

    # Define enforcement functions
    def enforce_policy(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        if event.event_type == EVENT_EXECVE:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            allowed_paths = allowed_syscalls.get('execve', set())
            if filename not in allowed_paths:
                print(f"ALERT: Unauthorized execve call detected: {filename}")
        elif event.event_type == EVENT_OPEN:
            filename = bytes(event.data[:128]).rstrip(b'\x00').decode('utf-8', 'replace')
            flags = event.flags
            if flags & os.O_WRONLY or flags & os.O_RDWR:
                if filename not in fs_write_allowed:
                    print(f"ALERT: Unauthorized write access detected: {filename}")
            else:
                if filename not in fs_read_allowed:
                    print(f"ALERT: Unauthorized read access detected: {filename}")
        elif event.event_type == EVENT_CONNECT:
            dport = ct.cast(event.data, ct.POINTER(ct.c_uint16)).contents.value
            daddr = ct.cast(ct.byref(event.data, 2), ct.POINTER(ct.c_uint32)).contents.value
            daddr_str = ip_to_str(daddr)
            dport_host = socket.ntohs(dport)
            allowed = False
            for entry in outbound_allowed:
                if entry['ip'] == daddr_str and dport_host in entry['ports']:
                    allowed = True
                    break
            if not allowed:
                print(f"ALERT: Unauthorized network connection to {daddr_str}:{dport_host}")
        elif event.event_type == EVENT_CAPABILITY:
            capability = ct.cast(event.data, ct.POINTER(ct.c_int)).contents.value
            cap_name = capability_name(capability)
            if cap_name not in allowed_capabilities:
                print(f"ALERT: Unauthorized capability used: {cap_name}")
        elif event.event_type == EVENT_KERNEL_MODULE_LOAD:
            module = bytes(event.data[:56]).rstrip(b'\x00').decode('utf-8', 'replace')
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
