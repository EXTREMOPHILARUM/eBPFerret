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
EVENT_ACCEPT = 7

def parse_arguments():
    parser = argparse.ArgumentParser(description="eBPF-based Threat Detection Engine")
    parser.add_argument("--mode", choices=["learning", "enforcement"], required=True, help="Mode of operation")
    parser.add_argument("--config", required=True, help="Path to the YAML config file")
    parser.add_argument("--duration", type=int, default=60, help="Learning duration in seconds")
    return parser.parse_args()

def load_ebpf_programs():
    with open("ebpf/filesystem.c", "r") as f:
        bpf_filesystem = BPF(text=f.read())
    with open("ebpf/network.c", "r") as f:
        bpf_network = BPF(text=f.read())
    with open("ebpf/syscalls.c", "r") as f:
        bpf_syscalls = BPF(text=f.read())
    
    # Attach XDP program to a network interface (e.g., eth0)
    try:
        function_xdp_prog = bpf_network.load_func("xdp_prog", BPF.XDP)
        bpf_network.attach_xdp("wlan0", function_xdp_prog)
    except Exception as e:
        print(f"Failed to attach XDP program: {e}")
        print("Continuing without XDP...")
    
    return bpf_filesystem, bpf_network, bpf_syscalls

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack('!I', ip))

# Define the ctypes structure matching data_t
class Data(ct.Structure):
    _fields_ = [
        ('pid', ct.c_uint32),
        ('comm', ct.c_char * 16),
        ('event_type', ct.c_uint32),
        ('direction', ct.c_uint8),
        ('filename', ct.c_char * 128),  # Add this line
        ('sport', ct.c_uint16),
        ('dport', ct.c_uint16),
        ('saddr', ct.c_uint32),
        ('daddr', ct.c_uint32),
        ('flags', ct.c_int),
    ]

class XdpData(ct.Structure):
    _fields_ = [
        ('src_ip', ct.c_uint32),
        ('dst_ip', ct.c_uint32),
        ('src_port', ct.c_uint16),
        ('dst_port', ct.c_uint16),
        ('protocol', ct.c_uint8),
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

def learning_mode(bpf_programs, duration, config_path):
    bpf_filesystem, bpf_network, bpf_syscalls = bpf_programs
    events = defaultdict(list)
    start_time = time.time()

    def collect_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        if event.event_type == EVENT_EXECVE:
            filename = event.filename.decode('utf-8', 'replace').rstrip('\0')
            events['execve'].append(filename)
        elif event.event_type == EVENT_OPEN:
            filename = event.filename.decode('utf-8', 'replace').rstrip('\0')
            flags = event.flags
            events['open'].append((filename, flags))
        elif event.event_type in (EVENT_CONNECT, EVENT_ACCEPT):
            saddr_str = socket.inet_ntoa(struct.pack('!I', event.saddr))
            daddr_str = socket.inet_ntoa(struct.pack('!I', event.daddr))
            sport = socket.ntohs(event.sport)
            dport = socket.ntohs(event.dport)
            connection = {
                'source_ip': saddr_str,
                'source_port': sport,
                'destination_ip': daddr_str,
                'destination_port': dport,
                'direction': 'inbound' if event.direction == 1 else 'outbound'
            }
            events['network'].append(connection)
        elif event.event_type == XDP_EVENT:
            xdp_data = ct.cast(data, ct.POINTER(XdpData)).contents
            src_ip = socket.inet_ntoa(struct.pack('!I', xdp_data.src_ip))
            dst_ip = socket.inet_ntoa(struct.pack('!I', xdp_data.dst_ip))
            src_port = socket.ntohs(xdp_data.src_port)
            dst_port = socket.ntohs(xdp_data.dst_port)
            connection = {
                'source_ip': src_ip,
                'source_port': src_port,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'protocol': xdp_data.protocol
            }
            events['xdp_network'].append(connection)

    bpf_filesystem["events"].open_perf_buffer(collect_event)
    bpf_network["events"].open_perf_buffer(collect_event)
    bpf_syscalls["events"].open_perf_buffer(collect_event)

    while time.time() - start_time < duration:
        bpf_filesystem.perf_buffer_poll(timeout=100)
        bpf_network.perf_buffer_poll(timeout=100)
        bpf_syscalls.perf_buffer_poll(timeout=100)

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
    allowlist['allowlist']['syscalls'] = [s for s in syscalls if s['paths']]
    allowlist['allowlist']['filesystem'] = {
        'read': [f for f in filesystem['read'] if f.strip()],
        'write': [f for f in filesystem['write'] if f.strip()]
    }
    allowlist['allowlist']['network'] = {
        'outbound': [n for n in network['outbound'] if n['destination_ip'].strip() and n['ports']],
        'inbound': [n for n in network['inbound'] if n['source_ip'].strip() and n['ports']]
    }

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
            filename = event.filename.decode('utf-8', 'replace').rstrip('\0')
            allowed_paths = allowed_syscalls.get('execve', set())
            if filename not in allowed_paths:
                print(f"ALERT: Unauthorized execve call detected: {filename}")
        elif event.event_type == EVENT_OPEN:
            filename = event.filename.decode('utf-8', 'replace').rstrip('\0')
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
            module = bytes(event.filename[:56]).rstrip(b'\x00').decode('utf-8', 'replace')
            if module not in allowed_kernel_modules:
                print(f"ALERT: Unauthorized kernel module load: {module}")
        # Handle other event types as needed

    b["events"].open_perf_buffer(enforce_policy)

    print("Enforcement mode active. Monitoring for unauthorized events.")

    while True:
        b.perf_buffer_poll(timeout=100)

def main():
    args = parse_arguments()
    bpf_programs = load_ebpf_programs()

    if args.mode == "learning":
        learning_mode(bpf_programs, args.duration, args.config)
    elif args.mode == "enforcement":
        enforcement_mode(bpf_programs, args.config)

if __name__ == "__main__":
    main()
