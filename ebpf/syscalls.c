#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 event_type;
    u8 direction;
    char filename[MAX_FILENAME_LEN];
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    int flags;
};

BPF_PERF_OUTPUT(events);

// Trace execve syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.event_type = 1; // EVENT_EXECVE
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Trace open syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    struct data_t data = {};
    data.event_type = 2; // EVENT_OPEN
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    data.flags = args->flags;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Trace connect syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    data.event_type = 3; // EVENT_CONNECT
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (addr) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        bpf_probe_read(&data.daddr, sizeof(data.daddr), &addr_in->sin_addr.s_addr);
        bpf_probe_read(&data.dport, sizeof(data.dport), &addr_in->sin_port);
    }
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Trace accept syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
    struct data_t data = {};
    data.event_type = 7; // EVENT_ACCEPT
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
