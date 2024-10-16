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
        // Remove capability and module fields
    };
    int flags;  // For open flags
};

enum event_types {
    EVENT_EXECVE = 1,
    EVENT_OPEN,
    EVENT_CONNECT,
    EVENT_SYSCALL,
    // Remove capability and module load events
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
    data.flags = args->flags;
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
