#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 event_type;
    char filename[128];
    int flags;
};

BPF_PERF_OUTPUT(events);

// Trace file open syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.event_type = 2; // EVENT_OPEN
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.flags = args->flags;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}