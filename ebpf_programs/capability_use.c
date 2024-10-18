#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    int cap;
};

BPF_PERF_OUTPUT(events);

int trace_capability_use(struct pt_regs *ctx, const struct cred *cred, int cap) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.cap = cap;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
