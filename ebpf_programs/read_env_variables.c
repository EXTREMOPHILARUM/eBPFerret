#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char var[256];
};

BPF_PERF_OUTPUT(events);

int trace_read_env_var(struct pt_regs *ctx, const char *var) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel_str(data.var, sizeof(data.var), var);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
