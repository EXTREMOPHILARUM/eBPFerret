#include <linux/module.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char module_name[128];
};

BPF_PERF_OUTPUT(events);

int trace_kernel_module_load(struct pt_regs *ctx, struct module *mod) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel_str(data.module_name, sizeof(data.module_name), mod->name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
