#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_LIB_NAME 256

struct data_t {
    u32 pid;
    u32 uid;
    char lib_name[MAX_LIB_NAME];
};

BPF_PERF_OUTPUT(events);

int trace_ld_preload(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_probe_read_user_str(data.lib_name, sizeof(data.lib_name), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
