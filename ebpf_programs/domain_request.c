#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
};

BPF_PERF_OUTPUT(events);

int trace_domain_request(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
