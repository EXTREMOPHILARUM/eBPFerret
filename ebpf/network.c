#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 event_type;
    u8 direction;
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
};

struct xdp_data_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(xdp_events);

// Trace outbound TCP connections
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    data.event_type = 3; // EVENT_CONNECT
    data.direction = 0;  // Outbound
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET) {
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &sk->__sk_common.skc_dport);
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Trace inbound TCP connections
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct sock *sk = (struct sock *)args->skaddr;
    if (args->oldstate != TCP_SYN_RECV || args->newstate != TCP_ESTABLISHED)
        return 0;

    struct data_t data = {};
    data.event_type = 7; // EVENT_ACCEPT
    data.direction = 1;  // Inbound
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        data.saddr = sk->__sk_common.skc_daddr;
        data.daddr = sk->__sk_common.skc_rcv_saddr;
        data.sport = sk->__sk_common.skc_dport;
        data.dport = sk->__sk_common.skc_num;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// XDP program
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct xdp_data_t xdp_data = {};
    xdp_data.src_ip = ip->saddr;
    xdp_data.dst_ip = ip->daddr;
    xdp_data.src_port = tcp->source;
    xdp_data.dst_port = tcp->dest;
    xdp_data.protocol = ip->protocol;

    xdp_events.perf_submit(ctx, &xdp_data, sizeof(xdp_data));

    return XDP_PASS;
}
