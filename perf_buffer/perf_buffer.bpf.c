#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ntohs(x)	((unsigned short int)((((x) >> 8) & 0xff) | (((x)&0xff) << 8)))
#define ETH_P_IP    0x0800        /* Internet Protocol packet	*/
#define ETH_P_ARP   0x0806        /* Address Resolution packet	*/
#define ETH_P_IPV6  0x86DD        /* IPv6 over bluebook		*/
#define TC_ACT_OK   0

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct metadata {
    __u64 packet_len;
};

static __always_inline int is_sctp(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *) data;
    if ((void *) (eth + 1) > data_end) {
        return 0;
    }
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return 0;
    }
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if ((void *) (ip + 1) > data_end) {
        return 0;
    }
    return (ip->protocol == IPPROTO_SCTP);
}

SEC("xdp")
int xdp_probe_f(struct xdp_md *ctx) {
//    if (is_sctp(ctx)) {
//        return XDP_PASS;
//    }
    __u64 len = (ctx->data_end - ctx->data);
    __u64 flags = (len << 32) | BPF_F_CURRENT_CPU;
    struct metadata m = {.packet_len = len};
    bpf_perf_event_output(ctx, &pb, flags, &m, sizeof(m));
    return XDP_PASS;
}

SEC("tc")
int tc_probe_f(struct __sk_buff *ctx) {
    __u64 len = (ctx->data_end - ctx->data);
    __u64 flags = (len << 32) | BPF_F_CURRENT_CPU;
    struct metadata m = {.packet_len = len};
    bpf_perf_event_output(ctx, &pb, flags, &m, sizeof(m));
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";