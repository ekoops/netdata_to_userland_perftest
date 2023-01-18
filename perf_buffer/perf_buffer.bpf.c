#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ntohs(x)	((unsigned short int)((((x) >> 8) & 0xff) | (((x)&0xff) << 8)))
#define ETH_P_IP    0x0800        /* Internet Protocol packet	*/
#define ETH_P_ARP   0x0806        /* Address Resolution packet	*/
#define ETH_P_IPV6  0x86DD        /* IPv6 over bluebook		*/
#define TC_ACT_OK   0

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct metadata {
    __u64 packet_len;
};

static __always_inline struct iphdr * get_iphdr(void *data, void *data_end) {
    struct ethhdr *eth = (struct ethhdr *) data;
    if ((void *) (eth + 1) > data_end) {
        return NULL;
    }
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return NULL;
    }
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if ((void *) (ip + 1) > data_end) {
        return NULL;
    }
    return ip;
}

SEC("xdp")
int xdp_probe_f(struct xdp_md *ctx) {
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

SEC("xdp")
int xdp_probe_filtered_f(struct xdp_md *ctx) {
    struct iphdr *ip = get_iphdr((void *) (long) ctx->data, (void *) (long) ctx->data_end);
    if (!ip) {
        return XDP_PASS;
    }
    int zero = 0;
    int *proto = bpf_map_lookup_elem(&filter_map, &zero);
    if (!proto) {
        return XDP_PASS;
    }
    if (ip->protocol != *proto) {
        return XDP_PASS;
    }
    __u64 len = (ctx->data_end - ctx->data);
    __u64 flags = (len << 32) | BPF_F_CURRENT_CPU;
    struct metadata m = {.packet_len = len};
    bpf_perf_event_output(ctx, &pb, flags, &m, sizeof(m));
    return XDP_PASS;
}

SEC("tc")
int tc_probe_filtered_f(struct __sk_buff *ctx) {
    struct iphdr *ip = get_iphdr((void *) (long) ctx->data, (void *) (long) ctx->data_end);
    if (!ip) {
        return TC_ACT_OK;
    }
    int zero = 0;
    int *proto = bpf_map_lookup_elem(&filter_map, &zero);
    if (!proto) {
        return TC_ACT_OK;
    }
    if (ip->protocol != *proto) {
        return TC_ACT_OK;
    }
    __u64 len = (ctx->data_end - ctx->data);
    __u64 flags = (len << 32) | BPF_F_CURRENT_CPU;
    struct metadata m = {.packet_len = len};
    bpf_perf_event_output(ctx, &pb, flags, &m, sizeof(m));
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";