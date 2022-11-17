#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct metadata {
    __u64 packet_len;
};

SEC("xdp")
int xdp_probe_f(struct xdp_md *ctx) {
    __u64 len = (ctx->data_end - ctx->data);
    __u64 flags = (len << 32) | BPF_F_CURRENT_CPU;
    struct metadata m = {.packet_len = len};
    bpf_perf_event_output(ctx, &pb, flags, &m, sizeof(m));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";