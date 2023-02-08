#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_dropper_f(struct xdp_md *ctx) {
    return bpf_ktime_get_boot_ns() % 2 ? XDP_PASS : XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";