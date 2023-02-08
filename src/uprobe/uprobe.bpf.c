#include <msg/msg.h>
#include <syscall/syscall.h>
#include <syscall/ctx_defs.h>

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

SEC("uprobe/read")
int BPF_KPROBE(uprobe_read_f, int fd, void *buf, size_t count) {
    bpf_printk("uprobe/read");
    handle_msg(fd, DIR_INGRESS, MSG_TYPE_SINGLE, (unsigned long long) buf, (unsigned long) count);
    return 0;
}

SEC("uretprobe/read")
int BPF_KRETPROBE(uretprobe_read_f, ssize_t ret) {
    bpf_printk("uretprobe/read");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/write")
int BPF_KPROBE(uprobe_write_f, int fd, const void *buf, size_t count) {
    bpf_printk("uprobe/write");
    handle_msg(fd, DIR_EGRESS, MSG_TYPE_SINGLE, (unsigned long long) buf, (unsigned long) count);
    return 0;
}

SEC("uretprobe/write")
int BPF_KRETPROBE(uretprobe_write_f, ssize_t ret) {
    bpf_printk("uretprobe/write");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/readv")
int BPF_KPROBE(uprobe_readv_f, int fd, const struct iovec *iov, int iovcnt) {
    bpf_printk("uprobe/readv");
    handle_msg(fd, DIR_INGRESS, MSG_TYPE_VEC, (unsigned long long) iov, (unsigned long) iovcnt);
    return 0;
}

SEC("uretprobe/readv")
int BPF_KRETPROBE(uretprobe_readv_f, ssize_t ret) {
    bpf_printk("uretprobe/readv");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/writev")
int BPF_KPROBE(uprobe_writev_f, int fd, const struct iovec *iov, int iovcnt) {
    bpf_printk("uprobe/writev");
    handle_msg(fd, DIR_EGRESS, MSG_TYPE_VEC, (unsigned long long) iov, (unsigned long) iovcnt);
    return 0;
}

SEC("uretprobe/writev")
int BPF_KRETPROBE(uretprobe_writev_f, ssize_t ret) {
    bpf_printk("uretprobe/writev");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

//SEC("uprobe/sendto")
//int BPF_KPROBE(uprobe_sendto_f, int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
//        unsigned long addrlen) {
//    handle_msg(sockfd, DIR_EGRESS, MSG_TYPE_SINGLE, (unsigned long long) buf, (unsigned long) len);
//    return 0;
//}
//
//SEC("uretprobe/sendto")
//int BPF_KRETPROBE(uretprobe_sendto_f, ssize_t ret) {
//    handle_msg_ret(ctx, (long) ret);
//    return 0;
//}
//
//SEC("uprobe/recvfrom")
//int BPF_KPROBE(uprobe_recvfrom_f, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
//        unsigned long *addrlen) {
//    handle_msg(sockfd, DIR_INGRESS, MSG_TYPE_SINGLE, (unsigned long long) buf, (unsigned long) len);
//    return 0;
//}

SEC("uretprobe/recvfrom")
int BPF_KRETPROBE(uretprobe_recvfrom_f, ssize_t ret) {
    bpf_printk("uretprobe/recvfrom");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/sendmsg")
int BPF_KPROBE(uprobe_sendmsg_f, int sockfd, const struct msghdr *msg, int flags) {
    unsigned long long ptr, len;
    struct user_msghdr *umsg = (struct user_msghdr *) msg;
    BPF_CORE_READ_USER_INTO(&ptr, umsg, msg_iov);
    BPF_CORE_READ_USER_INTO(&len, umsg, msg_iovlen);
    bpf_printk("uprobe/sendmsg");
    handle_msg(sockfd, DIR_EGRESS, MSG_TYPE_VEC, ptr, len);
    return 0;
}

SEC("uretprobe/sendmsg")
int BPF_KRETPROBE(uretprobe_sendmsg_f, ssize_t ret) {
    bpf_printk("uretprobe/sendmsg");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/recvmsg")
int BPF_KPROBE(uprobe_recvmsg_f, int sockfd, struct msghdr *msg, int flags) {
    unsigned long long ptr, len;
    struct user_msghdr *umsg = (struct user_msghdr *) msg;
    BPF_CORE_READ_USER_INTO(&ptr, umsg, msg_iov);
    BPF_CORE_READ_USER_INTO(&len, umsg, msg_iovlen);
    bpf_printk("uprobe/recvmsg");
    handle_msg(sockfd, DIR_INGRESS, MSG_TYPE_VEC, ptr, len);
    return 0;
}

SEC("uretprobe/recvmsg")
int BPF_KRETPROBE(uretprobe_recvmsg_f, ssize_t ret) {
    bpf_printk("uretprobe/recvmsg");
    handle_msg_ret(ctx, (long) ret);
    return 0;
}

SEC("uprobe/recvmmsg")
int BPF_KPROBE(uprobe_recvmmsg_f, int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
        void *timeout) {
    // TODO
    return 0;
}

SEC("uretprobe/recvmmsg")
int BPF_KRETPROBE(uretprobe_recvmmsg_f, int ret) {
    // TODO
    return 0;
}

SEC("uprobe/sendmmsg")
int BPF_KPROBE(uprobe_sendmmsg_f, int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    // TODO
    return 0;
}

SEC("uretprobe/sendmmsg")
int BPF_KRETPROBE(uretprobe_sendmmsg_f, int ret) {
    // TODO
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
