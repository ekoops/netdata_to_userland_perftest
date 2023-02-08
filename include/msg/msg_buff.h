#include <common.h>
#include <msg/maps.h>

#define BUFF_SIZE (128 * 1024)
#define MAX_MSG_SIZE (64 * 1024)
#define CAP_TO_MAX_MSG_SIZE(x) (x & (MAX_MSG_SIZE - 1))

struct msg_buff {
    __u8 data[BUFF_SIZE];
    __u32 data_len;
} __attribute__((packed));

struct msg_metadata {
    __u64 ktime;
    __u64 pod_id;
    __u64 tid;
    __u32 sockfd;
    __u32 direction;
    __u32 len;
};
// Force emitting struct msg_metadata into the ELF.
const struct msg_metadata *msg_metadata__unused __attribute__((unused));

static __always_inline struct msg_buff *msg_buff__get() {
    __u32 cpu_id = (__u32) bpf_get_smp_processor_id();
    return (struct msg_buff *) bpf_map_lookup_elem(&msg_buffs, &cpu_id);
}

/*
 * msg_buff__store_metadata stores the metadata at the beginning of the provided message buffer by using the provided
 * info. This helper must be called after the message buffer has been populated with data.
 */
static __always_inline void msg_buff__store_metadata(struct msg_buff *buff, __u64 pod_id, __u32 tid, __u32 sockfd,
    __u8 direction) {
    __u64 ktime = bpf_ktime_get_ns();
    struct msg_metadata md = {.ktime = ktime, .pod_id = pod_id, .tid = tid, .sockfd = sockfd, .direction = direction,
        .len = buff->data_len};
    *((struct msg_metadata *) buff->data) = md;
}

// returns 0 on success, or a negative error in case of failure
static __always_inline int msg_buff__store_single(struct msg_buff *buff, void *data, unsigned long bytes_to_read) {
    int result = bpf_probe_read_user(&buff->data[CAP_TO_MAX_MSG_SIZE(sizeof(struct msg_metadata))], bytes_to_read, data);

    // if the read operation was successful, store the size of the message in the message buffer
    if (!result) {
        buff->data_len = bytes_to_read;
    }
    return result;
}

// 0 is returned on success, a negative number in case of error
static __always_inline int msg_buff__store_vec(struct msg_buff *buff, struct iovec *iovecs, unsigned long iovecs_len,
    unsigned long bytes_to_read) {
    int i, result;
    struct iovec iov;
    unsigned long to_read = 0;
    unsigned long remaining_bytes_to_read = bytes_to_read;
    unsigned long last_written_pos = sizeof(struct msg_metadata);

    #pragma unroll
    for (i=0; i<32; i++) {
        if (i == iovecs_len) {
            break;
        }
        result = bpf_probe_read_user(&iov, sizeof(struct iovec), (void *) iovecs + i * sizeof(struct iovec));
        if (result != 0) {
            return -1;
        }

        to_read = (iov.iov_len < remaining_bytes_to_read) ? iov.iov_len : remaining_bytes_to_read;

        result = bpf_probe_read_user(&buff->data[CAP_TO_MAX_MSG_SIZE(last_written_pos)],
                                     CAP_TO_MAX_MSG_SIZE(to_read), iov.iov_base);
        if (result != 0) {
            return -2;
        }

        remaining_bytes_to_read -= to_read;
        if (remaining_bytes_to_read == 0) {
            break;
        }
        last_written_pos += to_read;
    }
    // if the read operation was successful, store the size of the message in the message buffer
    buff->data_len = bytes_to_read;
    return 0;
}

static __always_inline int msg_buff__output(void *ctx, struct msg_buff *buff) {
    return bpf_ringbuf_output(&data_buff, buff->data, CAP_TO_MAX_MSG_SIZE(buff->data_len + sizeof(struct msg_metadata)),
            BPF_RB_FORCE_WAKEUP);
}