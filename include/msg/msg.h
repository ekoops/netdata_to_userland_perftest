#include <common.h>
#include <msg/maps.h>
#include <msg/msg_buff.h>

#define AF_INET     2
#define S_IFMT      00170000
#define S_IFSOCK    0140000
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

enum MSG_TYPE {MSG_TYPE_SINGLE = 0, MSG_TYPE_VEC = 1, MSG_TYPE_MULTI = 2};
enum DIR { DIR_INGRESS = 0, DIR_EGRESS = 1};

struct msg_info {
    __u64 ptr;
    __u64 len;
    __u64 pod_id;
    __u64 tid;
    __u64 sockfd;
    __u64 direction;
    __u64 type;
};

/*
 * task__get_cgroup_id returns the id associated with the current process default cgroupv1 cgroup id. The default cgroup is
 * the one associated with the default cgroupv1 subsystem mount path. The default cgroupv1 subsystem is the first
 * available cgroupv1 subsystem.
 */
static __always_inline __u64 task__get_cgroup_id(struct task_struct *task) {
    __u32 zero = 0;
    __u8 *subsys_id = bpf_map_lookup_elem(&subsys_id_map, &zero);
    if (!subsys_id) {
        return 0;
    }
    __u8 cgroup_subsys_count = bpf_core_enum_value(enum cgroup_subsys_id, CGROUP_SUBSYS_COUNT);
    if (*subsys_id >= cgroup_subsys_count) {
        return 0;
    }
    return BPF_CORE_READ(task, cgroups, subsys[*subsys_id], cgroup, kn, id);
}

static __always_inline struct file *task__get_open_file_by_fd(struct task_struct *task, unsigned int fd) {
    struct file *f = NULL;
    struct file **fds = NULL;
    BPF_CORE_READ_INTO(&fds, task, files, fdt, fd);
    bpf_probe_read_kernel(&f, sizeof(struct file *), &fds[fd]);
    return f;
}

static __always_inline void handle_msg(unsigned int sockfd, unsigned int direction, unsigned int msg_type,
                                       unsigned long ptr, unsigned long len) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    __u64 pod_id_value = 0; // TODO: dummy
    __u64 *pod_id = &pod_id_value;  // TODO: dummy
//    // retrieve pod id by using cgroup id
//    // if no pod id is found, the message is not received/sent from/by a monitored pod, so simply ignore it
//    __u64 cgroup_id = task__get_cgroup_id(task);
//    __u64 *pod_id = bpf_map_lookup_elem(&cgroup_id_to_pod_id, &cgroup_id);
//    if (!pod_id) {
//        return;
//    }

    /* ======================== extract the socket information from the current task struct ======================== */
    // retrieve the file associated with the file descriptor
    struct file *f = task__get_open_file_by_fd(task, sockfd);
    if (!f) {
        return;
    }

    // verify if the file is a socket
    unsigned int imode = 0;
    BPF_CORE_READ_INTO(&imode, f, f_path.dentry, d_inode, i_mode);
    if (imode == 0 || !S_ISSOCK(imode)) {
        return;
    }

    // extract the relevant socket information
    struct socket_alloc *sk_alloc = NULL;
    BPF_CORE_READ_INTO(&sk_alloc, f, private_data);
    if (!sk_alloc) {
        return;
    }
    __u8 family = 0;
    __u16 type = 0, protocol = 0;
    BPF_CORE_READ_INTO(&family, sk_alloc, socket.sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&type, sk_alloc, socket.type);
    BPF_CORE_READ_INTO(&protocol, sk_alloc, socket.sk, sk_protocol);

//    // check if the message is received/sent from/by an SCTP socket
//    if ((type == SOCK_STREAM || type == SOCK_SEQPACKET) && (protocol == IPPROTO_SCTP)) {
//        // insert the SCTP message information into the pending messages map for the current process
//        __u64 tid = bpf_get_current_pid_tgid();
//        struct msg_info minfo = {.ptr = ptr, .len = len, .pod_id = *pod_id, .tid = tid, .sockfd = sockfd,
//                .direction = direction,  .type = msg_type };
//        int result = bpf_map_update_elem(&pending_msgs, &tid, &minfo, BPF_NOEXIST);
//        if (result < 0) {
//            return;
//        }
//    }

    __u32 zero = 0;
    __u16 *proto = bpf_map_lookup_elem(&sock_proto_filter, &zero);
    if (!proto) {
        return;
    }
    if (protocol != *proto) {
        return;
    }

    // insert the message information into the pending messages map for the current process
    __u64 tid = bpf_get_current_pid_tgid();
    struct msg_info minfo = {.ptr = ptr, .len = len, .pod_id = *pod_id, .tid = tid, .sockfd = sockfd,
            .direction = direction,  .type = msg_type };
    int result = bpf_map_update_elem(&pending_msgs, &tid, &minfo, BPF_NOEXIST);
    if (result < 0) {
        return;
    }
    return;
}

static __always_inline void handle_msg_ret(void *ctx, long ret) {
    __u64 tid = bpf_get_current_pid_tgid();

    // retrieve message information from pending messages map
    struct msg_info *minfo = bpf_map_lookup_elem(&pending_msgs, &tid);
    if (!minfo) {
        return;
    }

    int result;

    /*
     * Here we handle two cases:
     * - the returned value is -1 or 0 (an error or an orderly shutdown has occurred);
     * - the returned value indicates the message size (> 0) and this size, together with the message metadata, is
     *   greater than the size of the buffer.
     * In both cases, simply remove the message information from pending messages map.
     * Notice: do not separate these two statements or the verifier will complain!
     */
    if (ret < 1 || ret > MAX_MSG_SIZE - sizeof(struct msg_metadata)) {
        goto CLEAN;
    }

    /* ======================== store message data and metadata into the message buffer ======================== */
    // retrieve the message buffer for the current CPU
    struct msg_buff *mbuff = msg_buff__get();
    if (!mbuff) { /* should never happen */
        goto CLEAN;
    }

    switch (minfo->type) {
        case MSG_TYPE_SINGLE: {
            result = msg_buff__store_single(mbuff, (void *) minfo->ptr, ret);
            if (result < 0) {
                goto CLEAN;
            }
            break;
        }
        case MSG_TYPE_VEC: {
            result = msg_buff__store_vec(mbuff, (struct iovec *) minfo->ptr, minfo->len, ret);
            if (result < 0) {
                goto CLEAN;
            }
            break;
        }
        case MSG_TYPE_MULTI: {
            // TODO: not implemented
            break;
        }
        default: {
            break;
        }
    }

    msg_buff__store_metadata(mbuff, minfo->pod_id, minfo->tid, minfo->sockfd, minfo->direction);

    /* ======================== send message data and metadata to user space ======================== */
    result = msg_buff__output(ctx, mbuff);
    if (result < 0) {
        goto CLEAN;
    }

    /* ======================== extract kernel parsable message information ======================== */
    // TODO


    CLEAN:
    bpf_map_delete_elem(&pending_msgs, &tid);
}