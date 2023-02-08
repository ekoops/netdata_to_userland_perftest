struct sys_enter_recvfrom_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    void *ubuf;
    __s64 size;
    __u64 flags;
    struct sockaddr *addr;
    int *addr_len;
};

struct sys_exit_recvfrom_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_recvmmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    struct mmsghdr *mmsg;
    __u64 vlen;
    __u64 flags;
    struct __kernel_timespec *timeout;
};

struct sys_exit_recvmmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_recvmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    struct user_msghdr *msg;
    __u64 flags;
};

struct sys_exit_recvmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_read_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

struct sys_exit_read_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_readv_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    const struct iovec * vec;
    __u64 vlen;
};

struct sys_exit_readv_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_sendto_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    void *buff;
    __u64 len;
    __u64 flags;
    struct sockaddr *addr;
    int *addr_len;
};

struct sys_exit_sendto_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_sendmmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    struct mmsghdr * mmsg;
    __u64 vlen;
    __u64 flags;
};

struct sys_exit_sendmmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_sendmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    struct user_msghdr * msg;
    __u64 flags;
};

struct sys_exit_sendmsg_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_write_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    const char * buf;
    __u64 count;
};

struct sys_exit_write_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};

struct sys_enter_writev_args {
    __u64 pad;

    __s32 __syscall_nr;
    __u64 fd;
    const struct iovec * vec;
    __u64 vlen;
};

struct sys_exit_writev_args {
    __u64 pad;

    __s32 __syscall_nr;
    __s64 ret;
};