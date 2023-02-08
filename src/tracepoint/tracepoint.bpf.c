#include <msg/msg.h>
#include <syscall/syscall.h>
#include <syscall/ctx_defs.h>

SEC("raw_tp/sys_enter")
int BPF_PROG(sys_enter_handler, struct pt_regs *regs, long syscall_id) {
    unsigned int sockfd;
    unsigned int direction;
    unsigned int msg_type;
    unsigned long ptr;
    unsigned long len;

    switch (syscall_id) {
        case SYS_read: {
            direction = DIR_INGRESS;
            msg_type = MSG_TYPE_SINGLE;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_write: {
            direction = DIR_EGRESS;
            msg_type = MSG_TYPE_SINGLE;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_readv: {
            direction = DIR_INGRESS;
            msg_type = MSG_TYPE_VEC;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_writev: {
            direction = DIR_EGRESS;
            msg_type = MSG_TYPE_VEC;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_sendto: {
            direction = DIR_EGRESS;
            msg_type = MSG_TYPE_SINGLE;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_recvfrom: {
            direction = DIR_INGRESS;
            msg_type = MSG_TYPE_SINGLE;
            ptr = PT_REGS_PARM2_CORE_SYSCALL(regs);
            len = PT_REGS_PARM3_CORE_SYSCALL(regs);
            break;
        }
        case SYS_sendmsg: {
            direction = DIR_EGRESS;
            msg_type = MSG_TYPE_VEC;
            struct user_msghdr *msg = (struct user_msghdr *) PT_REGS_PARM2_CORE_SYSCALL(regs);
            BPF_CORE_READ_USER_INTO(&ptr, msg, msg_iov);
            BPF_CORE_READ_USER_INTO(&len, msg, msg_iovlen);
            break;
        }
        case SYS_recvmsg: {
            direction = DIR_INGRESS;
            msg_type = MSG_TYPE_VEC;
            struct user_msghdr *msg = (struct user_msghdr *) PT_REGS_PARM2_CORE_SYSCALL(regs);
            BPF_CORE_READ_USER_INTO(&ptr, msg, msg_iov);
            BPF_CORE_READ_USER_INTO(&len, msg, msg_iovlen);
            break;
        }
        case SYS_recvmmsg: {
            // TODO
            return 0;
        }
        case SYS_sendmmsg: {
            // TODO
            return 0;
        }
        default: {
            return 0;
        }
    }
    sockfd = PT_REGS_PARM1_CORE_SYSCALL(regs);

    handle_msg(sockfd, direction, msg_type, ptr, len);

    return 0;
}

SEC("raw_tp/sys_exit")
int BPF_PROG(sys_exit_handler, struct pt_regs *regs, long ret) {
    handle_msg_ret(ctx, ret);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";