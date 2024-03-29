#include <iostream>
#include <string>
#include <map>
#include <iomanip>
#include <csignal>
#include <linux/limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/in.h>
#include <sys/resource.h>
#include <process_state.h>
#include <libbpf_util.h>
#include "uprobe.skel.h"

#define OFFSET_read        0x114980 // read@@GLIBC_2.2.5
#define OFFSET_write       0x114a20 // write@@GLIBC_2.2.5
#define OFFSET_readv       0x11ab50 // readv@@GLIBC_2.2.5
#define OFFSET_writev      0x11abf0 // writev@@GLIBC_2.2.5
#define OFFSET_sendto      0x127ba0 // sendto@@GLIBC_2.2.5
#define OFFSET_recvfrom    0x1278c0 // recvfrom@@GLIBC_2.2.5
#define OFFSET_sendmsg     0x127b00 // sendmsg@@GLIBC_2.2.5
#define OFFSET_recvmsg     0x127990 // recvmsg@@GLIBC_2.2.5
#define OFFSET_recvmmsg    0x127f30 // recvmmsg@@GLIBC_2.12
#define OFFSET_sendmmsg    0x127ff0 // sendmmsg@@GLIBC_2.14

#define GLIBC_SYMBOL_OFFSET(symbol) (OFFSET_##symbol)

#define CONCAT(a, b, c) a##b##c
#define UPROBE(symbol) CONCAT(uprobe_, symbol, _f)
#define URETPROBE(symbol) CONCAT(uretprobe_, symbol, _f)

#define ATTACH_UPROBE(symbol, skel, pid, binary_path)                                                   \
    ({                                                                                                  \
        int err;                                                                                        \
        skel->links.UPROBE(symbol) = bpf_program__attach_uprobe(                                        \
            skel->progs.UPROBE(symbol), false, pid, binary_path, GLIBC_SYMBOL_OFFSET(symbol));          \
        if (!skel->links.UPROBE(symbol)) {                                                              \
            err = -errno;                                                                               \
            std::cerr << "Failed to attach uprobe for symbol " #symbol ": " << err << std::endl;        \
            return -1;                                                                                  \
        }                                                                                               \
        skel->links.URETPROBE(symbol) = bpf_program__attach_uprobe(                                     \
            skel->progs.URETPROBE(symbol), true, pid, binary_path, GLIBC_SYMBOL_OFFSET(symbol));        \
        if (!skel->links.URETPROBE(symbol)) {                                                           \
            err = -errno;                                                                               \
            std::cerr << "Failed to attach uretuprobe for symbol " #symbol ": " << err << std::endl;    \
            return -1;                                                                                  \
        }                                                                                               \
    })

// return 0 on success, -1 in case of error
int attach_uprobes(struct uprobe_bpf *skel, pid_t pid, const char *binary_path) {
    ATTACH_UPROBE(read, skel, pid, binary_path);
    ATTACH_UPROBE(write, skel, pid, binary_path);
    ATTACH_UPROBE(readv, skel, pid, binary_path);
    ATTACH_UPROBE(writev, skel, pid, binary_path);
//    ATTACH_UPROBE(sendto, skel, pid, binary_path); // TODO: attach uprobe on sendto
//    ATTACH_UPROBE(recvfrom, skel, pid, binary_path); // TODO: attach uprobe on recvfrom
    ATTACH_UPROBE(sendmsg, skel, pid, binary_path);
    ATTACH_UPROBE(recvmsg, skel, pid, binary_path);
//    ATTACH_UPROBE(recvmmsg, skel, pid, binary_path); // TODO: attach uprobe on recvmmsg
//    ATTACH_UPROBE(sendmmsg, skel, pid, binary_path); // TODO: attach uprobe on sendmmsg
    return 0;
}

process_state proc_state {};
unsigned long long samples = 0, losts = 0 /* TODO: handle lost messages */;

std::map<std::string, int> capture_filters = {
        {"tcp",  IPPROTO_TCP},
        {"udp",  IPPROTO_UDP},
        {"sctp", IPPROTO_SCTP}
};

static void sig_handler(int sig) {
    proc_state.signal();
}

int rb_sample_handler(void *ctx, void *data, size_t len) {
    samples++;
    return 0;
}

void print_stats() {
    auto w = std::setw(21);
    std::cout << "Total:\t" << w << samples << w << losts << std::endl;
    std::chrono::duration<double> time = proc_state.get_time();
    std::cout << "Time:\t" << w << time.count() << std::endl;
    std::cout << "Pps:\t" << w << (samples / time.count()) << std::endl;
}

int main(int argc, char **argv) {
    int err, result, zero = 0;
    pid_t pid;
    std::string binary_path;
    unsigned long rb_buffer_pages_num, page_size, rb_buffer_size;
    int capture_filter;
    struct uprobe_bpf *skel;
    unsigned int rb_map_fd, filter_map_fd;
    struct ring_buffer *rb = NULL;

    if (argc < 5) {
        std::cerr << "Usage: ./<prog_name> <pid> <binary_path> <buffer_pages_num> <tcp|udp|sctp>" << std::endl;
        return 1;
    }

    // parse arguments
    try {
        pid = (pid_t) std::stoi(argv[1]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <pid> parameter: " << ex.what() << std::endl;
        return 2;
    }
    binary_path = std::string { argv[2] };
    try {
        rb_buffer_pages_num = std::stoi(argv[3]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <buffer_pages_num> parameter: " << ex.what() << std::endl;
        return 3;
    }
    auto it = capture_filters.find(std::string{argv[4]});
    if (it == capture_filters.end()) {
        std::ostringstream oss;
        oss << "Capture filter must be set to a value belonging to the following list:\n";
        for (auto &filter: capture_filters) {
            oss << filter.first << "\n";
        }
        std::cerr << oss.str() << std::endl;
        return 4;
    }
    capture_filter = it->second;

    // get some environment information
    page_size = sysconf(_SC_PAGESIZE);
    rb_buffer_size = rb_buffer_pages_num * page_size;
    std::cout << "Buffer size set to " << rb_buffer_size << " bytes (pages: " << rb_buffer_pages_num << ", size: " <<
        page_size << ")" << std::endl;

    // set up libbpf logging callback
    libbpf_set_print(libbpf_print_fn);
    // set up BPF strict mode
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // bump RLIMIT_MEMLOCK to create BPF maps
    bump_memlock_rlimit();

    // open the skeleton
    skel = uprobe_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open skeleton" << std::endl;
        return 5;
    }

    // set ring buffer buffer size
    err = bpf_map__set_max_entries(skel->maps.data_buff, rb_buffer_size);
    if (err) {
        std::cerr << "Failed to set ring buffer buffer size" << std::endl;
        return 6;
    }

    // load the skeleton
    err = uprobe_bpf__load(skel);
    if (err) {
        err = 7;
        std::cerr << "Failed to load skeleton" << std::endl;
        goto cleanup_skel_destroy;
    }

    // attach uprobes and uretprobes
    err = attach_uprobes(skel, pid, binary_path.data());
    if (err) {
        err = 8;
        std::cerr << "Failed to attach uprobes and uretprobes" << std::endl;
        goto cleanup_skel_destroy;
    }

    // load in kernel the protocol number of traffic we are interested in
    filter_map_fd = bpf_map__fd(skel->maps.sock_proto_filter);
    if (filter_map_fd == EINVAL) {
        err = 9;
        std::cerr << "Failed to get filter map file descriptor" << std::endl;
        goto cleanup_skel_destroy;
    }
    result = bpf_map_update_elem(filter_map_fd, &zero, &capture_filter, BPF_EXIST);
    if (result == -1) {
        err = 10;
        std::cerr << "Failed to update in-kernel traffic capture filter" << std::endl;
        goto cleanup_skel_destroy;
    }

    // get ring buffer file descriptor
    rb_map_fd = bpf_map__fd(skel->maps.data_buff);
    if (rb_map_fd == EINVAL) {
        err = 11;
        std::cerr << "Failed to get ring buffer file descriptor" << std::endl;
        goto cleanup_skel_destroy;
    }

    // get ring buffer handle
    rb = ring_buffer__new(rb_map_fd, rb_sample_handler, NULL /*TODO: provide reference to packet handler*/, NULL);
    if (libbpf_get_error(rb)) {
        err = 12;
        std::cerr << "Failed to create ring buffer manager" << std::endl;
        goto cleanup_skel_destroy;
    }

    // register signal handlers
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    // wait for signal before start reading from perf buffer
    std::cout << "Waiting for external signal..." << std::endl;
    proc_state.wait();

    // Read samples from ring buffer
    std::cout << "Starting to read from ring buffer..." << std::endl;
    while (proc_state.get_state() != 2) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            std::cerr << "Failed to read from ring buffer: " << err << std::endl;
            err = 13;
            goto cleanup;
        }
    }
    // print results
    print_stats();

    cleanup:
    ring_buffer__free(rb);
    cleanup_skel_destroy:
    uprobe_bpf__destroy(skel);

    return err;
}