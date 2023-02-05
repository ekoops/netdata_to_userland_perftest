#include <mutex>
#include <condition_variable>
#include <iostream>
#include <vector>
#include <map>
#include <iomanip>
#include <thread>
#include <csignal>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <sys/resource.h>
#include ".output/xdp_tc.skel.h"

int state = 0;
std::mutex state_mutex;
std::condition_variable state_cv;

std::vector<unsigned long long> samples;
std::vector<unsigned long long> losts;
std::chrono::time_point <std::chrono::system_clock> start, end;

std::map<std::string, int> capture_filters = {
        {"tcp",  IPPROTO_TCP},
        {"udp",  IPPROTO_UDP},
        {"sctp", IPPROTO_SCTP}
};

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    /* Ignore debug-level libbpf logs */
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
            .rlim_cur    = RLIM_INFINITY,
            .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        std::cerr << "Failed to increase RLIMIT_MEMLOCK limit!" << std::endl;
        exit(1);
    }
}

static void sig_handler(int sig) {
    std::unique_lock <std::mutex> ul{state_mutex};
    if (state == 0) {
        start = std::chrono::system_clock::now();
    }
    state++;
    state_cv.notify_all();
}

void pb_sample_handler(void *ctx, int cpu, void *data, __u32 size) {
    samples[cpu]++;
}

void pb_lost_handler(void *ctx, int cpu, __u64 count) {
    losts[cpu] += count;
}

void print_stats(int cpu_num) {
    int i;
    unsigned long long samples_tot = 0, losts_tot = 0;
    auto w = std::setw(21);
    std::cout << "\n\t" << w << "Samples" << w << "Losts" << std::endl;
    for (i = 0; i < cpu_num; i++) {
        samples_tot += samples[i];
        losts_tot += losts[i];
        std::cout << "Core " << i << ":\t" << w << samples[i] << w << losts[i] << std::endl;
    }
    std::cout << "Total:\t" << w << samples_tot << w << losts_tot << std::endl;
    std::chrono::duration<double> time = end - start;
    std::cout << "Time:\t" << w << time.count() << std::endl;
    std::cout << "Pps:\t" << w << (samples_tot / time.count()) << std::endl;
}

void wait_for_signal() {
    std::unique_lock <std::mutex> ul{state_mutex};
    while (state == 0) {
        state_cv.wait(ul);
    }
}

int get_state() {
    std::unique_lock <std::mutex> ul{state_mutex};
    return state;
}

int main(int argc, char **argv) {
    int err;
    std::string prog_type;
    int ifindex;
    unsigned long pb_per_cpu_pages, pb_per_cpu_page_size;
    bool is_filtered = false;
    int capture_filter;
    int cpu_num;
    struct bpf_program *pb_prog;
    struct xdp_tc_bpf *skel;
    unsigned int xt_prog_fd, pb_map_fd, filter_map_fd;
    struct perf_buffer *pb = NULL;

    if (argc < 4 || argc > 5) {
        std::cerr << "Usage: ./<prog_name> <xdp|tc> <ifindex> <per_cpu_buffer_pages> [<tcp|udp|sctp>]" << std::endl;
        return 1;
    }

    // parse arguments
    prog_type = std::string{argv[1]};
    try {
        ifindex = std::stoi(argv[2]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <ifindex> parameter: " << ex.what() << std::endl;
        return 2;
    }
    try {
        pb_per_cpu_pages = std::stoi(argv[3]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <per_cpu_buffer_pages> parameter: " << ex.what() << std::endl;
        return 2;
    }

    if (argc == 5) { // capture filter is provided
        auto it = capture_filters.find(std::string{argv[4]});
        if (it == capture_filters.end()) {
            std::ostringstream oss;
            oss << "Capture filter must be set to a value belonging to the following list:\n";
            for (auto &filter: capture_filters) {
                oss << filter.first << "\n";
            }
            std::cerr << oss.str() << std::endl;
            return 2;
        }
        is_filtered = true;
        capture_filter = it->second;
    }

    // get some environment information
    pb_per_cpu_page_size = sysconf(_SC_PAGESIZE);
    cpu_num = std::thread::hardware_concurrency();
    std::cout << "Per-core buffer size set to " << pb_per_cpu_pages * pb_per_cpu_page_size << " bytes (pages: " <<
              pb_per_cpu_pages << ", size: " << pb_per_cpu_page_size << ")\nDetected " << cpu_num << " cpus"
              << std::endl;

    try {
        samples = std::vector<unsigned long long>(cpu_num);
        losts = std::vector<unsigned long long>(cpu_num);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to allocate counters: " << ex.what() << std::endl;
        return 3;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress,.ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress,.ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress,.handle = 1, .priority = 1);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress,.handle = 2, .priority = 1);
    bool tc_hook_created_ingress = false, tc_hook_created_egress = false;

    // set up libbpf logging callback
    libbpf_set_print(libbpf_print_fn);
    // set up BPF strict mode
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // bump RLIMIT_MEMLOCK to create BPF maps
    bump_memlock_rlimit();

    // open and load the skeleton
    skel = xdp_tc_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open skeleton" << std::endl;
        return 4;
    }

    if (prog_type == "xdp") {
        pb_prog = is_filtered ? skel->progs.xdp_probe_filtered_f : skel->progs.xdp_probe_f;
        xt_prog_fd = bpf_program__fd(pb_prog);
        // attach XDP program to the interface corresponding to the provided ifindex
        err = bpf_xdp_attach(ifindex, xt_prog_fd, XDP_FLAGS_DRV_MODE /*XDP_FLAGS_SKB_MODE*/, NULL);
        if (err) {
            std::cerr << "Failed to attach XDP program" << std::endl;
            goto cleanup_skel_destroy;
        }
        std::cout << "Attached XDP program" << std::endl;
    } else if (prog_type == "tc") {
        // create ingress TC hook
        err = bpf_tc_hook_create(&tc_hook_ingress);
        if (err && err != -EEXIST) {
            std::cerr << "Failed to create ingress TC hook" << std::endl;
            goto cleanup_skel_destroy;
        }
        tc_hook_created_ingress = true;

        // create egress TC hook
        err = bpf_tc_hook_create(&tc_hook_egress);
        if (err && err != -EEXIST) {
            std::cerr << "Failed to create egress TC hook" << std::endl;
            goto cleanup_skel_destroy;
        }
        tc_hook_created_egress = true;

        pb_prog = is_filtered ? skel->progs.tc_probe_filtered_f : skel->progs.tc_probe_f;
        xt_prog_fd = bpf_program__fd(pb_prog);

        tc_opts_ingress.prog_fd = xt_prog_fd;
        // attach ingress TC program to the interface corresponding to the provided ifindex
        err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
        if (err) {
            std::cerr << "Failed to attach ingress TC program" << std::endl;
            goto cleanup_skel_destroy;
        }

        tc_opts_egress.prog_fd = xt_prog_fd;
        // attach egress TC program to the interface corresponding to the provided ifindex
        err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
        if (err) {
            std::cerr << "Failed to attach egress TC program" << std::endl;
            goto cleanup_skel_destroy;
        }

        std::cout << "Attached TC programs" << std::endl;
    } else {
        err = 4;
        std::cerr << "Wrong prog type parameter (should be xdp or tc)" << std::endl;
        goto cleanup_skel_destroy;
    }

    // if traffic needs to be filtered, load in kernel the protocol number of traffic we are interested in
    if (is_filtered) {
        filter_map_fd = bpf_map__fd(skel->maps.filter_map);
        if (filter_map_fd == EINVAL) {
            err = 5;
            std::cerr << "Failed to get filter map file descriptor" << std::endl;
            goto cleanup_detach;
        }
        int zero = 0;
        int result = bpf_map_update_elem(filter_map_fd, &zero, &capture_filter, BPF_EXIST);
        if (result == -1) {
            err = 6;
            std::cerr << "Failed to update in-kernel traffic capture filter" << std::endl;
            goto cleanup_detach;
        }
    }

    pb_map_fd = bpf_map__fd(skel->maps.pb);
    if (pb_map_fd == EINVAL) {
        err = 7;
        std::cerr << "Failed to get perf buffer file descriptor" << std::endl;
        goto cleanup_detach;
    }

    // get perf buffer handle
    pb = perf_buffer__new(pb_map_fd, pb_per_cpu_pages, pb_sample_handler, pb_lost_handler, NULL, NULL);
    if (libbpf_get_error(pb)) {
        err = 8;
        std::cerr << "Failed to create perf buffer" << std::endl;
        goto cleanup_detach;
    }

    // register signal handlers
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    // wait for signal before start reading from perf buffer
    std::cout << "Waiting for external signal..." << std::endl;
    wait_for_signal();

    // Read samples from perf buffer
    std::cout << "Starting to read from perf buffer..." << std::endl;
    while (get_state() != 2) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);
        if (err < 0 && err != -EINTR) {
            std::cerr << "Failed to read from perf buffer: " << err << std::endl;
            goto cleanup;
        }
    }
    // print results
    end = std::chrono::system_clock::now();
    print_stats(cpu_num);

    cleanup:
    perf_buffer__free(pb);
    cleanup_detach:
    if (prog_type == "xdp") {
        bpf_xdp_detach(ifindex, 0, NULL);
    } else {
        tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id = 0;
        err = bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
        if (err) {
            std::cerr << "Failed to detach ingress TC: " << err << std::endl;
        }
        tc_opts_egress.flags = tc_opts_egress.prog_fd = tc_opts_egress.prog_id = 0;
        err = bpf_tc_detach(&tc_hook_egress, &tc_opts_egress);
        if (err) {
            std::cerr << "Failed to detach egress TC: " << err << std::endl;
        }
    }
    cleanup_skel_destroy:
    if (tc_hook_created_ingress) {
        bpf_tc_hook_destroy(&tc_hook_ingress);
    }
    if (tc_hook_created_egress) {
        bpf_tc_hook_destroy(&tc_hook_egress);
    }
    xdp_tc_bpf__destroy(skel);

    return err;
}