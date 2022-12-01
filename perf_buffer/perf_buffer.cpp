// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <vector>
#include <iomanip>
#include <thread>
#include <csignal>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include ".output/perf_buffer.skel.h"

int state = 0;
std::mutex state_mutex;
std::condition_variable state_cv;

std::vector<unsigned long long> samples;
std::vector<unsigned long long> losts;
std::chrono::time_point<std::chrono::system_clock> start, end;

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
    int ifindex;
    unsigned long pb_per_cpu_pages, pb_per_cpu_page_size;
    int cpu_num;
    struct perf_buffer_bpf *skel;
    unsigned int pb_prog_fd, pb_map_fd;
    struct perf_buffer *pb = NULL;

    if (argc > 3) {
        std::cerr << "Usage: ./<prog_name> <ifindex> [<per_cpu_buffer_pages>]" << std::endl;
        return 1;
    }

    // parsing arguments
    try {
        ifindex = std::stoi(argv[1]);
    } catch (std::exception const& ex) {
        std::cerr << "Failed to parse <ifindex> parameter: " << ex.what() << std::endl;
        return 2;
    }
    try {
        pb_per_cpu_pages = (argc == 3) ? std::stoi(argv[2]) : 8;
    } catch (std::exception const& ex) {
        std::cerr << "Failed to parse <per_cpu_buffer_pages> parameter: " << ex.what() << std::endl;
        return 2;
    }

    // get some environment information
    pb_per_cpu_page_size = sysconf(_SC_PAGESIZE);
    cpu_num = std::thread::hardware_concurrency();;
    std::cout << "Per-core buffer size set to " << pb_per_cpu_pages * pb_per_cpu_page_size << " bytes (pages: " <<
        pb_per_cpu_pages << ", size: " << pb_per_cpu_page_size << ")\nDetected " << cpu_num << " cpus" << std::endl;

    try {
        samples = std::vector<unsigned long long>(cpu_num);
        losts = std::vector<unsigned long long>(cpu_num);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to allocate counters: " << ex.what() << std::endl;
        return 3;
    }

    // set up libbpf logging callback
    libbpf_set_print(libbpf_print_fn);
    // set up BPF strict mode
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // bump RLIMIT_MEMLOCK to create BPF maps
    bump_memlock_rlimit();

    // open and load the skeleton
    skel = perf_buffer_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open skeleton" << std::endl;
        return 5;
    }
    pb_prog_fd = bpf_program__fd(skel->progs.xdp_probe_f);
    if (pb_prog_fd == EINVAL) {
        std::cerr << "Failed to get XDP program file descriptor" << std::endl;
        goto cleanup_skel_destroy;
    }

    // attach XDP program to the interface corresponding to the provided ifindex
    err = bpf_xdp_attach(ifindex, pb_prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        std::cerr << "Failed to attach XDP program" << std::endl;
        goto cleanup_skel_destroy;
    }

    pb_map_fd = bpf_map__fd(skel->maps.pb);
    if (pb_map_fd == EINVAL) {
        std::cerr << "Failed to get perf buffer file descriptor" << std::endl;
        goto cleanup_xdp_detach;
    }

    // get perf buffer handle
    pb = perf_buffer__new(pb_map_fd, pb_per_cpu_pages, pb_sample_handler, pb_lost_handler, NULL, NULL);
    if (libbpf_get_error(pb)) {
        std::cerr << "Failed to create perf buffer" << std::endl;
        goto cleanup_xdp_detach;
    }

    // Register signal handlers
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
    cleanup_xdp_detach:
    bpf_xdp_detach(ifindex, 0, NULL);
    cleanup_skel_destroy:
    perf_buffer_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}