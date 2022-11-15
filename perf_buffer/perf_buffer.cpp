// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <mutex>
#include <condition_variable>

int cpu_num;
unsigned long long *samples = NULL;
unsigned long long *losts = NULL;
std::mutex m;
std::condition_variable cv;
int state = 0;
time_t start, end;

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    /* Ignore debug-level libbpf logs */
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
            .rlim_cur	= RLIM_INFINITY,
            .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static void sig_handler(int sig) {
    std::unique_lock<std::mutex> ul {m};
    if (state == 0) {
        start = time(NULL);
    }
    state++;
    cv.notify_all();
}

void pb_sample_handler(void *ctx, int cpu, void *data, __u32 size) {
    samples[cpu]++;
}
void pb_lost_handler(void *ctx, int cpu, __u64 count) {
    losts[cpu] += count;
}

void print_stats() {
    int i;
    unsigned long long samples_tot = 0, losts_tot = 0;
    printf("\n\t%21s%21s\n", "Samples", "Losts");
    for (i=0; i<cpu_num; i++) {
        samples_tot += samples[i];
        losts_tot += losts[i];
        printf("Core %d:\t%21llu%21llu\n", i, samples[i], losts[i]);
    }
    printf("Total:\t%21llu%21llu\n", samples_tot, losts_tot);
    time_t time = end - start;
    printf("Time:\t%21ld\n", time);
    printf("Pps:\t%21llu\n", samples_tot / time);
}

void wait_for_signal() {
    std::unique_lock<std::mutex> ul {m};

    while (state == 0) {
        cv.wait(ul);
    }
}

int main(int argc, char **argv) {
    int err;
    unsigned int pb_id, pb_fd;
    unsigned long pb_per_cpu_pages, pb_per_cpu_page_size;
    struct perf_buffer *pb = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: <prog_name> <pb_id> [<per_cpu_buffer_pages>]\n");
        return 1;
    }

    pb_id = atoi(argv[1]);
    if (!pb_id) {
        fprintf(stderr, "Failed to parse perf buffer id\n");
        return 2;
    }
    if (argc == 3) {
        pb_per_cpu_pages = atoi(argv[2]);
        if (!pb_per_cpu_pages) {
            fprintf(stderr, "Failed to parse <per_cpu_buffer_pages> parameter\n");
            return 3;
        }
    }
    else {
        pb_per_cpu_pages = 32;
    }
    pb_per_cpu_page_size = sysconf(_SC_PAGESIZE);
    printf("Per-core buffer size set to %lu bytes (pages: %lu, size: %lu)\t\n",
           pb_per_cpu_pages*pb_per_cpu_page_size, pb_per_cpu_pages, pb_per_cpu_page_size);

    cpu_num = get_nprocs();
    printf("Detected %d cpus\n", cpu_num);
    samples = (unsigned long long *) calloc(cpu_num, sizeof(unsigned long long));
    if (!samples) {
        fprintf(stderr, "Failed to allocate memory for samples accounting\n");
        return 4;
    }
    losts = (unsigned long long *) calloc(cpu_num, sizeof(unsigned long long));
    if (!losts) {
        fprintf(stderr, "Failed to allocate memory for lost samples accounting\n");
        free(samples);
        return 5;
    }

    /* Set up libbpf logging callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();

    pb_fd = bpf_map_get_fd_by_id(pb_id);
    pb = perf_buffer__new(pb_fd, pb_per_cpu_pages, pb_sample_handler, pb_lost_handler, NULL , NULL);
    if (libbpf_get_error(pb)) {
        err = 4;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    wait_for_signal();

    printf("Starting to read from perf buffer...\n");
    /* Process events */
    while (state != 2) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Failed to read from perf buffer: %d\n", err);
            break;
        }
    }
    end = time(NULL);

cleanup:
    perf_buffer__free(pb);
    print_stats();
    free(samples);
    free(losts);

    return err < 0 ? -err : 0;
}