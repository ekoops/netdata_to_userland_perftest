#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <mutex>
#include <condition_variable>

#define perr(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define SNAPSHOT_LEN            65535
#define PKT_BUFFER_TIMEOUT_MS   10000
#define CAPTURE_BUFFER_SIZE     (2 << 16)

#define SET_OPTION_OR_EXIT(pcap_h, set_opt_func, opt_value, err_msg, exit_code) \
    ({                                                   \
        if (set_opt_func(pcap_h, opt_value)) {          \
            perr("%s\n", err_msg);                      \
            exit(exit_code);                            \
        }                                               \
    })


pcap_t *handle = NULL;
unsigned long long samples = 0;
unsigned long long losts = 0;
std::mutex m;
std::condition_variable cv;
int state = 0;
time_t start, end;


void pcap_set_options() {
    SET_OPTION_OR_EXIT(handle, pcap_set_snaplen, SNAPSHOT_LEN, "Failed to set the snapshot length", 101);
    SET_OPTION_OR_EXIT(handle, pcap_set_timeout, PKT_BUFFER_TIMEOUT_MS, "Failed to set the packet buffer timeout", 102);
    SET_OPTION_OR_EXIT(handle, pcap_set_buffer_size, CAPTURE_BUFFER_SIZE, "Failed to set the buffer size", 103);
}


void pcap_handler_cb(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_payload) {
    samples++;
}

static void sig_handler(int sig) {
    std::unique_lock<std::mutex> ul {m};
    if (state == 0) {
        start = time(NULL);
    }
    state++;
    cv.notify_all();
    if (state == 2) {
        pcap_breakloop(handle);
    }
}

void print_stats() {
    printf("Total:\t%21llu%21llu\n", samples, losts);
    time_t time = end - start;
    printf("Time:\t%21ld\n", time);
    printf("Pps:\t%21llu\n", samples / time);
}

void wait_for_signal() {
    std::unique_lock<std::mutex> ul {m};

    while (state == 0) {
        cv.wait(ul);
    }
}

int main(int argc, char *argv[]) {
    int err;
    const char *err_msg;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev_name;

    if (argc < 2) {
        perr("Usage: ./<prog_name> <dev_name>");
        return 1;
    }
    dev_name = argv[1];

    // init the pcap library
    err = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (err) {
        perr("%s\n", errbuf);
        return 2;
    }
    // get a packet capture handle for the specified device
    handle = pcap_create(dev_name, errbuf);
    if (!handle) {
        perr("%s\n", errbuf);
        return 3;
    }
    // set capture options
    pcap_set_options();

    // start capture
    err = pcap_activate(handle);
    if (err) { // print error and exit if an error or a warning is returned
        err_msg = pcap_statustostr(err);
        perr("%s\n", err_msg);
        pcap_close(handle);
        return 4;
    }

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    wait_for_signal();

    err = pcap_loop(handle, -1, pcap_handler_cb, NULL);
    switch (err) {
        case PCAP_ERROR:
            err_msg = pcap_statustostr(err);
            perr("%s\n", err_msg);
            return 5;
        case PCAP_ERROR_NOT_ACTIVATED:
            perr("Error: %d\n", err);
            return 6;
        default:
            end = time(NULL);
            print_stats();
            return 0;
    }
}