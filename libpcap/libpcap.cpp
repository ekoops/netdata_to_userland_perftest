#include <mutex>
#include <condition_variable>
#include <iostream>
#include <iomanip>
#include <csignal>
#include <pcap/pcap.h>

#define SNAPSHOT_LEN            65535
#define PKT_BUFFER_TIMEOUT_MS   10000
#define CAPTURE_BUFFER_SIZE     (2 << 16)

#define SET_OPTION_OR_EXIT(pcap_h, set_opt_func, opt_value, err_msg, exit_code) \
    ({                                                  \
        if (set_opt_func(pcap_h, opt_value)) {          \
            std::cerr << err_msg << std::endl;          \
            exit(exit_code);                            \
        }                                               \
    })

pcap_t *handle = NULL;

int state = 0;
std::mutex state_mutex;
std::condition_variable state_cv;

unsigned long long samples;
unsigned long long losts;
std::chrono::time_point <std::chrono::system_clock> start, end;

void pcap_set_options() {
    SET_OPTION_OR_EXIT(handle, pcap_set_snaplen, SNAPSHOT_LEN, "Failed to set the snapshot length", 101);
    SET_OPTION_OR_EXIT(handle, pcap_set_timeout, PKT_BUFFER_TIMEOUT_MS, "Failed to set the packet buffer timeout", 102);
    SET_OPTION_OR_EXIT(handle, pcap_set_buffer_size, CAPTURE_BUFFER_SIZE, "Failed to set the buffer size", 103);
}


void pcap_handler_cb(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_payload) {
    samples++;
}

static void sig_handler(int sig) {
    std::unique_lock <std::mutex> ul{state_mutex};
    if (state == 0) {
        start = std::chrono::system_clock::now();
    }
    state++;
    if (state == 2) {
        pcap_breakloop(handle);
    }
    state_cv.notify_all();
}

void wait_for_signal() {
    std::unique_lock <std::mutex> ul{state_mutex};

    while (state == 0) {
        state_cv.wait(ul);
    }
}

void print_stats() {
    auto w = std::setw(21);
    std::cout << "Total:\t" << w << samples << w << losts << std::endl;
    std::chrono::duration<double> time = end - start;
    std::cout << "Time:\t" << w << time.count() << std::endl;
    std::cout << "Pps:\t" << w << (samples / time.count()) << std::endl;
}


int main(int argc, char *argv[]) {
    int err;
    const char *err_msg;
    int exit_code = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev_name;

    if (argc < 2) {
        std::cerr << "Usage: ./<prog_name> <dev_name>" << std::endl;
        exit_code = 1;
        goto cleanup;
    }
    dev_name = argv[1];

    // init the pcap library
    err = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (err) {
        std::cerr << errbuf << std::endl;
        exit_code = 2;
        goto cleanup;
    }

    // get a packet capture handle for the specified device
    handle = pcap_create(dev_name, errbuf);
    if (!handle) {
        std::cerr << errbuf << std::endl;
        exit_code = 3;
        goto cleanup;
    }

    // set capture options
    pcap_set_options();

    // activate capture
    err = pcap_activate(handle);
    if (err) { // print error and exit if an error or a warning is returned
        err_msg = pcap_statustostr(err);
        std::cerr << err_msg << std::endl;
        exit_code = 4;
        goto cleanup;
    }

    // Register signal handlers
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    // wait for signal before start reading
    std::cout << "Waiting for external signal..." << std::endl;
    wait_for_signal();

    // start reading loop
    std::cout << "Starting to read..." << std::endl;
    err = pcap_loop(handle, -1, pcap_handler_cb, NULL);
    switch (err) {
        case PCAP_ERROR:
            err_msg = pcap_statustostr(err);
            std::cerr << err_msg << std::endl;
            exit_code = 5;
            goto cleanup;
        case PCAP_ERROR_NOT_ACTIVATED:
            std::cerr << "Error: " << err << std::endl;
            exit_code = 6;
            goto cleanup;
        default: // match if PCAP_ERROR_BREAK or 0 (0 never happen)
            end = std::chrono::system_clock::now();
            print_stats();
    }

    cleanup:
    if (handle) {
        pcap_close(handle);
    }
    return exit_code;
}