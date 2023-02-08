#include <mutex>
#include <condition_variable>
#include <iostream>
#include <iomanip>
#include <csignal>
#include <pcap/pcap.h>
#include <process_state.h>
#include "PacketHandler.h"

#define SNAPSHOT_LEN            65535
#define PKT_BUFFER_TIMEOUT_MS   10000
#define CAPTURE_BUFFER_SIZE     (2 << 16)

#define SET_OPTION_OR_EXIT(pcap_h, set_opt_func, opt_value, err_msg, exit_code) \
    ({                                                  \
        if (set_opt_func(pcap_h, opt_value)) {          \
            std::cerr << err_msg << std::endl;          \
            std::exit(exit_code);                       \
        }                                               \
    })

pcap_t *handle = NULL;

process_state proc_state {};
unsigned long long samples, losts;

void pcap_set_options() {
    SET_OPTION_OR_EXIT(handle, pcap_set_snaplen, SNAPSHOT_LEN, "Failed to set the snapshot length", 101);
    SET_OPTION_OR_EXIT(handle, pcap_set_timeout, PKT_BUFFER_TIMEOUT_MS, "Failed to set the packet buffer timeout", 102);
    SET_OPTION_OR_EXIT(handle, pcap_set_buffer_size, CAPTURE_BUFFER_SIZE, "Failed to set the buffer size", 103);
}


void pcap_handler_cb(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_payload) {
//    PacketHandler *packet_handler = (PacketHandler *) user;
//    packet_handler->handle(pkt_payload, pkt_hdr->caplen, pkt_hdr->ts);
    samples++;
}

static void sig_handler(int sig) {
    proc_state.signal([](){ pcap_breakloop(handle); });
}

void print_stats() {
    auto w = std::setw(21);
    std::cout << "Total:\t" << w << samples << w << losts << std::endl;
    std::chrono::duration<double> time = proc_state.get_time();
    std::cout << "Time:\t" << w << time.count() << std::endl;
    std::cout << "Pps:\t" << w << (samples / time.count()) << std::endl;
}


int main(int argc, char *argv[]) {
    int err;
    const char *err_msg;
    int exit_code = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_program;
    char *filter_expr = NULL;
    char *dev_name;

    // create connections manager and packet handler
    TcpReassemblyConnMgr conn_mgr;
    PacketHandler packet_handler {&conn_mgr};

    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: ./<prog_name> <dev_name> [<capture_filter>]" << std::endl;
        exit_code = 1;
        goto cleanup;
    }
    dev_name = argv[1];

    if (argc == 3) { // capture filter is provided
        filter_expr = argv[2];
    }

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

    if (filter_expr) {
        // set capture filter
        err = pcap_compile(handle, &filter_program,  filter_expr, 0, PCAP_NETMASK_UNKNOWN);
        if (err) {
            err_msg = pcap_statustostr(err);
            std::cerr << err_msg << std::endl;
            exit_code = 4;
            goto cleanup;
        }
        err = pcap_setfilter(handle, &filter_program);
        if (err) {
            err_msg = pcap_statustostr(err);
            std::cerr << err_msg << std::endl;
            exit_code = 4;
            goto cleanup;
        }
    }

    // register signal handlers
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    // wait for signal before start reading
    std::cout << "Waiting for external signal..." << std::endl;
    proc_state.wait();

    // start reading loop
    std::cout << "Starting to read..." << std::endl;
    err = pcap_loop(handle, -1, pcap_handler_cb, (u_char *) &packet_handler);
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
            print_stats();
    }

    cleanup:
    if (handle) {
        pcap_close(handle);
    }
    return exit_code;
}