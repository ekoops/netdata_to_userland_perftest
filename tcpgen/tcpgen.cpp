#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

#define MAX_RETRY_ATTEMPTS  3
#define ALPHA_SIZE          63
#define ALPHA_SYMBOLS       (ALPHA_SIZE - 1)

const char alpha[ALPHA_SIZE] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/*
 * Populate the provided buffer, having size buff_size, by using (buff_size - 1) alphabet symbols starting from the
 * alpha_base_index position
 */
int populate_buffer(char *buff, uint16_t buff_size, int alpha_base_index) {
    const int buff_sz = buff_size - 1; // last is termination character '\0'
    int i, j;
    for (i = 0; i < buff_sz; i++) {
        j = (alpha_base_index + i) % ALPHA_SYMBOLS;
        buff[i] = alpha[j];
    }
    return (j + 1) % ALPHA_SYMBOLS;
}

void client_conn_handler(int connfd, uint16_t buff_sz) {
    char *buff, *buff_cur_pos;
    uint16_t buff_size;
    int attempts, written, remaining;
    int alpha_next_base_index;

    // allocate buffer (provided size + 1 in order to reserve space also for termination character '\0'
    buff_size = buff_sz + 1;
    buff = (char *) calloc(buff_size, sizeof(char));

    // populate the buffer using the alphabet symbols
    alpha_next_base_index = populate_buffer(buff, buff_size, 0);

    attempts = 0;
    buff_cur_pos = buff;
    remaining = buff_size;

    while (1) {
        written = write(connfd, buff_cur_pos, remaining);
        if (written == -1) {
            attempts++;
            if (attempts == MAX_RETRY_ATTEMPTS) {
                return;
            }
            continue;
        }
        attempts = 0;
        remaining -= written;
        if (remaining) {
            buff_cur_pos += written;
        } else {
            // reset pointers
            buff_cur_pos = buff;
            remaining = buff_size;
            alpha_next_base_index = populate_buffer(buff, buff_size, alpha_next_base_index);
        }
        sleep(1);
    }
}

void server_conn_handler(int connfd, uint16_t buff_sz) {
    char *buff, *buff_cur_pos;
    uint16_t buff_size;
    int attempts, rd, remaining;

    // allocate buffer (provided size + 1 in order to reserve space also for termination character '\0'
    buff_size = buff_sz + 1;
    buff = (char *) calloc(buff_size, sizeof(char));

    attempts = 0;
    buff_cur_pos = buff;
    remaining = buff_size;

    while (1) {
        rd = read(connfd, buff_cur_pos, remaining);
        if (rd == -1) {
            attempts++;
            if (attempts == MAX_RETRY_ATTEMPTS) {
                return;
            }
            continue;
        }
        if (rd == 0) { // EOF
            return;
        }
        attempts = 0;
        remaining -= rd;
        if (remaining) {
            buff_cur_pos += rd;
        } else {
            printf("%s\n", buff);
            // reset pointers and clean buffer
            memset(buff, 0, buff_size);
            buff_cur_pos = buff;
            remaining = buff_size;
        }
    }
}


int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr, client_addr;
    socklen_t len = sizeof(struct sockaddr_in);
    bool is_server;
    uint32_t ip;
    uint8_t *ip_ptr;
    uint16_t port;
    uint16_t buff_sz;
    int sockfd, connfd;

    if (argc < 4) {
        std::cerr << "Usage: ./<prog_name> -c|-s <ip> <port> <buff_sz>" << std::endl;
        std::exit(1);
    }

    // parse arguments
    if (!strcmp(argv[1], "-s")) {
        is_server = true;
    } else if (!strcmp(argv[1], "-c")) {
        is_server = false;
    } else {
        std::cerr << "First argument must be -c or -s";
        std::exit(2);
    }

    // parse ip
    ip_ptr = (uint8_t * ) & ip;
    if (sscanf(argv[2], "%hhd.%hhd.%hhd.%hhd", ip_ptr + 3, ip_ptr + 2, ip_ptr + 1, ip_ptr) != 4) {
        std::cerr << "Failed to parse IP address: " << argv[2] << std::endl;
        std::exit(3);
    }

    // parse port
    try {
        port = std::stoi(argv[3]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <port> parameter: " << ex.what() << std::endl;
        std::exit(5);
    }

    // parse buffer size
    try {
        buff_sz = std::stoi(argv[4]);
    } catch (std::exception const &ex) {
        std::cerr << "Failed to parse <buff_sz> parameter: " << ex.what() << std::endl;
        std::exit(6);
    }

    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        std::exit(7);
    }

    // init sockaddr_in struct for server address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(ip);
    serv_addr.sin_port = htons(port);

    if (is_server) {
        // bind newly created socket to given IP and port
        if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
            std::cerr << "Failed to bind socket" << std::endl;
            std::exit(10);

        }

        // listen on socket
        if ((listen(sockfd, 1))) {
            std::cerr << "Failed to listen on socket" << std::endl;
            std::exit(11);
        }

        // accept connection from client
        connfd = accept(sockfd, (struct sockaddr *) &client_addr, &len);
        if (connfd < 0) {
            std::cerr << "Failed to accept on socket" << std::endl;
            std::exit(12);
        }
        std::cout << "Accepted client connection" << std::endl;

        // handle connection
        server_conn_handler(connfd, buff_sz);
    } else {
        // connect client socket to server socket
        if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
            std::cout << "Failed to connect to server" << std::endl;
            std::exit(20);
        }
        std::cout << "Connected to server" << std::endl;

        // handle connection
        client_conn_handler(sockfd, buff_sz);
    }

    // close the socket
    close(sockfd);
    return 0;
}