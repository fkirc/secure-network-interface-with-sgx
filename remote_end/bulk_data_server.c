#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include "../common/utils.h"
#include <getopt.h>
#include <inttypes.h>
#include <assert.h>


#define BUF_SIZE 10000000 // Maximum 10 MB request-response
static uint8_t rec_buf[BUF_SIZE] = {0};

static void serve_respond(int client_fd);

static uint16_t port = 0;

static void run_server() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd == -1) {
        perror("socket()");
        exit(-1);
    }

    // Set the SO_REUSEADDR option to enable fast server restarts
    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse))) {
        perror("setsockopt(SO_REUSEADDR)");
        exit(-1);
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *) &server, sizeof(server))) {
        perror("bind()");
        TEST_LOG("Failed to bind to socket, port %d is probably already occupied\n", port);
        exit(-1);
    }

    if (listen(listen_fd, 1000)) {
        perror("listen()");
        exit(-1);
    }

    TEST_LOG("Waiting for incoming connections on port %d...\n", port);

    struct sockaddr_in client_addr = {0};
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        int client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept()");
            exit(-1);
        }
        serve_respond(client_fd);
        if (close(client_fd)) {
	    perror("close()");
	    exit(-1);
        }
    }
}


static void serve_respond(int client_fd) {

    int n_rec = read(client_fd, rec_buf, sizeof(size_t));
    if (n_rec != sizeof(size_t)) {
	DEBUG_LOG("Error - received %d bytes\n", n_rec);
        return;
    }
    const size_t stream_size = *((size_t*)rec_buf);
    size_t to_receive = stream_size;
    while (to_receive) {
        n_rec = read(client_fd, rec_buf, to_receive);
        if (n_rec == -1) {
	    DEBUG_LOG("Connection to client lost\n");
            return;
        }
        if (!n_rec) {
            DEBUG_LOG("Error - read zero bytes\n");
            return;
        }
        to_receive -= n_rec;
    }
    int n_write = write(client_fd, &stream_size, sizeof(size_t));
    if (n_write < 0) {
        DEBUG_LOG("Send failed\n");
    } else if (n_write != sizeof(size_t)) {
        DEBUG_LOG("Wrong number of bytes sent\n");
    }
}


static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s --port <port_to_listen>\n", prog_name);
    exit(-1);
}

int main(int argc, char **argv) {
    int arg_cnt = 0;
    while (1) {
        static struct option options[] = {
                {"port", required_argument, 0, 'p'},
                {0,      0,                 0, 0}};
        int option_index = 0;
        int c = getopt_long(argc, argv, "p:", options, &option_index);
        if (c < 0) {
            break;
        }
        arg_cnt++;
        switch (c) {
            case 'p':
                if (str_to_short(optarg, &port)) {
                    printf("Invalid port\n");
                    exit(-1);
                }
                break;
            default:
                usage(argv[0]);
        }
    }
    if (arg_cnt != 1) {
        usage(argv[0]);
    }

    run_server();
    return 0;
}

