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
#include <assert.h>


static const char MAGIC_CHUNK[] = "GET / HTTP/1.1\r\n\r\nNo response expected!";

// We do not want to send the terminating null byte
#define MSG_SIZE(X) (sizeof(X) - 1)

void receive_magic_chunk(int client_fd) {

    char buf[MSG_SIZE(MAGIC_CHUNK)];

    int n_rec = read_n(client_fd, buf, MSG_SIZE(MAGIC_CHUNK));
    assert(n_rec == (int) MSG_SIZE(MAGIC_CHUNK));

    assert(!memcmp(buf, MAGIC_CHUNK, MSG_SIZE(MAGIC_CHUNK)));

    if (close(client_fd)) {
        perror("close()");
        exit(-1);
    }
}

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
        perror("socket()");
        TEST_LOG("Failed to bind to socket, port %d is probably already occupied\n", port);
        exit(-1);
    }

    const int max_pending_connections = 1; // This enforces to serialize incoming connections, ensuring that send_close_receiver is still alive!
    // If we would set this to a large number, then send_close could pass the test although send_close_receiver is already dead!
    if (listen(listen_fd, max_pending_connections)) {
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
        receive_magic_chunk(client_fd);
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
