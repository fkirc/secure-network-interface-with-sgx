#include "netutils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <errno.h>

static int interface_exists(const char* iface) {
    return if_nametoindex(iface);
}

int open_raw_socket(const char *iface) {

    if (!interface_exists(iface)) {
        DEBUG_LOG("The interface %s does not exist! Available interfaces:\n", iface);
        run_cmd("ip link");
        return -1;
    }

    int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd == -1) {
        perror("socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");
        return -1;
    }

    struct sockaddr_ll socket_address = {0};
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_ifindex = if_nametoindex(iface);
    socket_address.sll_protocol = htons(ETH_P_ALL);

    int ret = bind(raw_fd, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret) {
        perror("bind()");
        return -1;
    }

    return raw_fd;
}


int get_mac_address(const char* iface, const int raw_fd, char* mac) {

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if ((ioctl(raw_fd, SIOCGIFHWADDR, &ifr)) < 0) {
        perror("ioctl()");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}
