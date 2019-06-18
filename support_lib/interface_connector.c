#include "../common/netutils.h"
#include "../common/tcp_definitions.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <x86intrin.h>
#include "../tests/test_app/test_enclave_u.h"
#include "../common/key_file_definitions.h"
#include "interface_connector.h"

#define RANDOM_PACKET_DROP_N 10

static int random_drop_enabled = 0;
void enable_random_packet_dropping(int enable) {
    random_drop_enabled = enable;
}

static int sgx_enabled = 1;
void enable_sgx(int enable) {
    sgx_enabled = enable;
}

static int raw_macsec_enabled = 0;
void enable_raw_macsec(int enable) {
    raw_macsec_enabled = enable;
}

static int raw_sgx_enabled = 0;
void enable_raw_sgx(int enable) {
    raw_sgx_enabled = enable;
}

static int random_packet_drop() {
    if (!random_drop_enabled) {
        return 0; // do not drop
    }
    uint64_t cycles = __rdtsc();
    if (cycles % RANDOM_PACKET_DROP_N == 0) {
        return 1; // drop
    }
    return 0; // do not drop
}
const char *VIRTUAL_ENCLAVE_INTERFACE = "tap_enclave";

static int raw_fd = -1;
static int tap_fd = -1;
static int packet_number_fd = -1;
static uint32_t packet_number = -1;
static pthread_t tid_raw_to_tap = {0};
static pthread_t tid_tap_to_raw = {0};
static sgx_enclave_id_t enclave_id = {0};


static int load_packet_number() {

    if (!sgx_enabled) {
        return 0;
    }

    const char packet_number_file[] = "macsec_next_packet_number.bin";

    packet_number_fd = open(packet_number_file, O_RDWR | O_CREAT);
    if (packet_number_fd < 0) {
        perror("open(packet_number_file)");
        return -1;
    }

    packet_number = 1; // start at packet number 1 if there is no previous packet number stored
    int n_read = read(packet_number_fd, &packet_number, sizeof(packet_number));
    if (n_read != 0 && n_read != sizeof(packet_number)) {
        perror("read(packet_number_fd)");
        return -1;
    }
    return 0;
}


static int setup_tap_interface(const char *tap_dev, const char *trusted_dev, const char *ip_config) {
    /**************************************************************************/
    // Instead of issuing loads of obscure ioctl's for the interface creation and configuration, we use the ip command.
    // The ip command makes it easier for developers and users to review/change/reproduce the interface configuration.

    /**************************************************************************/
    // Check whether the tap interface is already existing. Create it if not.
    int ret = run_cmd("ip link show %s", tap_dev);
    if (ret) {
        // tap interface does not exist yet, create it
        if (run_cmd("ip tuntap add mode tap %s", tap_dev)) {
            return -1;
        }
        DEBUG_LOG("Created tap interface %s\n", tap_dev);
    } else {
        DEBUG_LOG("tap interface %s is already existing\n", tap_dev);
    }

    /**************************************************************************/
    // The tap interface needs to have the same mac address as the trusted physical interface to make arp work seamlessly
    if (run_cmd("ip link set addr `cat /sys/class/net/%s/address` dev %s", trusted_dev, tap_dev)) {
        DEBUG_LOG("Failed to configure MAC address of tap interface\n");
        return -1;
    }

    /**************************************************************************/
    // Set the interface flag UP to make the interface visible.
    // This does not actually set it to UP, since there no "carrier" attached yet.
    if ((run_cmd("ip link set dev %s up", tap_dev))) {
        return -1;
    }

    /**************************************************************************/
    // Since we want to route the traffic via the tap interface, we may need to remove the ip address from the trusted physical interface
    if ((run_cmd("ip addr flush dev %s", trusted_dev))) {
        return -1;
    }

    /**************************************************************************/
    // Configure an ipv4 address for the tap interface. Clear addresses in case that there are previous addresses set.
    if ((run_cmd("ip addr flush dev %s", tap_dev))) {
        return -1;
    }

    if ((run_cmd("ip addr add %s dev %s", ip_config, tap_dev))) {
        return -1;
    }

    /**************************************************************************/
    // Attach this process to the tap interface, which is done by an ioctl on a "clone device" file descriptor.
    // This sets the interface to the actual UP state, enabling packets to be sent and received.
    // Note that there can only be at most one process attached to a tap interface.
    const char *clone_dev = "/dev/net/tun";

    if ((tap_fd = open(clone_dev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return tap_fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tap_dev, IFNAMSIZ);

    // Configure the interface to be a tun interface. This ioctl associates this process with the tap interface.
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    int err;
    if ((err = ioctl(tap_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        DEBUG_LOG(
                "There can be only at most one process attached to the tap interface %s! Probably you already have an instance of this program running.\n",
                tap_dev);
        close(tap_fd);
        return err;
    }

    return 0;
}


static int is_macsec_fast_check(const void* buf, size_t len) {
    if (len < MIN_MACSEC_LEN) {
        return 0;
    }
    const struct ethhdr* e = buf;
    if (e->h_proto == ETHER_TYPE_MACSEC) {
        return 1;
    }
    return 0;
}


static uint16_t checksum(const void *buf, size_t size)
{
    const uint16_t* wbuf = buf;
    uint32_t sum = 0;
    while(size > 1) {
        sum += *wbuf++;
        size -= sizeof(uint16_t);
    }
    if(size) {
        sum += *(uint8_t*)wbuf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

struct checksum_hdr {
    uint32_t daddr;
    uint32_t saddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t ip_payload_len;
} __attribute__((packed));


static int fix_tcp_udp_checksum(void* buf, const size_t len)
{
    if (len < sizeof(struct ipv4_packet)) {
        return 0;
    }
    struct ipv4_packet* p = buf;
    if (p->ether.ether_type != ETHER_TYPE_IPV4) {
        return 0;
    }

    uint16_t* checksum_ptr = 0;
    size_t min_len = 0;
    if (p->ip.proto == IP_PROTO_TCP) {
        checksum_ptr = &((struct tcp_packet*)buf)->tcp.check;
        min_len = sizeof(struct tcp_packet);
    } else if (p->ip.proto == IP_PROTO_UDP) {
        checksum_ptr = &((struct udp_packet*)buf)->udp.check;
        min_len = sizeof(struct udp_packet);
    } else {
        return 0;
    }
    if (len < min_len) {
        return 0;
    }

    char check_buf[65536];
    const size_t ip_payload_len = len - sizeof(struct ipv4_packet);
    struct checksum_hdr* chdr = (struct checksum_hdr*)check_buf;
    chdr->daddr = p->ip.daddr;
    chdr->saddr = p->ip.saddr;
    chdr->reserved = 0;
    chdr->proto = p->ip.proto;
    chdr->ip_payload_len = htons(ip_payload_len);

    const uint32_t old_checksum = *checksum_ptr;
    *checksum_ptr = 0;
    assert((sizeof(struct checksum_hdr) + ip_payload_len) <= sizeof(check_buf));
    memcpy(check_buf + sizeof(struct checksum_hdr), (char*)buf + sizeof(struct ipv4_packet), ip_payload_len);

    const size_t new_checksum = checksum(check_buf, sizeof(struct checksum_hdr) + ip_payload_len);
    *checksum_ptr = new_checksum;
    if (old_checksum != new_checksum) {
        return -1; // Invalid checksum fixed
    }
    return 0;
}


static ssize_t tap_to_raw_packet(void* buf, ssize_t* packet_len, const size_t buf_len) {
    assert((size_t)*packet_len <= buf_len);

    if (!sgx_enabled) {
        return 0; // Forward everything without checks if SGX is disabled
    }

    int ret_val = -1;
    sgx_status_t ret_state = -1;
    if (raw_macsec_enabled) {
        ret_state = ecall_macsec_raw_authenticate(enclave_id, &ret_val, buf, *packet_len, buf_len, packet_number);
    } else if (raw_sgx_enabled) {
        ret_state = ecall_raw_packet_copy(enclave_id, &ret_val, buf, *packet_len, buf_len);
    } else {
        ret_state = ecall_authenticate_outgoing_packet(enclave_id, &ret_val, buf, *packet_len, buf_len, packet_number);
    }
    if (ret_state != SGX_SUCCESS) {
        DEBUG_LOG("Failed to perform outgoing packet authentication ECALL. Enclave is not running (anymore)?\n");
        exit(-1);
    }

    if (ret_val) {
        //DEBUG_LOG("Outgoing packet validation failed, drop packet\n");
        return -1;
    }

    if (random_packet_drop()) {
        DEBUG_LOG("Random drop outgoing packet\n");
        return -1;
    }

    if (is_macsec_fast_check(buf, *packet_len + MACSEC_OVERHEAD)) {
        *packet_len += MACSEC_OVERHEAD;
        packet_number++;
        if (lseek(packet_number_fd, 0, SEEK_SET)) {
            perror("lseek(packet_number_fd)");
            exit(-1);
        }
        if (write(packet_number_fd, &packet_number, sizeof(packet_number)) != sizeof(packet_number)) {
            perror("write(packet_number_fd)");
            exit(-1);
        }
    }

    return 0;
}


void *thread_tap_to_raw_sock(void *ignored) {
    (void) (ignored);
    
    char buf[MAX_PACK_SIZE];
    memset(&buf, 0, sizeof(buf));

    while (1) {

        ssize_t packet_len = read(tap_fd, &buf, sizeof(buf));
        if (packet_len == -1) {
            perror("tap_fd receive");
            exit(-1);
        }
        
        if (tap_to_raw_packet(buf, &packet_len, sizeof(buf))) {
            continue; // Drop
        }

        ssize_t n_sent = send(raw_fd, &buf, packet_len, 0);
        if (n_sent == -1) {
            perror("raw_fd send");
            exit(-1);
        } else if (n_sent != packet_len) {
            DEBUG_LOG("tap_to_raw_sock: mismatch of received and sent bytes, exit app!\n");
            exit(-1);
        }
    }
}

int raw_sock_to_tap_packet(void* buf, ssize_t* packet_len, const size_t buf_len) {
    assert((size_t)*packet_len <= buf_len);

    if (!sgx_enabled) {
        return 0; // Forward everything if SGX is disabled
    }

    if (random_packet_drop()) {
        DEBUG_LOG("Random drop incoming packet\n");
        return -1;
    }

    ssize_t new_packet_len = *packet_len;
    if (is_macsec_fast_check(buf, *packet_len)) {
        new_packet_len -= MACSEC_OVERHEAD;
    }

    int ret_val = -1;
    sgx_status_t ret_state = -1;
    if (raw_macsec_enabled) {
        ret_state = ecall_macsec_raw_verify(enclave_id, &ret_val, buf, *packet_len, buf_len);
    } else if (raw_sgx_enabled) {
        ret_state = ecall_raw_packet_copy(enclave_id, &ret_val, buf, *packet_len, buf_len);
    } else {
        ret_state = ecall_verify_incoming_packet(enclave_id, &ret_val, buf, *packet_len, buf_len);
    }
    if (ret_state != SGX_SUCCESS) {
        DEBUG_LOG("Failed to perform incoming packet verification ECALL. Enclave is not running (anymore)?\n");
        exit(-1);
    }

    if (ret_val) {
        //DEBUG_LOG("Incoming packet validation failed, drop packet\n");
        return -1;
    }

    *packet_len = new_packet_len;
    return 0;
}

void *thread_raw_sock_to_tap(void *ignored) {
    (void) (ignored);
    char buf[MAX_PACK_SIZE];

    memset(&buf, 0, sizeof(buf));

    while (1) {

        ssize_t packet_len = recv(raw_fd, &buf, sizeof(buf), 0);
        if (packet_len == -1) {
            perror("raw_fd receive");
            exit(-1);
        }

        if (raw_sock_to_tap_packet(buf, &packet_len, sizeof(buf))) {
            continue; // Drop
        }
        // The incoming TCP/UDP checksum may be broken due to "checksum offloading" from a veth interface.
        // We only have to check it for incoming packets,
        // but not for packets that originate from the TAP interface.
        fix_tcp_udp_checksum(buf, packet_len);

        ssize_t n_sent = write(tap_fd, &buf, packet_len);
        if (n_sent == -1) {
            perror("tap_fd send");
            exit(-1);
        } else if (n_sent != packet_len) {
            DEBUG_LOG("raw_sock_to_tap: mismatch of received and sent bytes, exit app!\n");
            exit(-1);
        }
    }
}


static char* get_sealed_key_path() {
    char* path = getenv("MACSEC_SEALED_KEY_FILE");
    if (!path) {
        printf("Error: MACSEC_SEALED_KEY_FILE is not set, cannot find a sealed key file\n");
        exit(-1);
    }
    return path;
}


int load_macsec_keys(sgx_enclave_id_t eid) {

    const char* sealed_key_file = get_sealed_key_path();

    int fd = open(sealed_key_file, O_RDONLY);
    if (fd < 0) {
        perror("open()");
        printf("Failed to open the sealed key file \"%s\"\n", sealed_key_file);
        return -1;
    }
    char sealed_keys[10000] = {0};
    int sealed_keys_len = read(fd, sealed_keys, sizeof(sealed_keys));
    if (sealed_keys_len < 0) {
        perror("read()");
        return -1;
    }
    if (close(fd)) {
        perror("close()");
        return -1;
    }

    int ret_val = -1;
    sgx_status_t ret_state = ecall_load_macsec_keys(eid, &ret_val, sealed_keys, sealed_keys_len);
    assert(ret_state == SGX_SUCCESS);
    if (ret_val) {
        printf("The enclave rejected the sealed key file \"%s\" with error code %d\n", sealed_key_file, ret_val);
        return -1;
    }

    return 0;
}



int launch_trusted_interface(const char *trusted_iface, const char *ip_config, const sgx_enclave_id_t eid) {

    /**************************************************************************/
    // Ensure that the given enclave is already running
    if (sgx_enabled) {
        if (ecall_authenticate_outgoing_packet(eid, 0, 0, 0, 0, 0) != SGX_SUCCESS) {
            DEBUG_LOG("Invalid enclave id (enclave not running?)\n");
            return -1;
        }
        enclave_id = eid;
    }

    /**************************************************************************/
    // Setup the interface configuration
    raw_fd = open_raw_socket(trusted_iface);
    if (raw_fd == -1) {
        DEBUG_LOG("Failed to open raw socket\n");
        return -1;
    }

    if (setup_tap_interface(VIRTUAL_ENCLAVE_INTERFACE, trusted_iface, ip_config)) {
        DEBUG_LOG("Failed to setup the tap interface\n");
        return -1;
    }

    /**************************************************************************/
    // The last outgoing packet number is needed for the outgoing MACSec replay protection
    if (load_packet_number()) {
        return -1;
    }

    /**************************************************************************/
    // Launch the packet forwarding threads
    if (pthread_create(&tid_tap_to_raw, 0, &thread_tap_to_raw_sock, 0)) {
        perror("pthread_create(tid_tap_to_raw)");
        return -1;
    }
    if (pthread_create(&tid_raw_to_tap, 0, &thread_raw_sock_to_tap, 0)) {
        perror("pthread_create(tid_raw_to_tap)");
        return -1;
    }

    return 0;
}


// Performs a graceful shutdown of the trusted interface, cancelling threads and closing file descriptors
int shutdown_trusted_interface(void) {

    if (pthread_cancel(tid_tap_to_raw)) {
        perror("pthread_cancel(tid_tap_to_raw)");
        return -1;
    }
    if (pthread_cancel(tid_raw_to_tap)) {
        perror("pthread_cancel(tid_raw_to_tap)");
        return -1;
    }

    if (pthread_join(tid_tap_to_raw, 0)) {
        perror("pthread_join(tid_tap_to_raw)");
        return -1;
    }
    if (pthread_join(tid_raw_to_tap, 0)) {
        perror("pthread_join(tid_raw_to_tap)");
        return -1;
    }

    if (close(raw_fd)) {
        perror("close(raw_fd)");
        return -1;
    }
    if (close(tap_fd)) {
        perror("close(tap_fd)");
        return -1;
    }

    if (sgx_enabled && close(packet_number_fd)) {
        perror("close(packet_number_fd)");
        return -1;
    }

    return 0;
}
