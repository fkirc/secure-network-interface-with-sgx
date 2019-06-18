#include "netutils_t.h"
#include "../packet_validation/edl_types.h"
#include "tcp_validation.h"


int is_ether_type(const void* packet, uint16_t ether_type) {
    const struct ether_header* e = packet;
    if (e->ether_type == ether_type) {
        return 1;
    }
    return 0;
}


uint32_t htonl(uint32_t hostlong) {
    char* little_end = (char*)&hostlong;
    uint32_t netlong;
    char* big_end = (char*)&netlong;
    big_end[0] = little_end[3];
    big_end[1] = little_end[2];
    big_end[2] = little_end[1];
    big_end[3] = little_end[0];
    return netlong;
}

uint32_t ntohl(uint32_t val) {
    return htonl(val);
}


uint16_t ntohs(uint16_t val) {
    return (uint16_t)(val >> 8) | (uint16_t)(val << 8);
}


static void reverse(char* str, int length) {
    int start = 0;
    int end_ = length -1;
    while (start < end_) {
        char tmp = *(str+start);
        *(str+start) = *(str+end_);
        *(str+end_) = tmp;
        start++;
        end_--;
    }
}


static char* append_byte_string(uint8_t num, char* str) {
    const uint8_t base = 10;
    int i = 0;

    if (num == 0) {
        str[i++] = '0';
        str[i] = 0;
        return str + i;
    }

    while (num != 0) {
        uint8_t rem = num % base;
        str[i++] = (char) ((rem > 9) ? (rem - 10) + 'a' : rem + '0');
        num = num / base;
    }

    str[i] = 0;
    reverse(str, i);
    return str + i;
}


static char global_ip_string[200] = {0};

const char* inet_ntoa_t(uint32_t ipv4) {
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(ipv4 & 0xFF);
    bytes[1] = (uint8_t)((ipv4 >> 8) & 0xFF);
    bytes[2] = (uint8_t)((ipv4 >> 16) & 0xFF);
    bytes[3] = (uint8_t)((ipv4 >> 24) & 0xFF);

    char* str = append_byte_string(bytes[3], global_ip_string);
    *str = '.';
    str = append_byte_string(bytes[2], str + 1);
    *str = '.';
    str = append_byte_string(bytes[1], str + 1);
    *str = '.';
    append_byte_string(bytes[0], str + 1);
    return global_ip_string; // This is not thread-safe
}


void ehex_dump(const void *data, size_t size) {
    unsigned char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((const unsigned char *) data)[i]);
        if (((const unsigned char *) data)[i] >= ' ' && ((const unsigned char *) data)[i] <= '~') {
            ascii[i % 16] = ((const unsigned char *) data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}
