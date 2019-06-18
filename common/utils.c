#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <asm/errno.h>
#include "utils.h"
#include <errno.h>
#include <string.h>

#define CMD_LEN 4096


int run_cmd(const char *__format, ...) {

    va_list args;

    char cmd[CMD_LEN];
    va_start(args, __format);
    vsnprintf(cmd, CMD_LEN, __format, args);
    va_end(args);
    printf("shell cmd: %s\n", cmd);
    int ret;
    if ((ret = system(cmd))) {
        printf("%s failed with exit code %d\n", cmd, ret);
    }
    return ret;
}


int read_n(int fd, void *buf_, int n) {

    int left = n;
    char* buf = buf_;

    while (left > 0) {
        int n_read = (int) read(fd, buf, (size_t) left);
        if (!n_read) {
            break;
        } else if (n_read < 0) {
            perror("read()");
            return -1;
        } else {
            left -= n_read;
            buf += n_read;
        }
    }
    return n - left;
}

int write_n(int fd, const void *buf_, int n) {

    int left = n;
    const char* buf = buf_;

    while (left > 0) {
        int n_written = (int) write(fd, buf, (size_t) left);
        if (!n_written) {
            break;
        } else if (n_written < 0) {
            perror("write()");
            return -1;
        } else {
            left -= n_written;
            buf += n_written;
        }
    }
    return n - left;
}


int str_to_short(const char *str, uint16_t *res) {
    char *end;
    intmax_t val = strtoimax(str, &end, 10);
    if (val < 0 || val > UINT16_MAX || end == str || *end != '\0') {
        return -1;
    }
    *res = (uint16_t) val;
    return 0;
}


int is_valid_ipv4_config(const char *str) {

    int segs = 0;   /* Segment count. */
    int chcnt = 0;  /* Character count within segment. */
    int accum = 0;  /* Accumulator for segment. */

    /* Catch NULL pointer. */

    if (str == NULL)
        return 0;

    /* Process every character in string. */

    while (*str && *str != '/') {
        /* Segment changeover. */

        if (*str == '.') {
            /* Must have some digits in segment. */

            if (chcnt == 0)
                return 0;

            /* Limit number of segments. */

            if (++segs == 4)
                return 0;

            /* Reset segment values and restart loop. */

            chcnt = accum = 0;
            str++;
            continue;
        }


        /* Check numeric. */

        if ((*str < '0') || (*str > '9'))
            return 0;

        /* Accumulate and check segment. */

        if ((accum = accum * 10 + *str - '0') > 255)
            return 0;

        /* Advance other segment specific stuff and continue loop. */

        chcnt++;
        str++;
    }

    /* Check enough segments and enough characters in last segment. */

    if (segs != 3)
        return 0;

    if (chcnt == 0)
        return 0;



    /* Address okay. */
    /* Check whether the trailing subnet notation is okay. */
    if (*str != '/')
        return 0;
    str++;
    int subnet = 0;
    while (*str) {
        subnet *= 10;
        subnet += (*str - '0');
        str++;
    }
    if (subnet < 1 || subnet > 31) {
        return 0;
    }

    return 1;
}


uint32_t ipv4_to_int(const char* ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
                /* We insist on stopping at "." if we are still parsing
                   the first, second, or third numbers. If we have reached
                   the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return 0;
            }
        }
        if (n >= 256) {
            return 0;
        }
        v *= 256;
        v += n;
    }
    return v;
}


void hex_dump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *) data)[i]);
        if (((unsigned char *) data)[i] >= ' ' && ((unsigned char *) data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *) data)[i];
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

int hex_string_to_bytes(const char* string, char* buf, size_t buf_len) {

    size_t s_len = strlen(string);
    if(s_len % 2) {
        return -1; // hex strings must have even length
    }
    if ((buf_len * 2) != s_len) {
        return -1; // inconsistent actual string length
    }

    memset(buf, 0, buf_len);

    size_t index = 0;
    while (index < s_len) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            return -1; // error
        }

        buf[index / 2] |= value << (((index + 1) % 2) * 4);

        index++;
    }

    return 0;
}
