#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int
ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return  0;
}

char *
ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p) {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

static void
ether_dump(const uint8_t *frame, size_t flen)
{

}

int
ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ssize_t (*callback)(struct net_device *dev, const uint8_t *data, size_t len))
{

}

int
ether_poll_helper(struct net_device *dev, ssize_t (*callback)(struct net_device *dev, uint8_t *buf, size_t size))
{

}

void
ether_setup_helper(struct net_device *dev)
{

}
