#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define NULL_MTU UINT16_MAX /* maximum size of IP datagram */

static int
null_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{

}

static struct net_device_ops null_ops = {
    .transmit = null_transmit,
};

struct net_device *
null_init(void)
{

}
