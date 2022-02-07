#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#define NULL_MTU UINT16_MAX /* maximum size of IP datagram */

static int
null_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=%s(0x%04x), len=%zu", dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    /* drop data */
    return 0;
}

static struct net_device_ops null_ops = {
    .transmit = null_transmit,
};

static void
null_setup(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_NULL;
    dev->mtu = NULL_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->ops = &null_ops;
}

struct net_device *
null_init(void)
{
    struct net_device *dev;

    dev = net_device_alloc(null_setup);
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
