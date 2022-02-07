#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

#include "loopback.h"

#define LOOPBACK_MTU UINT16_MAX /* maximum size of IP datagram */

static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=%s(0x%04x), len=%zu", dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    net_input_handler(type, data, len, dev);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

static void
loopback_setup(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;
}

struct net_device *
loopback_init(void)
{
    struct net_device *dev;

    dev = net_device_alloc(loopback_setup);
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
