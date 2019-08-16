#include <stdint.h>
#include <stdlib.h>
#include "util.h"
#include "net.h"

struct netdev_driver {
    struct netdev_driver *next;
    uint16_t type;
    uint16_t mtu;
    uint16_t flags;
    uint16_t hlen;
    uint16_t alen;
    struct netdev_ops *ops;
};

struct netdev_proto {
    struct netdev_proto *next;
    uint16_t type;
    void (*handler)(uint8_t *packet, size_t plen, struct netdev *dev);
};

static struct netdev_driver *drivers;
static struct netdev_proto *protos;
static struct netdev *devices;

int
netdev_driver_register (struct netdev_def *def) {
    struct netdev_driver *entry;

    for (entry = drivers; entry; entry = entry->next) {
        if (entry->type == def->type) {
            return -1;
        }
    }
    entry = malloc(sizeof(struct netdev_driver));
    if (!entry) {
        return -1;
    }
    entry->next = drivers;
    entry->type = def->type;
    entry->mtu = def->mtu;
    entry->flags = def->flags;
    entry->hlen = def->hlen;
    entry->alen = def->alen;
    entry->ops = def->ops;
    drivers = entry;
    return 0;
}

int
netdev_proto_register (unsigned short type, void (*handler)(uint8_t *packet, size_t plen, struct netdev *dev)) {
    struct netdev_proto *entry;

    for (entry = protos; entry; entry = entry->next) {
        if (entry->type == type) {
            return -1;
        }
    }
    entry = malloc(sizeof(struct netdev_proto));
    if (!entry) {
        return -1;
    }
    entry->next = protos;
    entry->type = type;
    entry->handler = handler;
    protos = entry;
    return 0;
}

struct netdev *
netdev_root (void) {
    return devices;
}

static void
netdev_rx_handler (struct netdev *dev, uint16_t type, uint8_t *packet, size_t plen) {
    struct netdev_proto *entry;

    for (entry = protos; entry; entry = entry->next) {
        if (hton16(entry->type) == type) {
            entry->handler(packet, plen, dev);
            return;
        }
    }
}

struct netdev *
netdev_alloc (uint16_t type) {
    struct netdev_driver *driver;
    struct netdev *dev;

    for (driver = drivers; driver; driver = driver->next) {
        if (driver->type == type) {
            break;
        }
    }
    if (!driver) {
        return NULL;
    }
    dev = malloc(sizeof(struct netdev));
    if (!dev) {
        return NULL;
    }
    dev->next = devices;
    dev->ifs = NULL;
    dev->type = driver->type;
    dev->mtu = driver->mtu;
    dev->flags = driver->flags;
    dev->hlen = driver->hlen;
    dev->alen = driver->alen;
    dev->rx_handler = netdev_rx_handler;
    dev->ops = driver->ops;
    devices = dev;
    return dev;
}

int
netdev_add_netif (struct netdev *dev, struct netif *netif) {
    struct netif *entry;

    for (entry = dev->ifs; entry; entry = entry->next) {
        if (entry->family == netif->family) {
            return -1;
        }
    }
    netif->next = dev->ifs;
    netif->dev  = dev;
    dev->ifs = netif;
    return 0;
}

struct netif *
netdev_get_netif (struct netdev *dev, int family) {
    struct netif *entry;

    for (entry = dev->ifs; entry; entry = entry->next) {
        if (entry->family == family) {
            return entry;
        }
    }
    return NULL;
}
