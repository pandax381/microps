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

struct netdev_protocol {
    struct netdev_protocol *next;
    uint16_t type;
    void (*handler)(uint8_t *packet, size_t plen, struct netdev *dev);
};

static struct netdev *devices;
static struct netdev_driver *drivers;
static struct netdev_protocol *protocols;

struct netdev *
netdev_root (void) {
    return devices;
}

int
netdev_register_driver (uint16_t type, uint16_t mtu, uint16_t flags, uint16_t hlen, uint16_t alen, struct netdev_ops *ops) {
    struct netdev_driver *new_entry;

    new_entry = malloc(sizeof(struct netdev_driver));
    if (!new_entry) {
        return -1;
    }
    new_entry->next = drivers;
    new_entry->type = type;
    new_entry->mtu = mtu;
    new_entry->flags = flags;
    new_entry->hlen = hlen;
    new_entry->alen = alen;
    new_entry->ops = ops;
    drivers = new_entry;
    return 0;
}

int
netdev_register_protocol (unsigned short type, void (*handler)(uint8_t *packet, size_t plen, struct netdev *dev)) {
    struct netdev_protocol *new_entry;

    new_entry = malloc(sizeof(struct netdev_protocol));
    if (!new_entry) {
        return -1;
    }
    new_entry->next = protocols;
    new_entry->type = type;
    new_entry->handler = handler;
    protocols = new_entry;
    return 0;
}

static void
netdev_rx_handler (struct netdev *dev, uint16_t type, uint8_t *packet, size_t plen) {
    struct netdev_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (hton16(entry->type) == type) {
            entry->handler(packet, plen, dev);
            return;
        }
    }
}

struct netdev *
netdev_alloc (uint16_t type) {
    struct netdev_driver *entry;
    struct netdev *dev;

    for (entry = drivers; entry; entry = entry->next) {
        if (entry->type == type) {
            break;
        }
    }
    if (!entry) {
        return NULL;
    }
    dev = malloc(sizeof(struct netdev));
    if (!dev) {
        return NULL;
    }
    dev->next = devices;
    dev->ifs = NULL;
    dev->type = entry->type;
    dev->mtu = entry->mtu;
    dev->flags = entry->flags;
    dev->hlen = entry->hlen;
    dev->alen = entry->alen;
    dev->rx_handler = netdev_rx_handler;
    dev->ops = entry->ops;
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
