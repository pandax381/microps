#ifndef NETDEV_H
#define NETDEV_H

#include <stdint.h>

#define NETDEV_TYPE_ETHERNET  (0x0001)
#define NETDEV_TYPE_SLIP      (0x0002)

#define NETDEV_FLAG_BROADCAST (0x0001)
#define NETDEV_FLAG_MULTICAST (0x0002)
#define NETDEV_FLAG_P2P       (0x0004)
#define NETDEV_FLAG_LOOPBACK  (0x0008)
#define NETDEV_FLAG_NOARP     (0x0010)
#define NETDEV_FLAG_PROMISC   (0x0020)
#define NETDEV_FLAG_RUNNING   (0x0040)
#define NETDEV_FLAG_UP        (0x0080)

#define NETIF_FAMILY_IPV4     (0x02)
#define NETIF_FAMILY_IPV6     (0x0a)

#ifndef IFNAMSIZ
#define IFNAMSIZ (16)
#endif

struct netdev;

struct netif {
    struct netif *next;
    uint8_t family;
    struct netdev *dev;
    /* Depends on implementation of protocols. */
};

struct netdev_ops {
    int (*open)(struct netdev *dev, int opt);
    int (*close)(struct netdev *dev);
    int (*run)(struct netdev *dev);
    int (*stop)(struct netdev *dev);
    ssize_t (*tx)(struct netdev *dev, uint16_t type, const uint8_t *packet, size_t size, const void *dst);
};

struct netdev {
    struct netdev *next;
    struct netif *ifs;
    char name[IFNAMSIZ];
    uint16_t type;
    uint16_t mtu;
    uint16_t flags;
    uint16_t hlen;
    uint16_t alen;
    uint8_t addr[16];
    uint8_t peer[16];
    uint8_t broadcast[16];
    void (*rx_handler)(struct netdev *dev, uint16_t type, uint8_t *packet, size_t plen);
    struct netdev_ops *ops;
    void *priv;
};

extern struct netdev *
netdev_root (void);
extern int
netdev_register_driver (uint16_t type, uint16_t mtu, uint16_t flags, uint16_t hlen, uint16_t alen, struct netdev_ops *ops);
extern int
netdev_register_protocol (unsigned short type, void (*handler)(uint8_t *packet, size_t plen, struct netdev *dev));
extern struct netdev *
netdev_alloc (uint16_t type);
extern int
netdev_add_netif(struct netdev *dev, struct netif *netif);
extern struct netif *
netdev_get_netif(struct netdev *dev, int family);

#endif
