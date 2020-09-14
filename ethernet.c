#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "util.h"
#include "raw.h"
#include "net.h"
#include "ethernet.h"

struct ethernet_hdr {
    uint8_t dst[ETHERNET_ADDR_LEN];
    uint8_t src[ETHERNET_ADDR_LEN];
    uint16_t type;
};

struct ethernet_priv {
    struct netdev *dev;
    struct rawdev *raw;
    pthread_t thread;
    int terminate;
};

const uint8_t ETHERNET_ADDR_ANY[ETHERNET_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHERNET_ADDR_BROADCAST[ETHERNET_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int
ethernet_addr_pton (const char *p, uint8_t *n) {
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHERNET_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHERNET_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHERNET_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return  0;
}

static const char *
ethernet_type_ntoa (uint16_t type) {
    switch (ntoh16(type)) {
    case ETHERNET_TYPE_IP:
        return "IP";
    case ETHERNET_TYPE_ARP:
        return "ARP";
    case ETHERNET_TYPE_IPV6:
        return "IPv6";
    }
    return "UNKNOWN";
}

char *
ethernet_addr_ntop (const uint8_t *n, char *p, size_t size) {
    if (!n || !p) {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

void
ethernet_dump (struct netdev *dev, uint8_t *frame, size_t flen) {
    struct ethernet_hdr *hdr;
    char addr[ETHERNET_ADDR_STR_LEN];

    hdr = (struct ethernet_hdr *)frame;
    fprintf(stderr, "  dev: %s (%s)\n", dev->name, ethernet_addr_ntop(dev->addr, addr, sizeof(addr)));
    fprintf(stderr, "  src: %s\n", ethernet_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "  dst: %s\n", ethernet_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, " type: 0x%04x (%s)\n", ntoh16(hdr->type), ethernet_type_ntoa(hdr->type));
    fprintf(stderr, "  len: %zu octets\n", flen);
    hexdump(stderr, frame, flen);
}

int
ethernet_open (struct netdev *dev, int opt) {
    struct ethernet_priv *priv;
    struct rawdev *raw;

    priv = malloc(sizeof(struct ethernet_priv));
    if (!priv) {
        return -1;
    }
    raw = rawdev_alloc(opt, dev->name);
    if (!raw) {
        free(priv);
        return -1;
    }
    if (raw->ops->open(raw) == -1) {
        free(raw);
        free(priv);
        return -1;
    }
    priv->raw = raw;
    priv->thread = pthread_self();
    priv->terminate = 0;
    priv->dev = dev;
    dev->priv = priv;
    if (memcmp(dev->addr, ETHERNET_ADDR_ANY, ETHERNET_ADDR_LEN) == 0) {
        raw->ops->addr(raw, dev->addr, ETHERNET_ADDR_LEN);
    }
    memcpy(dev->broadcast, ETHERNET_ADDR_BROADCAST, ETHERNET_ADDR_LEN);
    return 0;
}

static int
ethernet_close (struct netdev *dev) {
    struct ethernet_priv *priv;

    if (!dev || !dev->priv) {
        return -1;
    }
    priv = dev->priv;
    if (!pthread_equal(priv->thread, pthread_self())) {
        priv->terminate = 1;
        pthread_join(priv->thread, NULL);
    }
    if (priv->raw) {
        priv->raw->ops->close(priv->raw);
    }
    free(priv);
    return 0;
}

static void
ethernet_rx (uint8_t *frame, size_t flen, void *arg) {
    struct netdev *dev;
    struct ethernet_hdr *hdr;
    uint8_t *payload;
    size_t plen;

    dev = (struct netdev *)arg;
    if (flen < sizeof(struct ethernet_hdr)) {
        return;
    }
    hdr = (struct ethernet_hdr *)frame;
    if (memcmp(dev->addr, hdr->dst, ETHERNET_ADDR_LEN) != 0) {
        if (memcmp(ETHERNET_ADDR_BROADCAST, hdr->dst, ETHERNET_ADDR_LEN) != 0) {
            return;
        }
    }
#ifdef DEBUG
    fprintf(stderr, ">>> ethernet_rx <<<\n");
    ethernet_dump(dev, frame, flen);
#endif
    payload = (uint8_t *)(hdr + 1);
    plen = flen - sizeof(struct ethernet_hdr);
    dev->rx_handler(dev, hdr->type, payload, plen);
}

static void *
ethernet_rx_thread (void *arg) {
    struct netdev *dev;
    struct ethernet_priv *priv;

    dev = (struct netdev *)arg;
    priv = (struct ethernet_priv *)dev->priv;
    while (!priv->terminate) {
        priv->raw->ops->rx(priv->raw, ethernet_rx, dev, 1000);
    }
    return NULL;
}

static int
ethernet_run (struct netdev *dev) {
    struct ethernet_priv *priv;

    int err;

    priv = (struct ethernet_priv *)dev->priv;
    if ((err = pthread_create(&priv->thread, NULL, ethernet_rx_thread, dev)) != 0) {
        fprintf(stderr, "pthread_create: error, code=%d\n", err);
        return -1;
    }
    return 0;
}

static int
ethernet_stop (struct netdev *dev) {
    struct ethernet_priv *priv;

    priv = dev->priv;
    priv->terminate = 1;
    pthread_join(priv->thread, NULL);
    priv->thread = pthread_self();
    priv->terminate = 0;
    return 0;
}

static ssize_t
ethernet_tx (struct netdev *dev, uint16_t type, const uint8_t *payload, size_t plen, const void *dst) {
    struct ethernet_priv *priv;
    uint8_t frame[ETHERNET_FRAME_SIZE_MAX];
    struct ethernet_hdr *hdr;
    size_t flen;

    priv = (struct ethernet_priv *)dev->priv;
    if (!payload || plen > ETHERNET_PAYLOAD_SIZE_MAX || !dst) {
        return -1;
    }
    memset(frame, 0, sizeof(frame));
    hdr = (struct ethernet_hdr *)frame;
    memcpy(hdr->dst, dst, ETHERNET_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHERNET_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr + 1, payload, plen);
    flen = sizeof(struct ethernet_hdr) + (plen < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : plen);
#ifdef DEBUG
    fprintf(stderr, ">>> ethernet_tx <<<\n");
    ethernet_dump(dev, frame, flen);
#endif
    return priv->raw->ops->tx(priv->raw, frame, flen) == (ssize_t)flen ? (ssize_t)plen : -1;
}

struct netdev_ops ethernet_ops = {
    .open = ethernet_open,
    .close = ethernet_close,
    .run = ethernet_run,
    .stop = ethernet_stop,
    .tx = ethernet_tx
};

struct netdev_def ethernet_def = {
    .type = NETDEV_TYPE_ETHERNET,
    .mtu = ETHERNET_PAYLOAD_SIZE_MAX,
    .flags = NETDEV_FLAG_BROADCAST,
    .hlen = ETHERNET_HDR_SIZE,
    .alen = ETHERNET_ADDR_LEN,
    .ops = &ethernet_ops
};

int
ethernet_init (void) {
    if (netdev_driver_register(&ethernet_def) == -1) {
        return -1;
    }
    return 0;
}
