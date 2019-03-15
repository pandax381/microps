#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "net.h"
#include "arp.h"
#include "util.h"

#define ARP_HRD_ETHERNET 0x0001

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_TABLE_SIZE 4096
#define ARP_TABLE_TIMEOUT_SEC 300

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
} __attribute__ ((packed));

struct arp_ethernet {
    struct arp_hdr hdr;
    ethernet_addr_t sha;
    ip_addr_t spa;
    ethernet_addr_t tha;
    ip_addr_t tpa;
} __attribute__ ((packed));

struct arp_entry {
    unsigned char used;
    ip_addr_t pa;
    ethernet_addr_t ha;
    time_t timestamp;
    pthread_cond_t cond;
    void *data;
    size_t len;
    struct netif *netif;
};

static struct arp_entry arp_table[ARP_TABLE_SIZE];
static time_t timestamp;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static char *
arp_opcode_ntop (uint16_t opcode) {
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "REQUEST";
    case ARP_OP_REPLY:
        return "REPLY";
    }
    return "UNKNOWN";
}

void
arp_dump (uint8_t *packet, size_t plen) {
    struct arp_ethernet *message;
    char addr[128];

    message = (struct arp_ethernet *)packet;
    fprintf(stderr, " hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, " pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, " hln: %u\n", message->hdr.hln);
    fprintf(stderr, " pln: %u\n", message->hdr.pln);
    fprintf(stderr, "  op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntop(message->hdr.op));
    fprintf(stderr, " sha: %s\n", ethernet_addr_ntop(&message->sha, addr, sizeof(addr)));
    fprintf(stderr, " spa: %s\n", ip_addr_ntop(&message->spa, addr, sizeof(addr)));
    fprintf(stderr, " tha: %s\n", ethernet_addr_ntop(&message->tha, addr, sizeof(addr)));
    fprintf(stderr, " tpa: %s\n", ip_addr_ntop(&message->tpa, addr, sizeof(addr)));
}

static struct arp_entry *
arp_table_select (const ip_addr_t *pa) {
    struct arp_entry *entry;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (entry->used && entry->pa == *pa) {
            return entry;
        }
    }
    return NULL;
}

static int
arp_table_update (struct netdev *dev, const ip_addr_t *pa, const ethernet_addr_t *ha) {
    struct arp_entry *entry;

    entry = arp_table_select(pa);
    if (!entry) {
        return -1;
    }
    memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
    time(&entry->timestamp);
    if (entry->data) {
        if (entry->netif->dev != dev) {
            /* warning: receive response from unintended device */
            dev = entry->netif->dev;
        }
        dev->ops->tx(dev, ETHERNET_TYPE_IP, (uint8_t *)entry->data, entry->len, &entry->ha);
        free(entry->data);
        entry->data = NULL;
        entry->len = 0;
    }
    pthread_cond_broadcast(&entry->cond);
    return 0;
}

static struct arp_entry *
arp_table_freespace (void) {
    struct arp_entry *entry;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (!entry->used) {
            return entry;
        }
    }
    return NULL;
}

static int
arp_table_insert (const ip_addr_t *pa, const ethernet_addr_t *ha) {
    struct arp_entry *entry;

    entry = arp_table_freespace();
    if (!entry) {
        return -1;
    }
    entry->used = 1;
    entry->pa = *pa;
    memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
    time(&entry->timestamp);
    pthread_cond_broadcast(&entry->cond);
    return 0;
}

static void
arp_entry_clear (struct arp_entry *entry) {
    entry->used = 0;
    entry->pa = 0;
    memset(&entry->ha, 0, sizeof(ethernet_addr_t));
    entry->timestamp = 0;
    if (entry->data) {
        /* TODO: Unreachable */
        free(entry->data);
        entry->data = NULL;
        entry->len = 0;
        entry->netif = NULL;
    }
    /* !!! Don't touch entry->cond !!! */
}

static void
arp_table_patrol (void) {
    struct arp_entry *entry;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (entry->used && timestamp - entry->timestamp > ARP_TABLE_TIMEOUT_SEC) {
            arp_entry_clear(entry);
            pthread_cond_broadcast(&entry->cond);
        }
    }
}

static int
arp_send_request (struct netif *netif, const ip_addr_t *tpa) {
    struct arp_ethernet request;

    if (!tpa) {
        return -1;
    }
    request.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    request.hdr.pro = hton16(ETHERNET_TYPE_IP);
    request.hdr.hln = 6;
    request.hdr.pln = 4;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha.addr, netif->dev->addr, sizeof(request.sha.addr));
    request.spa = ((struct netif_ip *)netif)->unicast;
    memset(&request.tha, 0, ETHERNET_ADDR_LEN);
    request.tpa = *tpa;
#ifdef DEBUG
    fprintf(stderr, ">>> arp_send_request <<<\n");
    arp_dump((uint8_t *)&request, sizeof(request));
#endif
    if (netif->dev->ops->tx(netif->dev, ETHERNET_TYPE_ARP, (uint8_t *)&request, sizeof(request), (void *)&ETHERNET_ADDR_BROADCAST) == -1) {
        return -1;
    }
    return 0;
}

static int
arp_send_reply (struct netif *netif, const ethernet_addr_t *tha, const ip_addr_t *tpa, const ethernet_addr_t *dst) {
    struct arp_ethernet reply;

    if (!tha || !tpa) {
        return -1;
    }
    reply.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    reply.hdr.pro = hton16(ETHERNET_TYPE_IP);
    reply.hdr.hln = 6;
    reply.hdr.pln = 4;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha.addr, netif->dev->addr, sizeof(reply.sha.addr));
    reply.spa = ((struct netif_ip *)netif)->unicast;
    reply.tha = *tha;
    reply.tpa = *tpa;
#ifdef DEBUG
    fprintf(stderr, ">>> arp_send_reply <<<\n");
    arp_dump((uint8_t *)&reply, sizeof(reply));
#endif
    if (netif->dev->ops->tx(netif->dev, ETHERNET_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), (void *)dst) < 0) {
        return -1;
    }
    return 0;
}

static void
arp_rx (uint8_t *packet, size_t plen, struct netdev *dev) {
    struct arp_ethernet *message;
    time_t now;
    int marge = 0;
    struct netif *netif;

    if (plen < sizeof(struct arp_ethernet)) {
        return;
    }
    message = (struct arp_ethernet *)packet;
    if (ntoh16(message->hdr.hrd) != ARP_HRD_ETHERNET) {
        return;
    }
    if (ntoh16(message->hdr.pro) != ETHERNET_TYPE_IP) {
        return;
    }
    if (message->hdr.hln != ETHERNET_ADDR_LEN) {
        return;
    }
    if (message->hdr.pln != IP_ADDR_LEN) {
        return;
    }
#ifdef DEBUG
    fprintf(stderr, ">>> arp_rx <<<\n");
    arp_dump(packet, plen);
#endif
    pthread_mutex_lock(&mutex);
    time(&now);
    if (now - timestamp > 10) {
        timestamp = now;
        arp_table_patrol();
    }
    marge = (arp_table_update(dev, &message->spa, &message->sha) == 0) ? 1 : 0;
    pthread_mutex_unlock(&mutex);
    netif = netdev_get_netif(dev, NETIF_FAMILY_IPV4);
    if (netif && ((struct netif_ip *)netif)->unicast == message->tpa) {
        if (!marge) {
            pthread_mutex_lock(&mutex);
            arp_table_insert(&message->spa, &message->sha);
            pthread_mutex_unlock(&mutex);
        }
        if (ntoh16(message->hdr.op) == ARP_OP_REQUEST) {
            arp_send_reply(netif, &message->sha, &message->spa, &message->sha);
        }
    }
    return;
}

int
arp_resolve (struct netif *netif, const ip_addr_t *pa, ethernet_addr_t *ha, const void *data, size_t len) {
    struct timeval now;
    struct timespec timeout;
    struct arp_entry *entry;
    int ret;

    pthread_mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    timeout.tv_sec = now.tv_sec + 1;
    timeout.tv_nsec = now.tv_usec * 1000;
    entry = arp_table_select(pa);
    if (entry) {
        if (memcmp(&entry->ha, &ETHERNET_ADDR_ANY, sizeof(ethernet_addr_t)) == 0) {
            arp_send_request(netif, pa); /* just in case packet loss */
            do {
                ret = pthread_cond_timedwait(&entry->cond, &mutex, &timeout);
            } while (ret == EINTR);
            if (!entry->used || ret == ETIMEDOUT) {
                if (entry->used) {
                    arp_entry_clear(entry);
                }
                /* TODO: Unreachable */
                pthread_mutex_unlock(&mutex);
                return ARP_RESOLVE_ERROR;
            }
        }
        memcpy(ha, &entry->ha, sizeof(ethernet_addr_t));
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_FOUND;
    }
    if (!data) {
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_ERROR;
    }
    entry = arp_table_freespace();
    if (!entry) {
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_ERROR;
    }
    entry->data = malloc(len);
    if (!entry->data) {
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_ERROR;
    }
    memcpy(entry->data, data, len);
    entry->len = len;
    entry->used = 1;
    entry->pa = *pa;
    time(&entry->timestamp);
    entry->netif = netif;
    arp_send_request(netif, pa);
    pthread_mutex_unlock(&mutex);
    return ARP_RESOLVE_QUERY;
}

int
arp_init (void) {
    struct arp_entry *entry;

    time(&timestamp);
    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        pthread_cond_init(&entry->cond, NULL);
    }
    netdev_register_protocol(ETHERNET_TYPE_ARP, arp_rx);
    return 0;
}
