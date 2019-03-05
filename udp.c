#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include "util.h"
#include "udp.h"

#define UDP_CB_TABLE_SIZE 16
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
};

struct udp_queue_hdr {
    ip_addr_t addr;
    uint16_t port;
    uint16_t len;
    uint8_t data[0];
};

struct udp_cb {
    int used;
    struct netif *iface;
    uint16_t port;
    struct queue_head queue;
    pthread_cond_t cond;
};

static struct {
    struct {
        struct udp_cb table[UDP_CB_TABLE_SIZE];
        pthread_mutex_t mutex;
    } cb;
} udp;

#define UDP_CB_TABLE_FOREACH(x) \
    for (x = udp.cb.table; x != udp.cb.table + UDP_CB_TABLE_SIZE; x++)
#define UDP_CB_TABLE_OFFSET(x) \
    ((x - udp.cb.table) / sizeof(*x))

static ssize_t
udp_tx (struct netif *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
    char packet[65536];
    struct udp_hdr *hdr;
    ip_addr_t self;
    uint32_t pseudo = 0;

    hdr = (struct udp_hdr *)packet;
    hdr->sport = sport;
    hdr->dport = port;
    hdr->len = hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = 0;
    memcpy(hdr + 1, buf, len);
    self = ((struct netif_ip *)iface)->unicast;
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (*peer >> 16) & 0xffff;
    pseudo += *peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
    pseudo += hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, pseudo);
    return ip_tx(iface, IP_PROTOCOL_UDP, (uint8_t *)packet, sizeof(struct udp_hdr) + len, peer);
}

static void
udp_rx (uint8_t *buf, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *iface) {
    struct udp_hdr *hdr;
    uint32_t pseudo = 0;
    struct udp_cb *cb;
    void *data;
    struct udp_queue_hdr *queue_hdr;

    if (len < sizeof(struct udp_hdr)) {
        return;
    }
    hdr = (struct udp_hdr *)buf;
    pseudo += *src >> 16;
    pseudo += *src & 0xffff;
    pseudo += *dst >> 16;
    pseudo += *dst & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
    pseudo += hton16(len);
    if (cksum16((uint16_t *)hdr, len, pseudo) != 0) {
        fprintf(stderr, "udp checksum error\n");
        return;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    UDP_CB_TABLE_FOREACH (cb) {
        if (cb->used && (!cb->iface || cb->iface == iface) && cb->port == hdr->dport) {
            data = malloc(sizeof(struct udp_queue_hdr) + (len - sizeof(struct udp_hdr)));
            if (!data) {
                pthread_mutex_unlock(&udp.cb.mutex);
                return;
            }
            queue_hdr = data;
            queue_hdr->addr = *src;
            queue_hdr->port = hdr->sport;
            queue_hdr->len = len - sizeof(struct udp_hdr);
            memcpy(queue_hdr + 1, hdr + 1, len - sizeof(struct udp_hdr));
            queue_push(&cb->queue, data, sizeof(struct udp_queue_hdr) + (len - sizeof(struct udp_hdr)));
            pthread_cond_broadcast(&cb->cond);
            pthread_mutex_unlock(&udp.cb.mutex);
            return;
        }
    }
    pthread_mutex_unlock(&udp.cb.mutex);
    // icmp_send_destination_unreachable();
}

int
udp_api_open (void) {
    struct udp_cb *cb;

    pthread_mutex_lock(&udp.cb.mutex);
    UDP_CB_TABLE_FOREACH (cb) {
        if (!cb->used) {
            cb->used = 1;
            pthread_mutex_unlock(&udp.cb.mutex);
            return UDP_CB_TABLE_OFFSET(cb);
        }
    }
    pthread_mutex_unlock(&udp.cb.mutex);
    return -1;
}

int
udp_api_close (int soc) {
    struct udp_cb *cb;
    struct queue_entry *entry;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    cb = &udp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&udp.cb.mutex);
        return -1;
    }
    cb->used = 0;
    cb->port = 0;
    while ((entry = queue_pop(&cb->queue)) != NULL) {
        free(entry->data);
        free(entry);
    }
    cb->queue.next = cb->queue.tail = NULL;
    pthread_mutex_unlock(&udp.cb.mutex);
    return 0;
}

int
udp_api_bind (int soc, ip_addr_t *addr, uint16_t port) {
    struct udp_cb *cb, *tmp;
    struct netif *iface = NULL;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    cb = &udp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&udp.cb.mutex);
        return -1;
    }
    if (addr && *addr) {
        iface = ip_netif_by_addr(addr);
        if (!iface) {
            pthread_mutex_unlock(&udp.cb.mutex);
            return -1;
        }
    }
    UDP_CB_TABLE_FOREACH (tmp) {
        if (tmp->used && (!iface || !tmp->iface || tmp->iface == iface) && tmp->port == port) {
            pthread_mutex_unlock(&udp.cb.mutex);
            return -1;
        }
    }
    cb->iface = iface;
    cb->port = port;
    pthread_mutex_unlock(&udp.cb.mutex);
    return 0;
}

int
udp_api_bind_iface (int soc, struct netif *iface, uint16_t port) {
    struct udp_cb *cb, *tmp;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    cb = &udp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&udp.cb.mutex);
        return -1;
    }
    UDP_CB_TABLE_FOREACH (tmp) {
        if (tmp->used && (!tmp->iface || tmp->iface == iface) && tmp->port == port) {
            pthread_mutex_unlock(&udp.cb.mutex);
            return -1;
        }
    }
    cb->iface = iface;
    cb->port = port;
    pthread_mutex_unlock(&udp.cb.mutex);
    return 0;
}

ssize_t
udp_api_recvfrom (int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port, int timeout) {
    struct udp_cb *cb;
    struct queue_entry *entry;
    struct timeval tv;
    struct timespec ts;
    int ret = 0;
    ssize_t len;
    struct udp_queue_hdr *queue_hdr;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    cb = &udp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&udp.cb.mutex);
        return -1;
    }
    gettimeofday(&tv, NULL);
    while ((entry = queue_pop(&cb->queue)) == NULL && ret != ETIMEDOUT) {
        if (timeout != -1) {
            ts.tv_sec = tv.tv_sec + timeout;
            ts.tv_nsec = tv.tv_usec * 1000;
            ret = pthread_cond_timedwait(&cb->cond, &udp.cb.mutex, &ts);
        } else {
            ret = pthread_cond_wait(&cb->cond, &udp.cb.mutex);
        }
    }
    pthread_mutex_unlock(&udp.cb.mutex);
    if (ret == ETIMEDOUT) {
        return -1;
    }
    queue_hdr = (struct udp_queue_hdr *)entry->data;
    if (peer) {
        *peer = queue_hdr->addr;
    }
    if (port) {
        *port = queue_hdr->port;
    }
    len = MIN(size, queue_hdr->len);
    memcpy(buf, queue_hdr + 1, len);
    free(entry->data);
    free(entry);
    return len;
}

ssize_t
udp_api_sendto (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
    struct udp_cb *cb, *tmp;
    struct netif *iface;
    uint32_t p;
    uint16_t sport;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&udp.cb.mutex);
    cb = &udp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&udp.cb.mutex);
        return -1;
    }
    iface = cb->iface;
    if (!iface) {
        iface = ip_netif_by_peer(peer);
        if (!iface) {
            pthread_mutex_unlock(&udp.cb.mutex);
            return -1;
        }
    }
    if (!cb->port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            UDP_CB_TABLE_FOREACH (tmp) {
                if (tmp->port == hton16((uint16_t)p) && (!tmp->iface || tmp->iface == iface)) {
                    break;
                }
            }
            if (UDP_CB_TABLE_OFFSET(tmp) == UDP_CB_TABLE_SIZE) {
                cb->port = hton16((uint16_t)p);
                break;
            }
        }
        if (!cb->port) {
            pthread_mutex_unlock(&udp.cb.mutex);
            return -1;
        }
    }
    sport = cb->port;
    pthread_mutex_unlock(&udp.cb.mutex);
    return udp_tx(iface, sport, buf, len, peer, port);
}

int
udp_init (void) {
    struct udp_cb *cb;

    UDP_CB_TABLE_FOREACH (cb) {
        pthread_cond_init(&cb->cond, NULL);
    }
    pthread_mutex_init(&udp.cb.mutex, NULL);
    if (ip_add_protocol(IP_PROTOCOL_UDP, udp_rx) == -1) {
        return -1;
    }
    return 0;
}

#ifdef _UDP_TEST_

#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

#define ETHERNET_DEVICE_NAME "en0"
#define ETHERNET_DEVICE_ADDR "58:55:ca:fb:6e:9f"
#define IP_ADDR "10.13.100.100"
#define IP_NETMASK "10.13.0.0"
#define IP_GATEWAY "10.13.0.1"
#define UDP_ECHO_SERVER_PORT 7

static int
init (void) {
    if (ethernet_init() == -1) {
        return -1;
    }
    if (ethernet_device_open(ETHERNET_DEVICE_NAME, ETHERNET_DEVICE_ADDR) == -1) {
        return -1;
    }
    if (arp_init() == -1) {
        goto ERROR;
    }
    if (ip_init(IP_ADDR, IP_NETMASK, IP_GATEWAY) == -1) {
        goto ERROR;
    }
    if (icmp_init() == -1) {
        goto ERROR;
    }
    if (udp_init() == -1) {
        goto ERROR;
    }
    if (ethernet_device_run() == -1) {
        goto ERROR;
    }
    return 0;
ERROR:
    ethernet_device_close();
    return -1;
}

static void
terminate (void) {
    ethernet_device_close();
}

int
main (int argc, char *argv[]) {
    int soc = -1, ret;
    uint8_t buf[65535];
    ip_addr_t peer_addr;
    uint16_t peer_port;
    char addr[IP_ADDR_STR_LEN + 1];

    if (init() == -1) {
        fprintf(stderr, "protocol stack initialize error.\n");
        return -1;
    }
    soc = udp_api_open();
    if (soc == -1) {
        goto ERROR;
    }
    if (udp_api_bind(soc, hton16(UDP_ECHO_SERVER_PORT)) == -1) {
        goto ERROR;
    }
    while (1) {
        ret = udp_api_recvfrom(soc, buf, sizeof(buf), &peer_addr, &peer_port);
        if (ret <= 0) {
            break;
        }
        fprintf(stderr, "receive message, from %s:%d\n",
            ip_addr_ntop(&peer_addr, addr, sizeof(addr)) ,ntoh16(peer_port));
        hexdump(stderr, buf, ret);
        udp_api_sendto(soc, buf, ret, &peer_addr, peer_port);
    }
    udp_api_close(soc);
    terminate();
    return 0;
ERROR:
    if (soc != -1) {
        udp_api_close(soc);
    }
    terminate();
    return -1;
}

#endif
