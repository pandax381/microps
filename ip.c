#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include "ip.h"
#include "util.h"

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60
#define IP_PAYLOAD_SIZE_MAX (ETHERNET_PAYLOAD_SIZE_MAX - IP_HDR_SIZE_MIN)
#define IP_VERSION_IPV4 4
#define IP_ROUTE_TABLE_SIZE 8
#define IP_PROTOCOL_TABLE_SIZE 4
#define IP_FRAGMENT_TABLE_SIZE 32
#define IP_FRAGMENT_TIMEOUT_SEC 30

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

struct ip_route {
    uint8_t used;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
};

struct ip_fragment {
    uint8_t used;
    ip_addr_t src;
    ip_addr_t dst;
    uint16_t id;
    uint16_t protocol;
    uint16_t len;
    uint8_t data[65535];
    uint32_t mask[2048];
    time_t timestamp;
};

struct ip_protocol {
    uint8_t used;
    uint8_t protocol;
    __ip_protocol_handler_t handler;
};

static struct {
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t network;
    ip_addr_t broadcast;
    struct ip_route route_table[IP_ROUTE_TABLE_SIZE];
    struct ip_fragment fragment_table[IP_FRAGMENT_TABLE_SIZE];
    struct ip_protocol protocol_table[IP_PROTOCOL_TABLE_SIZE];
} ip;

#define IP_ROUTE_TABLE_FOREACH(x) \
    for (x = ip.route_table; x != ip.route_table + IP_ROUTE_TABLE_SIZE; x++)
#define IP_ROUTE_TABLE_OFFSET(x) \
    ((x - ip.route_table) / sizeof(*x))
#define IP_PROTOCOL_TABLE_FOREACH(x) \
    for (x = ip.protocol_table; x != ip.protocol_table + IP_PROTOCOL_TABLE_SIZE; x++)
#define IP_PROTOCOL_TABLE_OFFSET(x) \
    ((x - ip.protocol_table) / sizeof(*x))
#define IP_FRAGMENT_TABLE_FOREACH(x) \
    for (x = ip.fragment_table; x != ip.fragment_table + IP_FRAGMENT_TABLE_SIZE; x++)
#define IP_FRAGMENT_TABLE_OFFSET(x) \
    ((x - ip.fragment_table) / sizeof(*x))

const ip_addr_t IP_ADDR_BCAST = 0xffffffff;

int
ip_addr_pton (const char *p, ip_addr_t *n) {
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size) {
    uint8_t *ptr;

    ptr = (uint8_t *)n;
    snprintf(p, size, "%d.%d.%d.%d",
        ptr[0], ptr[1], ptr[2], ptr[3]);
    return p;
}

ip_addr_t
ip_get_addr (ip_addr_t *dst) {
    if (dst) {
        *dst = ip.unicast;
    }
    return ip.unicast;
}

static int
ip_route_add (const char *network, const char *netmask, const char *nexthop) {
    ip_addr_t _network, _netmask, _nexthop;
    struct ip_route *route;

    if (ip_addr_pton(network, &_network) == -1) {
        return -1;
    }
    if (ip_addr_pton(netmask, &_netmask) == -1) {
        return -1;
    }
    if (ip_addr_pton(nexthop, &_nexthop) == -1) {
        return -1;
    }
    IP_ROUTE_TABLE_FOREACH (route) {
        if (!route->used) {
            route->used = 1;
            route->network = _network;
            route->netmask = _netmask;
            route->nexthop = _nexthop;
            return 0;
        }
    }
    return -1;
}

static int
ip_route_lookup (const ip_addr_t *dst, ip_addr_t *nexthop) {
    struct ip_route *route, *candidate = NULL;

    IP_ROUTE_TABLE_FOREACH (route) {
        if (route->used && (*dst & route->netmask) == route->network) {
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
    }
    if (!candidate) {
        return -1;
    }
    *nexthop = candidate->nexthop;
    return 0;
}

static void
ip_fragment_init (struct ip_fragment *fragment) {
    fragment->used = 0;
    fragment->src = 0;
    fragment->dst = 0;
    fragment->id = 0;
    fragment->protocol = 0;
    fragment->len = 0;
    memset(fragment->data, 0, sizeof(fragment->data));
    maskclr(fragment->mask, sizeof(fragment->mask));
}

static struct ip_fragment *
ip_fragment_assign (void) {
    struct ip_fragment *fragment;
    time_t now;

    now = time(NULL);
    IP_FRAGMENT_TABLE_FOREACH (fragment) {
        if (fragment->used) {
            if (fragment->timestamp + IP_FRAGMENT_TIMEOUT_SEC > now) {
                continue;
            }
            ip_fragment_init(fragment);
        }
        fragment->used = 1;
        return fragment;
    }
    return NULL;
}

static struct ip_fragment *
ip_fragment_search (const struct ip_hdr *hdr) {
    struct ip_fragment *fragment;

    IP_FRAGMENT_TABLE_FOREACH (fragment) {
        if (fragment->used &&
            fragment->src == hdr->src &&
            fragment->dst == hdr->dst &&
            fragment->id == hdr->id &&
            fragment->protocol == hdr->protocol) {
            return fragment;
        }
    }
    return NULL;
}

int
ip_add_protocol (uint8_t protocol, __ip_protocol_handler_t handler) {
    struct ip_protocol *p;

    IP_PROTOCOL_TABLE_FOREACH (p) {
        if (!p->used) {
            p->used = 1;
            p->protocol = protocol;
            p->handler = handler;
            return 0;
        }
    }
    return -1;
}

static void
ip_input (uint8_t *dgram, size_t dlen, ethernet_addr_t *src, ethernet_addr_t *dst) {
    struct ip_hdr *hdr;
    uint16_t hlen, offset, off;
    uint8_t *payload;
    size_t plen;
    struct ip_fragment *fragment = NULL;
    struct ip_protocol *protocol;

    (void)src;
    (void)dst;
    if (dlen < sizeof(struct ip_hdr)) {
        return;
    }
    hdr = (struct ip_hdr *)dgram;
    if ((hdr->vhl >> 4) != IP_VERSION_IPV4) {
        fprintf(stderr, "not ipv4 packet.\n");
        return;
    }
    hlen = (hdr->vhl & 0x0f) << 2;
    if (dlen < hlen || dlen < ntoh16(hdr->len)) {
        fprintf(stderr, "ip packet length error.\n");
        return;
    }
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        fprintf(stderr, "ip checksum error.\n");
        return;
    }
    if (hdr->dst != ip.unicast) {
        if (hdr->dst != ip.broadcast && hdr->dst != IP_ADDR_BCAST) {
            return;
        }
    }
    payload = (uint8_t *)hdr + hlen;
    plen = ntoh16(hdr->len) - hlen;
    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        fragment = ip_fragment_search(hdr);
        if (!fragment) {
            fragment = ip_fragment_assign();
            if (!fragment) {
                return;
            }
            fragment->src = hdr->src;
            fragment->dst = hdr->dst;
            fragment->id = hdr->id;
            fragment->protocol = hdr->protocol;
        }
        off = (offset & 0x1fff) << 3;
        memcpy(fragment->data + off, payload, plen);
        maskset(fragment->mask, sizeof(fragment->mask), off, plen);
        if ((offset & 0x2000) == 0) {
            fragment->len = off + plen;
        }
        fragment->timestamp = time(NULL);
        if (!fragment->len) {
            return;
        }
        if (!maskchk(fragment->mask, sizeof(fragment->mask), 0, fragment->len)) {
            return;
        }
        payload = fragment->data;
        plen = fragment->len;
    }
    IP_PROTOCOL_TABLE_FOREACH (protocol) {
        if (protocol->used && protocol->protocol == hdr->protocol) {
            protocol->handler(payload, plen, &hdr->src, &hdr->dst);
            break;
        }
    }
    if (fragment) {
        ip_fragment_init(fragment);
    }
}

static ssize_t
ip_output_core (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst, const ip_addr_t *nexthop, uint16_t id, uint16_t offset) {
    uint8_t packet[ETHERNET_PAYLOAD_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen;
    ssize_t ret;

    hdr = (struct ip_hdr *)packet;
    hlen = sizeof(struct ip_hdr);
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    hdr->len = hton16(hlen + len);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = ip.unicast;
    hdr->dst = *dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    memcpy(hdr + 1, buf, len);
    if (*nexthop) {
        ret = ethernet_output(ETHERNET_TYPE_IP, (uint8_t *)packet, hlen + len, nexthop, NULL);
    } else {
        ret = ethernet_output(ETHERNET_TYPE_IP, (uint8_t *)packet, hlen + len, NULL, &ETHERNET_ADDR_BCAST);
    }
    if (ret != (ssize_t)(hlen + len)) {
        return -1;
    }
    return len;
}

static uint16_t
ip_generate_id (void) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint16_t id = 0;
    uint16_t ret;

    pthread_mutex_lock(&mutex);
    ret = id++;
    pthread_mutex_unlock(&mutex);
    return ret;
}

ssize_t
ip_output (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst) {
    ip_addr_t nexthop = 0;
    uint16_t id, flag, offset;
    size_t done, slen;
    ssize_t ret;

    if (*dst != IP_ADDR_BCAST && *dst != ip.broadcast) {
        if (ip_route_lookup(dst, &nexthop) == -1) {
            fprintf(stderr, "ip no route to host.\n");
            return -1;
        }
        if (!nexthop) {
            nexthop = *dst;
        }
    }
    id = ip_generate_id();
    for (done = 0; done < len; done += slen) {
        slen = MIN((len - done), IP_PAYLOAD_SIZE_MAX);
        flag = ((done + slen) < len) ? 0x2000 : 0x0000;
        offset = flag | ((done >> 3) & 0x1fff);
        ret = ip_output_core(protocol, buf + done, slen, dst, &nexthop, id, offset);
        if (ret != (ssize_t)slen) {
            return -1;
        }
    }
    return len;
}

int
ip_init (const char *addr, const char *netmask, const char *gateway) {
    char network[IP_ADDR_STR_LEN + 1];

    if (ip_addr_pton(addr, &ip.unicast) == -1) {
        return -1;
    }
    if (ip_addr_pton(netmask, &ip.netmask) == -1) {
        return -1;
    }
    ip.network = ip.unicast & ip.netmask;
    ip.broadcast = ip.network & ~ip.netmask;
    ip_addr_ntop(&ip.network, network, sizeof(network));
    if (ip_route_add(network, netmask, "0.0.0.0") == -1) {
        return -1;
    }
    if (gateway) {
        if (ip_route_add("0.0.0.0", "0.0.0.0", gateway) == -1) {
            return -1;
        }
    }
    ethernet_add_protocol(ETHERNET_TYPE_IP, ip_input);
    return 0;
}
