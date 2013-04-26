#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "util.h"

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60
#define IP_PAYLOAD_SIZE_MAX (ETHERNET_PAYLOAD_SIZE_MAX - IP_HDR_SIZE_MIN)
#define IP_VERSION_IPV4 4
#define IP_ROUTE_TABLE_SIZE 8
#define IP_PROTOCOL_TABLE_SIZE 4
#define IP_FRAGMENT_TABLE_SIZE 1024

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

static void
ip_recv_fragment (struct ip_hdr *hdr, uint8_t *payload, size_t plen);
static ssize_t
ip_send_core (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst, const ethernet_addr_t *dst_ha, uint16_t id, uint16_t offset);

const ip_addr_t IP_ADDR_BCAST = 0xffffffff;

struct ip_route {
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct ip_route *next;
};

struct ip_fragment {
    ip_addr_t src;
    ip_addr_t dst;
    uint16_t id;
    uint16_t protocol;
    uint16_t len;
    uint8_t data[2][65535];
    struct ip_fragment *next;
};

static struct {
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t network;
    ip_addr_t broadcast;
    struct {
        struct ip_route table[IP_ROUTE_TABLE_SIZE];
        struct ip_route *head;
        struct ip_route *pool;
    } route;
	struct {
		uint8_t protocol;
		__ip_protocol_handler_t handler;
	} protocol[IP_PROTOCOL_TABLE_SIZE];
    struct {
        struct ip_fragment table[IP_FRAGMENT_TABLE_SIZE];
        struct ip_fragment *head;
        struct ip_fragment *pool;
    } fragment;
} ip;

int
ip_route_add (const char *network, const char *netmask, const char *nexthop) {
    struct ip_route *route;

    route = ip.route.pool;
    if (!route) {
        return -1;
    }
    if (ip_addr_pton(network, &route->network) == -1) {
        return -1;
    }
    if (ip_addr_pton(netmask, &route->netmask) == -1) {
        return -1;
    }
    if (ip_addr_pton(nexthop, &route->nexthop) == -1) {
        return -1;
    }
    ip.route.pool = route->next;
    route->next = ip.route.head;
    ip.route.head = route;
    return 0;
}

int
ip_route_lookup (const ip_addr_t *dst, ip_addr_t *nexthop) {
    struct ip_route *route, *candidate = NULL;

    for (route = ip.route.head; route->next; route = route->next) {
        if ((*dst & route->netmask) == route->network) {
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

int
ip_init (const char *addr, const char *netmask, const char *gateway) {
    int index;
    char network[IP_ADDR_STR_LEN + 1];

	if (ip_addr_pton(addr, &ip.unicast) == -1) {
		return -1;
	}
	if (ip_addr_pton(netmask, &ip.netmask) == -1) {
		return -1;
	}
    ip.network = ip.unicast & ip.netmask;
    for (index = 0; index < IP_ROUTE_TABLE_SIZE - 1; index++) {
        ip.route.table[index].next = ip.route.table + (index + 1);
    }
    ip.route.pool = ip.route.table;
    ip_addr_ntop(&ip.network, network, sizeof(network));
    if (ip_route_add(network, netmask, "0.0.0.0") == -1) {
        return -1;
    }
    if (ip_route_add("0.0.0.0", "0.0.0.0", gateway) == -1) {
        return -1;
    }
    ethernet_add_protocol(ETHERNET_TYPE_IP, ip_recv);
    for (index = 0; index < IP_FRAGMENT_TABLE_SIZE - 1; index++) {
        ip.fragment.table[index].next = ip.fragment.table + (index + 1);
    }
    ip.fragment.pool = ip.fragment.table;
    return 0;
}

ip_addr_t
ip_get_addr (ip_addr_t *dst) {
    if (dst) {
        *dst = ip.unicast;
    }
    return ip.unicast;
}

int
ip_add_protocol (uint8_t protocol, __ip_protocol_handler_t handler) {
    int index;

    for (index = 0; index < IP_PROTOCOL_TABLE_SIZE; index++) {
        if (ip.protocol[index].protocol == 0) {
            ip.protocol[index].protocol = protocol;
            ip.protocol[index].handler = handler;
            break;
        }
    }
	return index < IP_PROTOCOL_TABLE_SIZE ? 0 : -1;
}

void
ip_recv (uint8_t *dgram, size_t dlen, ethernet_addr_t *src, ethernet_addr_t *dst) {
	struct ip_hdr *hdr;
	uint16_t hlen;
	int offset;
	uint8_t *payload;
	size_t plen;

	(void)src;
	(void)dst;
	if (dlen < sizeof(struct ip_hdr)) {
		return;
	}
	hdr = (struct ip_hdr *)dgram;
	if ((hdr->vhl >> 4) != 4) {
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
	if (hdr->dst != ip.unicast && hdr->dst != IP_ADDR_BCAST) {
        return;
	}
	payload = (uint8_t *)(hdr + 1);
	plen = ntoh16(hdr->len) - sizeof(struct ip_hdr);
	offset = ntoh16(hdr->offset);
	if (offset & 0x2000 || offset & 0x1fff) {
		ip_recv_fragment(hdr, payload, plen);
	} else {
		for (offset = 0; offset < IP_PROTOCOL_TABLE_SIZE; offset++) {
			if (ip.protocol[offset].protocol == hdr->protocol) {
				ip.protocol[offset].handler(payload, plen, &hdr->src, &hdr->dst);
				break;
			}
		}
	}
}

static void
ip_recv_fragment (struct ip_hdr *hdr, uint8_t *payload, size_t plen) {
	uint16_t offset;
    struct ip_fragment *fragment;
	int index;

	offset = (ntoh16(hdr->offset) & 0x1fff) << 3;
    for (fragment = ip.fragment.head; fragment; fragment = fragment->next) {
        if (fragment->src == hdr->src && fragment->dst == hdr->dst) {
            if (fragment->id == hdr->id && fragment->protocol == hdr->protocol) {
                memcpy(fragment->data[0] + offset, payload, plen);
                memset(fragment->data[1] + offset, 1, plen);
                break;
            }
        }
    }
    if (!fragment) {
        fragment = ip.fragment.pool;
        if (!fragment) {
            return;
        }
        fragment->src = hdr->src;
        fragment->dst = hdr->dst;
        fragment->id = hdr->id;
        fragment->protocol = hdr->protocol;
        memcpy(fragment->data[0] + offset, payload, plen);
        memset(fragment->data[1] + offset, 1, plen);
    }
	if ((ntoh16(hdr->offset) & 0x2000) == 0) {
        fragment->len = offset + plen;
	}
    if (fragment->len) {
        for (index = 0; index < (int)fragment->len; index++) {
            if (fragment->data[1][index] != 1) {
                return;
            }
        }
        for (index = 0; index < IP_PROTOCOL_TABLE_SIZE; index++) {
            if (ip.protocol[index].protocol == hdr->protocol) {
                ip.protocol[index].handler(fragment->data[0], fragment->len, &fragment->src, &fragment->dst);
                break;
            }
        }
        fragment->src = 0;
        fragment->dst = 0;
        fragment->id = 0;
        fragment->protocol = 0;
        fragment->len = 0;
        memset(fragment->data[0], 0, sizeof(fragment->data[0]));
        memset(fragment->data[1], 0, sizeof(fragment->data[1]));
    }
}

uint16_t
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
ip_send (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst) {
	uint16_t id;
    ip_addr_t nexthop;
	ethernet_addr_t dst_ha;
	size_t remain, slen;
	uint16_t offset, flag;

	id = ip_generate_id();
    if (ip_route_lookup(dst, &nexthop) == -1) {
		fprintf(stderr, "route lookup error.\n");
        return -1;
    }
	if (arp_resolve(nexthop ? &nexthop : dst, &dst_ha) == -1) {
		fprintf(stderr, "arp lookup error.\n");
		return -1;
	}
    remain = len;
    for (remain = len; remain > 0; remain -= slen) {
        slen = (remain > IP_PAYLOAD_SIZE_MAX) ? IP_PAYLOAD_SIZE_MAX : remain;
        offset = len - remain;
        flag = (remain - slen) ? 0x2000 : 0x0000;
        if (ip_send_core(protocol, buf + offset, slen, dst, &dst_ha, id, flag | ((offset >> 3) & 0x1fff)) != (ssize_t)slen) {
            return -1;
        }
    }
    return len;
}

static ssize_t
ip_send_core (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst, const ethernet_addr_t *dst_ha, uint16_t id, uint16_t offset) {
	uint8_t packet[1500];
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
	ret = ethernet_output(ETHERNET_TYPE_IP, (uint8_t *)packet, hlen + len, dst_ha);
	if (ret != (ssize_t)(hlen + len)) {
		return -1;
	}
	return len;
}

int
ip_addr_pton (const char *p, ip_addr_t *n) {
	struct in_addr addr;

	addr.s_addr = *n;
	if (inet_pton(AF_INET, p, &addr) == -1) {
		return -1;
	}
	*n = addr.s_addr;
	return 0;
}

char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size) {
	struct in_addr addr;

	addr.s_addr = *n;
	if (!inet_ntop(AF_INET, &addr, p, size)) {
		return NULL;
	}
	return p;
}
