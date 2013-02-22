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
#define IP_HANDLER_TABLE_SIZE 16
#define IP_FRAGMENT_STOCK_SIZE 1024

const ip_addr_t IP_ADDR_BCAST = 0xffffffff;

static struct {
	ip_addr_t addr;
	ip_addr_t mask;
	ip_addr_t bcast;
	ip_addr_t gw;
	struct {
		uint8_t protocol;
		__ip_handler_t handler;
	} handler_table[IP_HANDLER_TABLE_SIZE];
	int handler_num;
	struct {
		uint16_t id;
		uint16_t protocol;
		ip_addr_t src;
		uint16_t len;
		uint8_t payload[65536];
		uint8_t check[65536];
	} fragment_stock[IP_FRAGMENT_STOCK_SIZE];
} g_ip;

static void
ip_recv_fragment (struct ip_hdr *hdr, uint8_t *payload, size_t plen);
static ssize_t
ip_send_core (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst, uint16_t id, uint16_t offset);

ip_addr_t *
ip_get_addr (void) {
	return &g_ip.addr;
}

int
ip_set_addr (const char *addr, const char *mask) {
	if (ip_addr_pton(addr, &g_ip.addr) == -1) {
		return -1;
	}
	if (ip_addr_pton(mask, &g_ip.mask) == -1) {
		return -1;
	}
	g_ip.bcast = (g_ip.addr & g_ip.mask) + ~g_ip.mask;
	return 0;
}

int
ip_set_gw (const char *gw) {
	return ip_addr_pton(gw, &g_ip.gw);
}

int
ip_add_handler (uint8_t protocol, __ip_handler_t handler) {
	if (g_ip.handler_num >= IP_HANDLER_TABLE_SIZE) {
		return -1;
	}
	g_ip.handler_table[g_ip.handler_num].protocol = protocol;
	g_ip.handler_table[g_ip.handler_num].handler = handler;
	g_ip.handler_num++;
	return 0;
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
	if ((hdr->vhl >> 4 & 0x0f) != 4) {
		fprintf(stderr, "not ipv4 packet.\n");
		return;
	}
	hlen = (hdr->vhl & 0x0f) << 2;
	if (dlen < hlen || dlen < ntohs(hdr->len)) {
		fprintf(stderr, "ip packet length error.\n");
		return;
	}
	if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
		fprintf(stderr, "ip checksum error.\n");
		return;
	}
	if (ip_addr_cmp(&g_ip.addr, &hdr->dst) != 0) {
		if (ip_addr_cmp(&IP_ADDR_BCAST, &hdr->dst) != 0) {
			return;
		}
	}
	payload = (uint8_t *)(hdr + 1);
	plen = ntohs(hdr->len) - sizeof(struct ip_hdr);
	offset = ntohs(hdr->offset);
	if (offset & 0x2000 || offset & 0x1fff) {
		ip_recv_fragment(hdr, payload, plen);
	} else {
		for (offset = 0; offset < g_ip.handler_num; offset++) {
			if (g_ip.handler_table[offset].protocol == hdr->protocol) {
				g_ip.handler_table[offset].handler(payload, plen, &hdr->src, &hdr->dst);
				break;
			}
		}
	}
}

static void
ip_recv_fragment (struct ip_hdr *hdr, uint8_t *payload, size_t plen) {
	uint16_t offset;
	int index, stock = 0;

	offset = (ntohs(hdr->offset) & 0x1fff) << 3;
	for (index = 0; index < IP_FRAGMENT_STOCK_SIZE; index++) {
		if (g_ip.fragment_stock[index].id == hdr->id && g_ip.fragment_stock[index].protocol == hdr->protocol) {
			if (ip_addr_cmp(&g_ip.fragment_stock[index].src, &hdr->src) == 0) {
				memcpy(g_ip.fragment_stock[index].payload + offset, payload, plen);
				memset(g_ip.fragment_stock[index].check + offset, 1, plen);
				break;
			}
		} else if (stock == 0 && g_ip.fragment_stock[index].id == 0 && g_ip.fragment_stock[index].protocol == 0) {
			stock = index;
		}
	}
	if (index == IP_FRAGMENT_STOCK_SIZE) {
		if (stock == 0) {
			return;
		}
		index = stock;
		g_ip.fragment_stock[index].id = hdr->id;
		g_ip.fragment_stock[index].protocol = hdr->protocol;
		g_ip.fragment_stock[index].src = hdr->src;
		memcpy(g_ip.fragment_stock[index].payload + offset, payload, plen);
		memset(g_ip.fragment_stock[index].check + offset, 1, plen);
	}
	if ((ntohs(hdr->offset) & 0x2000) == 0) {
		g_ip.fragment_stock[index].len = offset + plen;
	}
	if (g_ip.fragment_stock[index].len == 0) {
		return;
	}
	int i;
	for (i = 0; i < (int)g_ip.fragment_stock[index].len; i++) {
		if (g_ip.fragment_stock[index].check[i] != 1) {
			return;
		}
	}
	for (i = 0; i < g_ip.handler_num; i++) {
		if (g_ip.handler_table[i].protocol == hdr->protocol) {
			g_ip.handler_table[i].handler(g_ip.fragment_stock[index].payload, offset + plen, &hdr->src, &hdr->dst);
			g_ip.fragment_stock[index].id = 0;
			g_ip.fragment_stock[index].protocol = 0;
			g_ip.fragment_stock[index].src = 0;
			g_ip.fragment_stock[index].len = 0;
			memset(g_ip.fragment_stock[index].payload, 0, sizeof(g_ip.fragment_stock[index].payload));
			memset(g_ip.fragment_stock[index].check, 0, sizeof(g_ip.fragment_stock[index].check));
			break;
		}
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
	size_t len2;
	uint16_t offset = 0, flag;
	ssize_t ret;

	id = ip_generate_id();
	while ((len - offset) != 0) {
		len2 = ((len - offset) > IP_PAYLOAD_SIZE_MAX) ? IP_PAYLOAD_SIZE_MAX : (len - offset);
		flag = (len - (len2 + offset) > 0) ? 0x2000 : 0x0000;
		ret = ip_send_core (protocol, buf + offset, len2, dst, id, flag | (uint16_t)((offset >> 3) & 0x1fff));
		if (ret != (ssize_t)len2) {
			return -1;
		}
		offset += len2;
	}
	return len;
}

static ssize_t
ip_send_core (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst, uint16_t id, uint16_t offset) {
	uint8_t packet[1500];
	struct ip_hdr *hdr;
	uint16_t hlen;
	ethernet_addr_t dst_ha;
	ssize_t ret;

	hdr = (struct ip_hdr *)packet;
	hlen = sizeof(struct ip_hdr);
	hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
	hdr->tos = 0;
	hdr->len = htons(hlen + len);
	hdr->id = htons(id);
	hdr->offset = htons(offset);
	hdr->ttl = 0xff;
	hdr->protocol = protocol;
	hdr->sum = 0;
	hdr->src = g_ip.addr;
	hdr->dst = *dst;

	hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
	memcpy(hdr + 1, buf, len);
	if (arp_table_lookup (ip_addr_islink(dst) ? dst : &g_ip.gw, &dst_ha) == -1) {
		fprintf(stderr, "arp lookup error.\n");
		return -1;
	}
	ret = ethernet_send(ETHERNET_TYPE_IP, (uint8_t *)packet, hlen + len, &dst_ha);
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

int
ip_addr_cmp (const ip_addr_t *a, const ip_addr_t *b) {
	return memcmp(a, b, sizeof(ip_addr_t));
}

int
ip_addr_isself (const ip_addr_t *addr) {
	return (*addr == g_ip.addr);
}

int
ip_addr_islink (const ip_addr_t *addr) {
	return (*addr & g_ip.mask) == (g_ip.addr & g_ip.mask);
}

#ifdef _IP_UNIT_TEST
#include "device.h"

void
icmp_recv (uint8_t *packet, size_t plen, in_addr_t *src, in_addr_t *dst) {
	char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

	fprintf(stderr, "%s > %s ICMP %lu\n",
		ip_addr_ntop(src, ss, sizeof(ss)),
		ip_addr_ntop(dst, ds, sizeof(ds)),
		plen);
	hexdump(stderr, packet, plen);
}

void
udp_recv (uint8_t *dgram, size_t dlen, in_addr_t *src, in_addr_t *dst) {
	char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

	fprintf(stderr, "%s > %s UDP  %lu\n",
		ip_addr_ntop(src, ss, sizeof(ss)),
		ip_addr_ntop(dst, ds, sizeof(ds)),
		dlen);
	hexdump(stderr, dgram, dlen);
}

void
tcp_recv (uint8_t *segment, size_t slen, in_addr_t *src, in_addr_t *dst) {
	char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

	fprintf(stderr, "%s > %s TCP  %lu\n",
		ip_addr_ntop(src, ss, sizeof(ss)),
		ip_addr_ntop(dst, ds, sizeof(ds)),
		slen);
	hexdump(stderr, segment, slen);
}

int
main (int argc, char *argv[]) {
	sigset_t sigset;
	int signo;

	if (argc != 6) {
		fprintf(stderr, "usage: %s device-name ethernet-addr ip-addr netmask default-gw\n", argv[0]);
		goto ERROR;
	}
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (ip_set_addr(argv[3], argv[4]) == -1) {
		fprintf(stderr, "error: ip-addr/netmask is invalid\n");
		goto ERROR;
	}
	if (ip_set_gw(argv[5]) == -1) {
		fprintf(stderr, "error: default-gw is invalid\n");
		goto ERROR;
	}
	ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
	ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
	ip_add_handler(IP_PROTOCOL_TCP, tcp_recv);
	arp_init();
    if (ethernet_set_addr(argv[2]) == -1) {
		fprintf(stderr, "error: ethernet-addr is invalid\n");
		goto ERROR;
	}
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(argv[1], ethernet_recv) == -1) {
		fprintf(stderr, "error: device-name is invalid\n");
        goto ERROR;
    }
	sigwait(&sigset, &signo);
    device_cleanup();
    return  0;

ERROR:
    return -1;
}
#endif
