#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "util.h"

#define IP_VERSION_IPV4 4
#define IP_HANDLER_TABLE_SIZE 16

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
} g_ip;

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
		return;
	}
	hlen = (hdr->vhl & 0x0f) << 2;
	if (dlen < hlen || dlen < ntohs(hdr->len)) {
		return;
	}
	if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
		return;
	}
	if (ip_addr_cmp(&g_ip.addr, &hdr->dst) != 0) {
		if (ip_addr_cmp(&IP_ADDR_BCAST, &hdr->dst) != 0) {
			return;
		}
	}
	offset = ntohs(hdr->offset);
	if (offset & 0x2000 || offset & 0x1fff) {
		// flagment packet.
		return;
	}
	payload = (uint8_t *)(hdr + 1);
	plen = ntohs(hdr->len) - sizeof(struct ip_hdr);
	for (offset = 0; offset < g_ip.handler_num; offset++) {
		if (g_ip.handler_table[offset].protocol == hdr->protocol) {
			g_ip.handler_table[offset].handler(payload, plen, &hdr->src, &hdr->dst);
			break;
		}
	}
}

ssize_t
ip_send (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst) {
	uint8_t packet[1500];
	struct ip_hdr *hdr;
	static uint16_t hlen, id = 0;
	ethernet_addr_t dst_ha;

	hdr = (struct ip_hdr *)packet;
	hlen = sizeof(struct ip_hdr);
	hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
	hdr->tos = 0;
	hdr->len = htons(hlen + len);
	hdr->id = htons(++id);
	hdr->offset = 0;
	hdr->ttl = 0xff;
	hdr->protocol = protocol;
	hdr->sum = 0;
	hdr->src = g_ip.addr;
	hdr->dst = *dst;

	hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
	memcpy(hdr + 1, buf, len);
	if (arp_table_lookup (ip_addr_islink(dst) ? dst : &g_ip.gw, &dst_ha) == -1) {
		return -1;
	}
	if (ethernet_send(ETHERNET_TYPE_IP, (uint8_t *)packet, sizeof(struct ip_hdr) + len, &dst_ha) < 0) {
		return -1;
	}
	return 0;
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
