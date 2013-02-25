#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "device.h"
#include "util.h"

#define ETHERNET_HANDLER_TABLE_SIZE 16

struct ethernet_hdr {
	ethernet_addr_t dst;
	ethernet_addr_t src;
	uint16_t type;
} __attribute__ ((packed));

const ethernet_addr_t ETHERNET_ADDR_BCAST = {"\xff\xff\xff\xff\xff\xff"};

static struct {
	ethernet_addr_t addr;
	struct {
		uint16_t type;
		__ethernet_handler_t handler;
	} handler_table[ETHERNET_HANDLER_TABLE_SIZE];
	int handler_num;
} g_ethernet;

void
ethernet_init (void) {
	int index;

	memset(&g_ethernet.addr.addr, 0x00, ETHERNET_ADDR_LEN);
	for (index = 0; index < ETHERNET_HANDLER_TABLE_SIZE; index++) {
		g_ethernet.handler_table[index].type = 0;
		g_ethernet.handler_table[index].handler = NULL;
	}
	g_ethernet.handler_num = 0;
}

ethernet_addr_t *
ethernet_get_addr (ethernet_addr_t *dst) {
    return memcpy(dst, &g_ethernet.addr, sizeof(ethernet_addr_t));
}

int
ethernet_set_addr (const char *addr) {
	return ethernet_addr_pton(addr, &g_ethernet.addr);
}

int
ethernet_add_handler (uint16_t type, __ethernet_handler_t handler) {
	if (g_ethernet.handler_num >= ETHERNET_HANDLER_TABLE_SIZE) {
		return -1;
	}
	g_ethernet.handler_table[g_ethernet.handler_num].type = hton16(type);
	g_ethernet.handler_table[g_ethernet.handler_num].handler = handler;
	g_ethernet.handler_num++;
	return 0;
}

void
ethernet_recv (uint8_t *frame, size_t flen) {
	struct ethernet_hdr *hdr;
	int offset;
	uint8_t *payload;
	size_t plen;

	if (flen < (ssize_t)sizeof(struct ethernet_hdr)) {
		return;
	}
	hdr = (struct ethernet_hdr *)frame;
	if (ethernet_addr_cmp(&g_ethernet.addr, &hdr->dst) != 0) {
		if (ethernet_addr_cmp(&ETHERNET_ADDR_BCAST, &hdr->dst) != 0) {
			return;
		}
	}
	payload = (uint8_t *)(hdr + 1);
	plen = flen - sizeof(struct ethernet_hdr);
	for (offset = 0; offset < g_ethernet.handler_num; offset++) {
		if (g_ethernet.handler_table[offset].type == hdr->type) {
			g_ethernet.handler_table[offset].handler(payload, plen, &hdr->src, &hdr->dst);
			break;
		}
	}
}

ssize_t
ethernet_send (uint16_t type, const uint8_t *payload, size_t plen, const ethernet_addr_t *dst) {
	uint8_t frame[ETHERNET_FRAME_SIZE_MAX];
	struct ethernet_hdr *hdr;
	size_t flen;

	if (!payload || plen > ETHERNET_PAYLOAD_SIZE_MAX || !dst) {
		return -1;
	}
	memset(&frame, 0x00, sizeof(frame));
	hdr = (struct ethernet_hdr *)&frame;
	memcpy(hdr->dst.addr, dst->addr, ETHERNET_ADDR_LEN);
	memcpy(hdr->src.addr, g_ethernet.addr.addr, ETHERNET_ADDR_LEN);
	hdr->type = hton16(type);
	memcpy(hdr + 1, payload, plen);
	flen = sizeof(struct ethernet_hdr) + (plen < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : plen);
	return device_write(frame, flen) == (ssize_t)flen ? (ssize_t)plen : -1;
}

int
ethernet_addr_pton (const char *p, ethernet_addr_t *n) {
	int index;
	char *ep;
	long val;

	if (!p || !n) {
		goto ERROR;
	}
	for (index = 0; index < ETHERNET_ADDR_LEN; index++) {
		val = strtol(p, &ep, 16);
		if (ep == p || val < 0 || val > 0xff || (index < ETHERNET_ADDR_LEN - 1 && *ep != ':')) {
			break;
		}
		n->addr[index] = (uint8_t)val;
		p = ep + 1;
	}
	if (index != ETHERNET_ADDR_LEN || *ep != '\0') {
		goto ERROR;
	}
	return  0;

ERROR:
	return -1;
}

char *
ethernet_addr_ntop (const ethernet_addr_t *n, char *p, size_t size) {
	
	if (!n || !p || size < ETHERNET_ADDR_STR_LEN + 1) {
		goto ERROR;
	}
	snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->addr[4], n->addr[5]);
	return p;

ERROR:
	return NULL;
}

int
ethernet_addr_cmp (const ethernet_addr_t *a, const ethernet_addr_t *b) {
	return memcmp(&a->addr, &b->addr, ETHERNET_ADDR_LEN);
}

int
ethernet_addr_isself (const ethernet_addr_t *addr) {
	return (ethernet_addr_cmp(addr, &g_ethernet.addr) == 0) ? 1 : 0;
}

#ifdef _ETHERNET_UNIT_TEST
#include <signal.h>
#include "util.h"

static void
arp_recv(uint8_t *packet, size_t plen, ethernet_addr_t *src, ethernet_addr_t *dst) {
	char ss[ETHERNET_ADDR_STR_LEN + 1], ds[ETHERNET_ADDR_STR_LEN + 1];

	fprintf(stderr, "%s > %s [ARP] length: %lu\n",
		ethernet_addr_ntop(src, ss, sizeof(ss)), ethernet_addr_ntop(dst, ds, sizeof(ds)), plen);
	hexdump(stderr, packet, plen);
}

static void
ip_recv(uint8_t *dgram, size_t dlen, ethernet_addr_t *src, ethernet_addr_t *dst) {
	char ss[ETHERNET_ADDR_STR_LEN + 1], ds[ETHERNET_ADDR_STR_LEN + 1];

	fprintf(stderr, "%s > %s [IP] length: %lu\n",
		ethernet_addr_ntop(src, ss, sizeof(ss)), ethernet_addr_ntop(dst, ds, sizeof(ds)), dlen);
	hexdump(stderr, dgram, dlen);
}

int
main (int argc, char *argv[]) {
	sigset_t sigset;
	int signo;

	if (argc != 3) {
		fprintf(stderr, "usage: %s device-name ethernet-addr\n", argv[0]);
        return -1;
	}
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
    device_init();
    if (device_open(argv[1]) == -1) {
        return -1;
    }
    device_set_handler(ethernet_recv);
	ethernet_init();
	if (ethernet_set_addr(argv[2]) == -1) {
        device_close();
        return -1;
	}
	ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
	ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
	if (device_dispatch() == -1) {
        device_close();
        return -1;
	}
	sigwait(&sigset, &signo);
	device_close();
	return 0;
}

#endif
