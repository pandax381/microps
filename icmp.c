#include <stdio.h>
#include <signal.h>
#include "icmp.h"
#include "util.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8

struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t sum;
};

struct icmp_echo {
	struct icmp_hdr hdr;
	uint16_t id;
	uint16_t seq;
	uint8_t data[0];
};

void
icmp_recv (uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst) {
	struct icmp_hdr *hdr;

	(void)dst;
	if (plen < sizeof(struct icmp_hdr)) {
		return;
	}
	hdr = (struct icmp_hdr *)packet;
#ifdef _ICMP_UNIT_TEST
	char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];
	fprintf(stderr, "icmp recv: %s > %s, type %u, code %u, length %lu\n",
		ip_addr_ntop(src, ss, sizeof(ss)), ip_addr_ntop(dst, ds, sizeof(ds)), hdr->type, hdr->code, plen);
	//hexdump(stderr, packet, plen);
#endif
	if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
		hdr->type = ICMP_TYPE_ECHO_REPLY;
		hdr->sum = 0;
		hdr->sum = cksum16((uint16_t *)hdr, plen, 0);
		ip_send(IP_PROTOCOL_ICMP, packet, plen, src);
	}
}

#ifdef _ICMP_UNIT_TEST
#include "device.h"
#include "ethernet.h"
#include "arp.h"

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
	arp_init();
    if (ethernet_set_addr(argv[2]) == -1) {
		fprintf(stderr, "error: ethernet-addr invalid\n");
		goto ERROR;
	}
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(argv[1], ethernet_recv) == -1) {
		fprintf(stderr, "error: device-name invalid\n");
        goto ERROR;
    }
	sigwait(&sigset, &signo);
    device_cleanup();
    return  0;

ERROR:
    return -1;
}
#endif
