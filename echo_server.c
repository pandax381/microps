#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "microps.h"

int
main (int argc, char *argv[]) {
	struct udp_dsc *dsc;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;
	ssize_t len;

	if (argc != 6) {
		fprintf(stderr, "usage: %s device-name ethernet-addr ip-addr netmask default-gw\n", argv[0]);
		goto ERROR;
	}
	microps_init(argv[1], argv[2], argv[3], argv[4], argv[5]);
	dsc = udp_api_open("7");
	if (!dsc) {
		goto ERROR;
	}
	while (1) {
		len = udp_api_recv(dsc, buf, sizeof(buf), &peer_addr, &peer_port);
		if (len < 0) {
			break;
		}
		fprintf(stderr, "udp_api_recv(): %ld\n", len);
		hexdump(stderr, buf, len);
		udp_api_send(dsc, buf, len, &peer_addr, peer_port);
	}
	udp_api_close(dsc);
	microps_cleanup();
    return  0;

ERROR:
    return -1;
}
