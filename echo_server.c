#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "microps.h"

struct microps_param param = {
    .ethernet_device = "en2",
    .ethernet_addr = "00:1f:5b:fe:ef:cd",
    .ip_addr = "10.10.2.228",
    .ip_netmask = "255.255.0.0",
    .ip_gateway = "10.10.0.1"
};
/*
struct microps_param param = {
    .ethernet_device = "en0",
    .ethernet_addr = "58:55:ca:fb:6e:9f",
    .ip_addr = "10.13.100.100",
    .ip_netmask = "255.255.0.0",
    .ip_gateway = "10.13.0.1"
};
*/

int
main (int argc, char *argv[]) {
	int soc;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;
	ssize_t len;

	microps_init(&param);
	soc = udp_api_open();
    if (soc == -1) {
        microps_cleanup();
        return -1;
	}
    if (udp_api_bind(soc, 7) == -1) {
fprintf(stderr, "error\n");
        udp_api_close(soc);
        microps_cleanup();
        return -1;
    }
	while (1) {
		len = udp_api_recv(soc, buf, sizeof(buf), &peer_addr, &peer_port);
		if (len < 0) {
			break;
		}
		fprintf(stderr, "udp_api_recv(): %ld\n", len);
		hexdump(stderr, buf, len);
		udp_api_send(soc, buf, len, &peer_addr, peer_port);
	}
	udp_api_close(soc);
	microps_cleanup();
    return  0;
}
