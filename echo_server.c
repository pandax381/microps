#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "microps.h"

/*
struct microps_param param = {
    .ethernet_device = "en2",
    .ethernet_addr = "00:1f:5b:fe:ef:cd",
    .ip_addr = "10.10.2.228",
    .ip_netmask = "255.255.0.0",
    .ip_gateway = "10.10.0.1"
};
*/
struct microps_param param = {
    .ethernet_device = "en0",
    .ethernet_addr = "58:55:ca:fb:6e:9f",
    .ip_addr = "10.13.100.100",
    .ip_netmask = "255.255.0.0",
    .ip_gateway = "10.13.0.1"
};

int
main (int argc, char *argv[]) {
	int soc, acc;
    ip_addr_t peer;
	uint8_t buf[65536];
	ssize_t len;

	microps_init(&param);
	soc = tcp_api_open();
    if (soc == -1) {
fprintf(stderr, "err1\n");
        microps_cleanup();
        return -1;
	}
/*
    if (tcp_api_bind(soc, 7) == -1) {
fprintf(stderr, "err2\n");
        tcp_api_close(soc);
        microps_cleanup();
        return -1;
    }
    tcp_api_listen(soc);
    acc = tcp_api_accept(soc);
    if (acc == -1) {
fprintf(stderr, "err3\n");
        tcp_api_close(soc);
        microps_cleanup();
        return -1;
    }
fprintf(stderr, "accept success, soc=%d, acc=%d\n", soc, acc);
*/
    ip_addr_pton("10.10.2.98", &peer);
    if (tcp_api_connect(soc, &peer, 7) == -1) {
fprintf(stderr, "err2\n");
        tcp_api_close(soc);
        microps_cleanup();
        return -1;
    }
fprintf(stderr, "connect success\n");
	while (1) {
		len = tcp_api_recv(soc, buf, sizeof(buf));
fprintf(stderr, "tcp_api_recv(): %ld\n", len);
		if (len <= 0) {
			break;
		}
		hexdump(stderr, buf, len);
		tcp_api_send(soc, buf, len);
	}
/*
	tcp_api_close(acc);
*/
	tcp_api_close(soc);
	microps_cleanup();
    return  0;
}
