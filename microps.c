#include <stdio.h>
#include "microps.h"

int
microps_init (const char *device_name, const char *ethernet_addr, const char *ip_addr, const char *netmask, const char *gw) {
	udp_init();
	if (ip_set_addr(ip_addr, netmask) == -1) {
		fprintf(stderr, "error: ip-addr/netmask is invalid\n");
		goto ERROR;
	}
	if (ip_set_gw(gw) == -1) {
		fprintf(stderr, "error: default-gw is invalid\n");
		goto ERROR;
	}
	ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
	ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
	arp_init();
    if (ethernet_set_addr(ethernet_addr) == -1) {
		fprintf(stderr, "error: ethernet-addr invalid\n");
		goto ERROR;
	}
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(device_name, ethernet_recv) == -1) {
		fprintf(stderr, "error: device-name invalid\n");
        goto ERROR;
    }
	arp_send_garp();
	return  0;

ERROR:
	return -1;
}

void
microps_cleanup (void) {
    device_cleanup();
}
