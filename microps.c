#include <stdio.h>
#include "microps.h"

int
microps_init (const char *device_name, const char *ethernet_addr, const char *ip_addr, const char *netmask, const char *gw) {
    device_init();
    if (device_open(device_name) == -1) {
		fprintf(stderr, "error: device-name invalid\n");
        return -1;
    }
    device_set_handler(ethernet_recv);
    ethernet_init();
    if (ethernet_set_addr(ethernet_addr) == -1) {
		fprintf(stderr, "error: ethernet-addr invalid\n");
		goto ERROR;
	}
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
	arp_init();
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
	udp_init();
    if (device_dispatch() == -1) {
		fprintf(stderr, "error: device dispatch error\n");
        goto ERROR;
    }
	arp_send_garp();
	return  0;

ERROR:
    device_close();
	return -1;
}

void
microps_cleanup (void) {
    device_close();
}
