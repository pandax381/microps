#include <stdio.h>
#include <pthread.h>
#include "microps.h"

int
microps_init (const struct microps_param *param) {
    if (ethernet_init() == -1) {
        goto ERROR;
	}
    if (ethernet_device_open(param->ethernet_device, param->ethernet_addr) == -1) {
        goto ERROR;
    }
	if (arp_init() == -1) {
        goto ERROR;
    }
    if (ip_init(param->ip_addr, param->ip_netmask, param->ip_gateway) == -1) {
        goto ERROR;
    }
    if (icmp_init() == -1) {
        goto ERROR;
    }
	if (udp_init() == -1) {
        goto ERROR;
    }
	if (tcp_init() == -1) {
        goto ERROR;
    }
    if (ethernet_device_run() == -1) {
        goto ERROR;        
    }
	return  0;

ERROR:
    microps_cleanup();
	return -1;
}

void
microps_cleanup (void) {
    ethernet_device_close();
}
