#include <stdio.h>
#include <pthread.h>
#include "microps.h"
#ifdef USE_DPDK
#include "dpdk.h"
#endif

int
microps_init (const struct microps_param *param) {
    struct ethernet_device *device;
    struct ip_interface *iface;

    if (ethernet_init() == -1) {
        goto ERROR;
    }
#ifdef USE_DPDK
    if (dpdk_init() == -1) {
        goto ERROR;
    }
#endif
    if (arp_init() == -1) {
        goto ERROR;
    }
    if (ip_init() == -1) {
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
    device = ethernet_device_open(param->ethernet_device, param->ethernet_addr);
    if (!device) {
        goto ERROR;
    }
    iface = ip_register_interface(device, param->ip_addr, param->ip_netmask, param->ip_gateway);
    if (!iface) {
        goto ERROR;
    }
    if (ethernet_device_run(device) == -1) {
        goto ERROR;
    }
/*
    if (param->use_dhcp) {
        if (dhcp_init(iface) == -1) {
          goto ERROR;
        }
    }
*/
    return  0;
ERROR:
    microps_cleanup();
    return -1;
}

void
microps_cleanup (void) {
    //ethernet_device_close();
}
