#include <stdio.h>
#include <pthread.h>
#include "microps.h"
#include "util.h"
#include "ethernet.h"
#include "slip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "dhcp.h"

int
microps_init (void) {
    if (ethernet_init() == -1) {
        goto ERROR;
    }
    if (slip_init() == -1) {
        goto ERROR;
    }
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
    return  0;

ERROR:
    microps_cleanup();
    return -1;
}

void
microps_cleanup (void) {
    //ethernet_device_close();
}
