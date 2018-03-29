#ifndef _MICROPS_H_
#define _MICROPS_H_

#include "util.h"
#include "device.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "dhcp.h"

struct microps_param {
    char *ethernet_device;
    char *ethernet_addr;
    char *ip_addr;
    char *ip_netmask;
    char *ip_gateway;
    uint8_t use_dhcp;
};

extern int
microps_init (const struct microps_param *param);
extern void
microps_cleanup (void);

#endif
