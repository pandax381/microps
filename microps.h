#ifndef _MICROPS_H_
#define _MICROPS_H_

#include "util.h"
#include "device.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"

extern int
microps_init (const char *device_name, const char *ethernet_addr, const char *ip_addr, const char *netmask, const char *gw);
extern void
microps_cleanup (void);

#endif
