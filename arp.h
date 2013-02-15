#ifndef _ARP_H_
#define _ARP_H_

#include "ethernet.h"
#include "ip.h"

extern int
arp_table_lookup (const ip_addr_t *pa, ethernet_addr_t *ha);
extern void
arp_recv (uint8_t *buf, ssize_t len, int bcast);

#endif
