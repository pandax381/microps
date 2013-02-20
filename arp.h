#ifndef _ARP_H_
#define _ARP_H_

#include "ethernet.h"
#include "ip.h"

extern void
arp_init (void);
extern int
arp_table_lookup (const ip_addr_t *pa, ethernet_addr_t *ha);
extern void
arp_recv (uint8_t *packet, size_t plen, ethernet_addr_t *src, ethernet_addr_t *dst);
extern int
arp_send_garp (void);

#endif
