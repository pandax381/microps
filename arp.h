#ifndef _ARP_H_
#define _ARP_H_

#include "ethernet.h"
#include "ip.h"

extern int
arp_init (void);
extern int
arp_resolve (const ip_addr_t *pa, ethernet_addr_t *ha);

#endif
