#ifndef _ARP_H_
#define _ARP_H_

#include <stdio.h>
#include "ethernet.h"
#include "ip.h"

extern int
arp_init (void);
extern int
arp_resolve (const ip_addr_t *pa, ethernet_addr_t *ha, const void *data, size_t len);

#endif
