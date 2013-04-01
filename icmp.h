#ifndef _ICMP_H_
#define _ICMP_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "ip.h"

extern int
icmp_init (void);
extern void
icmp_recv (uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst);

#endif
