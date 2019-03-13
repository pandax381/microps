#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

#define ICMP_UNREACH 3
#define ICMP_UNREACH_NET 0

#define ICMP_TIMXCEED 11
#define ICMP_TIMXCEED_INTRANS 0

extern int
icmp_error_tx (struct netif *iface, uint8_t type, uint8_t code, uint8_t *ip_dgram, size_t ip_dlen);
extern int
icmp_init (void);

#endif
