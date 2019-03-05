#ifndef _UDP_H_
#define _UDP_H_

#include <stddef.h>
#include <stdint.h>
#include "net.h"
#include "ip.h"

extern int
udp_api_open (void);
extern int
udp_api_close (int soc);
extern int
udp_api_bind (int soc, ip_addr_t *addr, uint16_t port);
extern int
udp_api_bind_iface (int soc, struct netif *iface, uint16_t port);
extern ssize_t
udp_api_recvfrom (int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port, int timeout);
extern ssize_t
udp_api_sendto (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);
extern int
udp_init (void);

#endif
