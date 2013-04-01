#ifndef _UDP_H_
#define _UDP_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "ip.h"

struct udp_cb;

extern int
udp_init (void);
extern void
udp_recv (uint8_t *dgram, size_t dlen, ip_addr_t *src, ip_addr_t *dst);
extern ssize_t
udp_send (uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);
extern int
udp_api_open (void);
extern int
udp_api_close (int soc);
extern int
udp_api_bind (int soc, uint16_t port);
extern ssize_t
udp_api_recv (int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port);
extern ssize_t
udp_api_send (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);

#endif
