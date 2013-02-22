#ifndef _UDP_H_
#define _UDP_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "ip.h"

struct udp_dsc;

extern void
udp_init (void);
extern void
udp_recv (uint8_t *dgram, size_t dlen, ip_addr_t *src, ip_addr_t *dst);
extern ssize_t
udp_send (struct udp_dsc *dsc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);
extern struct udp_dsc *
udp_api_open (const char *port);
extern void
udp_api_close (struct udp_dsc *dsc);
extern ssize_t
udp_api_recv (struct udp_dsc *dsc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port);
extern ssize_t
udp_api_send (struct udp_dsc *dsc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);

#endif
