#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

extern ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *buf, size_t len);

extern int
udp_init(void);

#endif