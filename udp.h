#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

#define UDP_ENDPOINT_STR_LEN (IP_ADDR_STR_LEN + 6) /* xxx.xxx.xxx.xxx:yyyyy\n */

struct udp_endpoint {
    ip_addr_t addr;
    uint16_t port;
};

extern int
udp_endpoint_pton(char *p, struct udp_endpoint *n);
extern char *
udp_endpoint_ntop(struct udp_endpoint *n, char *p, size_t size);

extern ssize_t
udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, const uint8_t *buf, size_t len);

extern int
udp_init(void);

#endif
