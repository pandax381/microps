#ifndef _IP_H_
#define _IP_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "ethernet.h"

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_RAW 255

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 15

#define IP_DATA_SIZE_MAX 65535

typedef uint32_t ip_addr_t;

struct ip_hdr {
	uint8_t vhl;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
	ip_addr_t dst;
	uint8_t options[0];
};

typedef void (*__ip_handler_t)(uint8_t *, size_t, ip_addr_t *, ip_addr_t *);

extern ip_addr_t *
ip_get_addr (ip_addr_t *dst);
extern int
ip_set_addr (const char *addr, const char *mask);
extern int
ip_set_gw (const char *gw);
extern int
ip_add_handler (uint8_t protocol, __ip_handler_t handler);
extern void
ip_recv (uint8_t *dgram, size_t dlen, ethernet_addr_t *src, ethernet_addr_t *dst);
extern ssize_t
ip_send (uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *addr);
extern int
ip_addr_pton (const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size);
extern int
ip_addr_cmp (const ip_addr_t *a, const ip_addr_t *b);
extern int
ip_addr_isself (const ip_addr_t *addr);
extern int
ip_addr_islink (const ip_addr_t *addr);

#endif
