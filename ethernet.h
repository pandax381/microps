#ifndef _ETHERNET_H_
#define _ETHERNET_H_

#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_LOOPBACK 0x9000

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_ADDR_STR_LEN 17

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

typedef struct {
	uint8_t addr[ETHERNET_ADDR_LEN];
} __attribute__ ((packed)) ethernet_addr_t;

typedef void (*__ethernet_handler_t)(uint8_t *, size_t, ethernet_addr_t *src, ethernet_addr_t *dst);

extern const ethernet_addr_t ETHERNET_ADDR_BCAST;

extern void
ethernet_init (void);
extern ethernet_addr_t *
ethernet_get_addr (void);
extern int
ethernet_set_addr (const char *addr);
extern int
ethernet_add_handler (uint16_t type, __ethernet_handler_t handler);
extern void
ethernet_recv (uint8_t *frame, size_t flen);
extern ssize_t
ethernet_send (uint16_t type, const uint8_t *payload, size_t plen, const ethernet_addr_t *dst);
extern int
ethernet_addr_pton (const char *p, ethernet_addr_t *n);
extern char *
ethernet_addr_ntop (const ethernet_addr_t *n, char *p, size_t size);
extern int
ethernet_addr_cmp (const ethernet_addr_t *a, const ethernet_addr_t *b);
extern int
ethernet_addr_isself (const ethernet_addr_t *addr);

#endif
