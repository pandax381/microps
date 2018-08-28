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

struct ip_interface;

typedef void (*__ip_protocol_handler_t)(uint8_t *, size_t, ip_addr_t *, ip_addr_t *, struct ip_interface *);

extern const ip_addr_t IP_ADDR_BCAST;

extern int
ip_addr_pton (const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size);
extern ip_addr_t
ip_get_addr (void *device, ip_addr_t *dst);
extern struct ip_interface *
ip_get_interface_by_addr (ip_addr_t *addr);
extern struct ip_interface *
ip_get_interface_by_peer (ip_addr_t *peer);
extern void *
ip_get_device(struct ip_interface *);
extern void *
ip_interface_device (struct ip_interface *iface);
extern ip_addr_t
ip_interface_addr (struct ip_interface *iface);
extern int
ip_add_protocol (uint8_t protocol, __ip_protocol_handler_t handler);
extern ssize_t
ip_output (struct ip_interface *iface, uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *addr);
extern struct ip_interface *
ip_register_interface (void *device, const char *addr, const char *netmask, const char *gateway);
extern int
ip_init (void);

#endif
