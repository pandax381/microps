#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>

#define IP_VERSION_IPV4 4

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60

#define IP_TOTAL_SIZE_MAX UINT16_MAX /* maximum value of uint16 */
#define IP_PAYLOAD_SIZE_MAX (IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN)

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 /* "ddd.ddd.ddd.ddd\0" */

typedef uint32_t ip_addr_t;

extern const ip_addr_t IP_ADDR_ANY;
extern const ip_addr_t IP_ADDR_BROADCAST;

extern int
ip_addr_pton(const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size);

extern int
ip_init(void);

#endif
