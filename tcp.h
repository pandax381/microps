#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>

#include "ip.h"

#define TCP_ENDPOINT_STR_LEN (IP_ADDR_STR_LEN + 6) /* xxx.xxx.xxx.xxx:yyyyy\n */

struct tcp_endpoint {
    ip_addr_t addr;
    uint16_t port;
};

extern int
tcp_endpoint_pton(char *p, struct tcp_endpoint *n);
extern char *
tcp_endpoint_ntop(struct tcp_endpoint *n, char *p, size_t size);

extern int
tcp_open_rfc793(struct tcp_endpoint *local, struct tcp_endpoint *foreign, int active);
extern int
tcp_close(int id);
extern ssize_t
tcp_receive(int id, uint8_t *buf, size_t size);
extern ssize_t
tcp_send(int id, uint8_t *data, size_t len);

extern int
tcp_init(void);

#endif
