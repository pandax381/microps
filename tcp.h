#ifndef TCP_H
#define TCP_H

#include "ip.h"

extern int
tcp_init(void);

extern int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active);
extern int
tcp_close(int id);
extern ssize_t
tcp_send(int id, uint8_t *data, size_t len);
extern ssize_t
tcp_receive(int id, uint8_t *buf, size_t size);

#endif
