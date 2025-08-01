#ifndef TCP_H
#define TCP_H

#include "ip.h"

extern int
tcp_init(void);

extern int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active);
extern int
tcp_close(int id);

#endif