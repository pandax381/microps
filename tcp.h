#include <stdio.h>
#include <stdint.h>

extern int
tcp_init (void);
extern int
tcp_api_open (void);
extern int
tcp_api_close (int soc);
extern int
tcp_api_bind (int soc, uint16_t port);
extern int
tcp_api_listen (int soc);
extern int
tcp_api_accept (int soc);
extern ssize_t
tcp_api_recv (int soc, uint8_t *buf, size_t size);
extern ssize_t
tcp_api_send (int soc, uint8_t *buf, size_t len);
