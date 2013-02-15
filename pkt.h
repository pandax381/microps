#ifndef _UTCPS_PKT_H_
#define _UTCPS_PKT_H_

#include <stdint.h>
#include <sys/types.h>

typedef struct pkt pkt_t;

extern pkt_t;
pkt_open (pkt_t *obj, const char *name);
extern void
pkt_close (pkt_t *obj);
extern ssize_t
pkt_write (pkt_t *obj, const uint8_t *buffer, size_t length);
extern ssize_t
pkt_read (pkt_t *obj, uint8_t *buffer, size_t length);

#endif
