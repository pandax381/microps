#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef void (*__device_handler_t)(uint8_t *, size_t);

extern void
device_init (void);
extern int
device_open (const char *device_name);
extern void
device_close (void);
extern void
device_set_handler (__device_handler_t handler);
extern int
device_dispatch (void);
extern ssize_t
device_write (const uint8_t *buf, size_t len);

#endif
