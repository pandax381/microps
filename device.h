#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef void (*__device_interrupt_handler_t)(uint8_t *, size_t);

extern int
device_init (const char *device_name, __device_interrupt_handler_t handler);
extern void
device_cleanup (void);
extern ssize_t
device_write (const uint8_t *buf, size_t len);
ssize_t
device_writev (const struct iovec *iov, int iovcnt);

#endif
