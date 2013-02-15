#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

typedef void (*__device_interrupt_handler_t)(uint8_t *, ssize_t);

extern int
device_init (const char *device_name, __device_interrupt_handler_t handler);
extern void
device_cleanup (void);
extern void
device_read_callback (uint8_t *buf, ssize_t len);
extern ssize_t
device_write (const uint8_t *buf, size_t len);

#endif
