#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>

typedef struct device device_t;

extern device_t *
device_open (const char *name);
extern void
device_close (device_t *device);
extern void
device_input (device_t *device, void (*callback)(uint8_t *, size_t), int timeout);
extern ssize_t
device_output (device_t *device, const uint8_t *buffer, size_t length);

#endif
