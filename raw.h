#ifndef RAW_H
#define RAW_H

#include <stddef.h>
#include <stdint.h>

struct raw_device;

extern struct raw_device *
raw_open (const char *name);
extern void
raw_close (struct raw_device *dev);
extern void
raw_rx (struct raw_device *dev, void (*callback)(uint8_t *flame, size_t size, void *arg), void *arg, int timeout);
extern ssize_t
raw_tx (struct raw_device *dev, const uint8_t *buffer, size_t length);
extern int
raw_addr (struct raw_device *dev, uint8_t *dst, size_t size);

#endif
