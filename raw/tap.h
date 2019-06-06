#ifndef TAP_DEV_H
#define TAP_DEV_H

#include <stddef.h>
#include <stdint.h>

struct tap_dev;

extern struct tap_dev *
tap_dev_open (char *name);
extern void
tap_dev_close (struct tap_dev *dev);
extern void
tap_dev_rx (struct tap_dev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout);
extern ssize_t
tap_dev_tx (struct tap_dev *dev, const uint8_t *buf, size_t len);
extern int
tap_dev_addr (char *name, uint8_t *dst, size_t size);

#endif
