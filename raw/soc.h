#ifndef SOC_DEV_H
#define SOC_DEV_H

#include <stddef.h>
#include <stdint.h>

struct soc_dev;

extern struct soc_dev *
soc_dev_open (char *name);
extern void
soc_dev_close (struct soc_dev *dev);
extern void
soc_dev_rx (struct soc_dev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout);
extern ssize_t
soc_dev_tx (struct soc_dev *dev, const uint8_t *buf, size_t len);
extern int
soc_dev_addr (char *name, uint8_t *dst, size_t size);

#endif
