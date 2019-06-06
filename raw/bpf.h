#ifndef BPF_DEV_H
#define BPF_DEV_H

#include <stddef.h>
#include <stdint.h>

struct bpf_dev;

extern int
bpf_dev_open (char *name);
extern void
bpf_dev_close (struct bpf_dev *dev);
extern void
bpf_dev_rx (struct bpf_dev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout);
extern ssize_t
bpf_dev_tx (struct bpf_dev *dev, const uint8_t *buf, size_t len);
extern int
bpf_dev_addr (char *name, uint8_t *dst, size_t size);

#endif
