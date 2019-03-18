#ifndef RAW_H
#define RAW_H

#include <stddef.h>
#include <stdint.h>
#include <net/if.h>
#include "net.h"

#define RAWDEV_TYPE_AUTO 0
#define RAWDEV_TYPE_SOCKET 1
#define RAWDEV_TYPE_BPF 2
#define RAWDEV_TYPE_TAP 3

struct rawdev;

struct rawdev_ops {
    int (*open)(struct rawdev *dev);
    void (*close)(struct rawdev *dev);
    void (*rx)(struct rawdev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout);
    ssize_t (*tx)(struct rawdev *dev, const uint8_t *buffer, size_t length);
    int (*addr)(struct rawdev *dev, uint8_t *dst, size_t size);
};

struct rawdev {
    uint8_t type;
    char *name;
    struct rawdev_ops *ops;
    void *priv;
};

extern int
rawdev_register (uint8_t type, struct rawdev_ops *ops);
extern struct rawdev *
rawdev_alloc (uint8_t type, char *name);
extern int
rawdev_init (void);

#endif
