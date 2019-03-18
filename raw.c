#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "raw.h"

struct rawdev_driver {
    struct rawdev_driver *next;
    uint8_t type;
    struct rawdev_ops *ops;
};

static struct rawdev_driver *drivers;

int
rawdev_register (uint8_t type, struct rawdev_ops *ops) {
    struct rawdev_driver *new_entry;

    new_entry = malloc(sizeof(struct rawdev_driver));
    if (!new_entry) {
        return -1;
    }
    new_entry->next = drivers;
    new_entry->type = type;
    new_entry->ops = ops;
    drivers = new_entry;
    return 0;
}

struct rawdev *
rawdev_alloc (uint8_t type, char *name) {
    struct rawdev_driver *entry;
    struct rawdev *dev;

    if (type == RAWDEV_TYPE_AUTO) {
        if (strncmp(name, "tap", 3) == 0) {
            type = RAWDEV_TYPE_TAP;
        } else {
#ifdef __linux__
            type = RAWDEV_TYPE_SOCKET;
#endif
#ifdef __APPLE__
            type = RAWDEV_TYPE_BPF;
#endif
        }
    }
    for (entry = drivers; entry; entry = entry->next) {
        if (entry->type == type) {
            break;
        }
    }
    if (!entry) {
        return NULL;
    }
    dev = malloc(sizeof(struct rawdev));
    if (!dev) {
        return NULL;
    }
    dev->type = entry->type;
    dev->name = name;
    dev->ops = entry->ops;
    dev->priv = NULL;
    return dev;
}

extern int
raw_socket_init (void);
extern int
raw_bpf_init (void);
extern int
raw_tap_init (void);

int
rawdev_init (void) {
#ifdef __linux__
    if (raw_socket_init() == -1) {
        return -1;
    }
#endif
#ifdef __APPLE__
    if (raw_bpf_init() == -1) {
        return -1;
    }
#endif
#ifdef HAVE_TAP
    if (raw_tap_init() == -1) {
        return -1;
    }
#endif
    return 0;
}
