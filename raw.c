#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "raw.h"

#include "raw/tap.h"
extern struct rawdev_ops tap_dev_ops;

#ifdef __linux__
#include "raw/soc.h"
#define RAWDEV_TYPE_DEFAULT RAWDEV_TYPE_SOCKET
extern struct rawdev_ops soc_dev_ops;
#endif

#ifdef __APPLE__
#include "raw/bpf.h"
#define RAWDEV_TYPE_DEFAULT RAWDEV_TYPE_BPF
extern struct rawdev_ops bpf_dev_ops;
#endif

static uint8_t
rawdev_detect_type (char *name) {
    if (strncmp(name, "tap", 3) == 0) {
        return RAWDEV_TYPE_TAP;
    }
    return RAWDEV_TYPE_DEFAULT;
}

struct rawdev *
rawdev_alloc (uint8_t type, char *name) {
    struct rawdev *raw;
    struct rawdev_ops *ops;

    if (type == RAWDEV_TYPE_AUTO) {
        type = rawdev_detect_type(name);
    }    
    switch (type) {
    case RAWDEV_TYPE_TAP:
        ops = &tap_dev_ops;
        break;
#ifdef __linux__
    case RAWDEV_TYPE_SOCKET:
        ops = &soc_dev_ops;
        break;
#endif
#ifdef __APPLE__
    case RAWDEV_TYPE_BPF:
        ops = &bpf_dev_ops;
        break;
#endif
    default:
        return NULL;
    }
    raw = malloc(sizeof(struct rawdev));
    if (!raw) {
        return NULL;
    }
    raw->type = type;
    raw->name = name;
    raw->ops = ops;
    raw->priv = NULL;
    return raw;
}
