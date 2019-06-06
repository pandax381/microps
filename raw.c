#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "raw.h"

#define RAW_DEV_DECLARE(TYPE) \
    static int \
    TYPE##_dev_open_wrap (struct rawdev *raw) { \
        raw->priv = TYPE##_dev_open(raw->name); \
        return raw->priv ? 0 : -1; \
    } \
    static void \
    TYPE##_dev_close_wrap (struct rawdev *raw) { \
        TYPE##_dev_close(raw->priv); \
    } \
    \
    static void \
    TYPE##_dev_rx_wrap (struct rawdev *raw, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) { \
        TYPE##_dev_rx(raw->priv, callback, arg, timeout); \
    } \
    static ssize_t \
    TYPE##_dev_tx_wrap (struct rawdev *raw, const uint8_t *buf, size_t len) { \
        return TYPE##_dev_tx(raw->priv, buf, len); \
    } \
    static int \
    TYPE##_dev_addr_wrap (struct rawdev *raw, uint8_t *dst, size_t size) { \
        return TYPE##_dev_addr(raw->name, dst, size); \
    } \
    struct rawdev_ops TYPE##_dev_ops = { \
        .open = TYPE##_dev_open_wrap, \
        .close = TYPE##_dev_close_wrap, \
        .rx = TYPE##_dev_rx_wrap, \
        .tx = TYPE##_dev_tx_wrap, \
        .addr = TYPE##_dev_addr_wrap, \
    }; \

#include "raw/tap.h"
RAW_DEV_DECLARE(tap)

#ifdef __linux__
#include "raw/soc.h"
RAW_DEV_DECLARE(soc)
#define RAWDEV_TYPE_DEFAULT RAWDEV_TYPE_SOCKET
#endif

#ifdef __APPLE__
#include "raw/bpf.h"
RAW_DEV_DECLARE(bpf)
#define RAWDEV_TYPE_DEFAULT RAWDEV_TYPE_BPF
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
