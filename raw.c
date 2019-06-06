#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "raw.h"

#include "raw/tap.h"

static int
tap_dev_open_wrap (struct rawdev *raw) {
    raw->priv = tap_dev_open(raw->name);
    return raw->priv ? 0 : -1;
}

static void
tap_dev_close_wrap (struct rawdev *raw) {
    tap_dev_close(raw->priv);
}

static void
tap_dev_rx_wrap (struct rawdev *raw, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    tap_dev_rx(raw->priv, callback, arg, timeout);
}

static ssize_t
tap_dev_tx_wrap (struct rawdev *raw, const uint8_t *buf, size_t len) {
    return tap_dev_tx(raw->priv, buf, len);
}

static int
tap_dev_addr_wrap (struct rawdev *raw, uint8_t *dst, size_t size) {
    return tap_dev_addr(raw->name, dst, size);
}

struct rawdev_ops tap_dev_ops = {
    .open = tap_dev_open_wrap,
    .close = tap_dev_close_wrap,
    .rx = tap_dev_rx_wrap,
    .tx = tap_dev_tx_wrap,
    .addr = tap_dev_addr_wrap,
};

#ifdef __linux__
#include "raw/soc.h"

static int
soc_dev_open_wrap (struct rawdev *raw) {
    raw->priv = soc_dev_open(raw->name);
    return raw->priv ? 0 : -1;
}

static void
soc_dev_close_wrap (struct rawdev *raw) {
    soc_dev_close(raw->priv);
}

static void
soc_dev_rx_wrap (struct rawdev *raw, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    soc_dev_rx(raw->priv, callback, arg, timeout);
}

static ssize_t
soc_dev_tx_wrap (struct rawdev *raw, const uint8_t *buf, size_t len) {
    return soc_dev_tx(raw->priv, buf, len);
}

static int
soc_dev_addr_wrap (struct rawdev *raw, uint8_t *dst, size_t size) {
    return soc_dev_addr(raw->name, dst, size);
}

struct rawdev_ops soc_dev_ops = {
    .open = soc_dev_open_wrap,
    .close = soc_dev_close_wrap,
    .rx = soc_dev_rx_wrap,
    .tx = soc_dev_tx_wrap,
    .addr = soc_dev_addr_wrap,
};
#endif

#ifdef __APPLE__
#include "raw/bpf.h"

static int
bpf_dev_open_wrap (struct rawdev *raw) {
    raw->priv = bpf_dev_open(raw->name);
    return raw->priv ? 0 : -1;
}

static void
bpf_dev_close_wrap (struct rawdev *raw) {
    bpf_dev_close(raw->priv);
}

static void
bpf_dev_rx_wrap (struct rawdev *raw, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    bpf_dev_rx(raw->priv, callback, arg, timeout);
}

static ssize_t
bpf_dev_tx_wrap (struct rawdev *raw, const uint8_t *buf, size_t len) {
    return bpf_dev_tx(raw->priv, buf, len);
}

static int
bpf_dev_addr_wrap (struct rawdev *raw, uint8_t *dst, size_t size) {
    return bpf_dev_addr(raw->name, dst, size);
}

struct rawdev_ops bpf_dev_ops = {
    .open = bpf_dev_open_wrap,
    .close = bpf_dev_close_wrap,
    .rx = bpf_dev_rx_wrap,
    .tx = bpf_dev_tx_wrap,
    .addr = bpf_dev_addr_wrap,
};
#endif

static uint8_t
rawdev_detect_type (char *name) {
    if (strncmp(name, "tap", 3) == 0) {
        return RAWDEV_TYPE_TAP;
    }
#ifdef __linux__
    return RAWDEV_TYPE_SOCKET;
#endif
#ifdef __APPLE__
    return RAWDEV_TYPE_BPF;
#endif
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
