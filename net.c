#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

struct net_protocol {
    struct net_protocol *next;
    char name[16];
    uint16_t type;
    pthread_mutex_t mutex; /* mutex for input queue */
    struct queue_head queue; /* input queue */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/* NOTE: The data follows immediately after the structure */
struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *
net_device_alloc(void (*setup)(struct net_device *dev))
{
    struct net_device *dev;

    dev = calloc(1, sizeof(*dev));
    if (!dev) {
        errorf("calloc() failure");
        return NULL;
    }
    if (setup) {
        setup(dev);
    }
    return dev;
}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registerd, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int
net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s, type=%s(0x%04x), len=%zu", dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            entry = calloc(1, sizeof(*entry) + len);
            if (!entry) {
                errorf("calloc() failure");
                return -1;
            }
            entry->dev = dev;
            entry->len = len;
            memcpy(entry+1, data, len);
            pthread_mutex_lock(&proto->mutex);
            if (queue_push(&proto->queue, entry) == NULL) {
                errorf("queue_push() failure");
                pthread_mutex_unlock(&proto->mutex);
                return -1;
            }
            pthread_mutex_unlock(&proto->mutex);
            debugf("queue pushed, dev=%s, type=%s(0x%04x), len=%zd", dev->name, proto->name, type, len);
            debugdump(data, len);
            return 0;
        }
    }
    /* unsupported protocol */
    return 0;
}

/* NOTE: must not be call after net_run() */
int
net_protocol_register(const char *name, uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registerd, type=0x%04x", type);
            return -1;
        }
    }
    proto = calloc(1, sizeof(*proto));
    if (!proto) {
        errorf("calloc() failure");
        return -1;
    }
    strncpy(proto->name, name, MIN(strlen(name), sizeof(proto->name)-1));
    proto->type = type;
    pthread_mutex_init(&proto->mutex, NULL);
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registerd, type=%s(0x%04x)", proto->name, type);
    return 0;
}

char *
net_protocol_name(uint16_t type)
{
    struct net_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            return entry->name;
        }
    }
    return "UNKNOWN";
}

int
net_run(void)
{
    struct net_device *dev;

    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    debugf("shutdown");
}

int
net_init(void)
{
    /* do nothing */
    return 0;
}
