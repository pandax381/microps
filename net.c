#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "util.h"
#include "net.h"

struct net_protocol {
    struct net_protocol *next;
    uint16_t type;
    pthread_mutex_t mutex; /* mutex for input queue */
    struct queue_head queue; /* input queue */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/* NOTE: the data follows immediately after the structure */
struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;

    dev = calloc(1, sizeof(*dev));
    if (!dev) {
        errorf("calloc() failure");
        return NULL;
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
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
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

/* NOTE: must not be call after net_run() */
int
net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{

}

struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{

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
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
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
    unsigned int num;

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
            if (!queue_push(&proto->queue, entry)) {
                pthread_mutex_unlock(&proto->mutex);
                errorf("queue_push() failure");
                free(entry);
                return -1;
            }
            num = proto->queue.num;
            pthread_mutex_unlock(&proto->mutex);
            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
            debugdump(data, len);
            return 0;
        }
    }
    /* unsupported protocol */
    return 0;
}

/* NOTE: must not be call after net_run() */
int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }
    proto = calloc(1, sizeof(*proto));
    if (!proto) {
        errorf("calloc() failure");
        return -1;
    }
    proto->type = type;
    pthread_mutex_init(&proto->mutex, NULL);
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

#define NET_THREAD_SLEEP_TIME 1000 /* micro seconds */

static pthread_t thread;
static volatile sig_atomic_t terminate;

static void *
net_thread(void *arg)
{
    unsigned int count, num;
    struct net_device *dev;
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    while (!terminate) {
        count = 0;
        for (dev = devices; dev; dev = dev->next) {
            if (NET_DEVICE_IS_UP(dev)) {
                if (dev->ops->poll) {
                    if (dev->ops->poll(dev) != -1) {
                        count++;
                    }
                }
            }
        }
        for (proto = protocols; proto; proto = proto->next) {
            pthread_mutex_lock(&proto->mutex);
            entry = (struct net_protocol_queue_entry *)queue_pop(&proto->queue);
            num = proto->queue.num;
            pthread_mutex_unlock(&proto->mutex);
            if (entry) {
                debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", num, entry->dev->name, proto->type, entry->len);
                debugdump((uint8_t *)(entry+1), entry->len);
                proto->handler((uint8_t *)(entry+1), entry->len, entry->dev);
                free(entry);
                count++;
            }
        }
        if (!count) {
            usleep(NET_THREAD_SLEEP_TIME);
        }
    }
    return NULL;
}

int
net_run(void)
{
    struct net_device *dev;
    int err;

    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("create background thread...");
    err = pthread_create(&thread, NULL, net_thread, NULL);
    if (err) {
        errorf("pthread_create() failure, err=%d", err);
        return -1;
    }
    debugf("running...");
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;
    int err;

    debugf("terminate background thread...");
    terminate = 1;
    err = pthread_join(thread, NULL);
    if (err) {
        errorf("pthread_join() failure, err=%d", err);
        return;
    }
    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    debugf("shutdown");
}

#include "ip.h"

int
net_init(void)
{
    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }
    return 0;
}
