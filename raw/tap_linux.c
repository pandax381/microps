#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "tap.h"

#define CLONE_DEVICE "/dev/net/tun"

struct tap_dev {
    int fd;
};

void
tap_dev_close (struct tap_dev *dev);

struct tap_dev *
tap_dev_open (char *name) {
    struct tap_dev *dev;
    struct ifreq ifr;

    dev = malloc(sizeof(struct tap_dev));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    dev->fd = open(CLONE_DEVICE, O_RDWR);
    if (dev->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(dev->fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl [TUNSETIFF]");
        goto ERROR;
    }
    return dev;

ERROR:
    if (dev) {
        tap_dev_close(dev);
    }
    return NULL;
}

void
tap_dev_close (struct tap_dev *dev) {
    if (dev->fd != -1) {
        close(dev->fd);
    }
    free(dev);
}

void
tap_dev_rx (struct tap_dev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct pollfd pfd;
    int ret;
    ssize_t len;
    uint8_t buf[2048];

    pfd.fd = dev->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    switch (ret) {
    case -1:
        if (errno != EINTR) {
            perror("poll");
        }
    case 0:
        return;
    }
    len = read(dev->fd, buf, sizeof(buf));
    switch (len) {
    case -1:
        perror("read");
    case 0:
        return;
    }
    callback(buf, len, arg);
}

ssize_t
tap_dev_tx (struct tap_dev *dev, const uint8_t *buf, size_t len) {
    return write(dev->fd, buf, len);
}

int
tap_dev_addr (char *name, uint8_t *dst, size_t size) {
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl [SIOCGIFHWADDR]");
        close(soc);
        return -1;
    }
    memcpy(dst, ifr.ifr_hwaddr.sa_data, size);
    close(soc);
    return 0;
}

#include "raw.h"

static int
tap_dev_open_wrap (struct rawdev *dev) {
    dev->priv = tap_dev_open(dev->name);
    return dev->priv ? 0 : -1;
}

static void
tap_dev_close_wrap (struct rawdev *dev) {
    tap_dev_close(dev->priv);
}

static void
tap_dev_rx_wrap (struct rawdev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    tap_dev_rx(dev->priv, callback, arg, timeout);
}

static ssize_t
tap_dev_tx_wrap (struct rawdev *dev, const uint8_t *buf, size_t len) {
    return tap_dev_tx(dev->priv, buf, len);
}

static int
tap_dev_addr_wrap (struct rawdev *dev, uint8_t *dst, size_t size) {
    return tap_dev_addr(dev->name, dst, size);
}

struct rawdev_ops tap_dev_ops = {
    .open = tap_dev_open_wrap,
    .close = tap_dev_close_wrap,
    .rx = tap_dev_rx_wrap,
    .tx = tap_dev_tx_wrap,
    .addr = tap_dev_addr_wrap
};
