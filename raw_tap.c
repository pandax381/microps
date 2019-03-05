#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include "util.h"
#include "raw.h"

#define CLONE_DEVICE "/dev/net/tun"

struct raw_device {
    char name[IFNAMSIZ];
    int fd;
};

struct raw_device *
raw_open (const char *name) {
    struct raw_device *dev;
    struct ifreq ifr;

    dev = malloc(sizeof(struct raw_device));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    dev->fd = open(CLONE_DEVICE, O_RDWR);
    if (dev->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(dev->name, name, sizeof(dev->name) - 1);
    strncpy(ifr.ifr_name, dev->name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(dev->fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl [TUNSETIFF]");
        goto ERROR;
    }
    return dev;

ERROR:
    if (dev) {
        raw_close(dev);
    }
    return NULL;
}

void
raw_close (struct raw_device *dev) {
    if (dev->fd != -1) {
        close(dev->fd);
    }
    free(dev);
}

void
raw_rx (struct raw_device *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct pollfd pfd;
    ssize_t ret, length;
    uint8_t buffer[2048];

    pfd.fd = dev->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        return;
    }
    length = read(dev->fd, buffer, sizeof(buffer));
    if (length <= 0) {
        return;
    }
    callback(buffer, length, arg);
}

ssize_t
raw_tx (struct raw_device *dev, const uint8_t *buffer, size_t length) {
    return write(dev->fd, buffer, length);
}

int
raw_addr (struct raw_device *dev, uint8_t *dst, size_t size) {
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl [SIOCGIFHWADDR]");
        close(soc);
        return -1;
    }
    memcpy(dst, ifr.ifr_hwaddr.sa_data, size);
    close(soc);
    return 0;
}
