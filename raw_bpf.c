#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include "raw.h"

#define BPF_DEVICE_NUM 4

struct raw_device {
    char name[IFNAMSIZ];
    int fd;
    int buffer_size;
    char *buffer;
};

struct raw_device *
raw_open (const char *name) {
    struct raw_device *dev;
    int index, disable = 0, enable = 1;
    char path[16];
    struct ifreq ifr;

    dev = malloc(sizeof(struct raw_device));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    strncpy(dev->name, name, sizeof(dev->name)-1);
    dev->fd = -1;
    dev->buffer_size = 0;
    dev->buffer = NULL;
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", index);
        dev->fd = open(path, O_RDWR, 0);
        if (dev->fd != -1) {
            break;
        }
    }
    if (dev->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);
    if (ioctl(dev->fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCGBLEN, &dev->buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    dev->buffer = malloc(dev->buffer_size);
    if (!dev->buffer) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl [BIOCPROMISC]");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCSSEESENT, &disable) == -1) {
        perror("ioctl [BIOCSSEESENT]");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl [BIOCIMMEDIATE]");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCSHDRCMPLT, &enable) == -1) {
        perror("ioctl [BIOCSHDRCMPLT]");
        goto ERROR;
    }
#ifdef BIOCFEEDBACK
    if (ioctl(dev->fd, BIOCFEEDBACK, &enable) == -1) {
        perror("ioctl [BIOCFEEDBACK]");
        goto ERROR;
    }
#endif
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
        free(dev->buffer);
    }
    free(dev);
}

void
raw_rx (struct raw_device *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct pollfd pfd;
    int ret;
    ssize_t length;
    struct bpf_hdr *hdr;

    pfd.fd = dev->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        if (ret == -1 && errno != EINTR) {
            perror("poll");
        }
        return;
    }
    length = read(dev->fd, dev->buffer, dev->buffer_size);
    if (length <= 0) {
        if (length == -1 && errno != EINTR) {
            perror("read");
        }
        return;
    }
    hdr = (struct bpf_hdr *)dev->buffer;
    while ((caddr_t)hdr < (caddr_t)dev->buffer + length) {
        callback((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen, arg);
        hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
    }
}

ssize_t
raw_tx (struct raw_device *dev, const uint8_t *buffer, size_t length) {
    return write(dev->fd, buffer, length);
}

int
raw_addr (struct raw_device *dev, uint8_t *dst, size_t size) {
    struct ifaddrs *ifas, *ifa;
    struct sockaddr_dl *dl;

    if (getifaddrs(&ifas) == -1) {
        perror("getifaddrs");
        return -1;
    }
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        dl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (dl->sdl_family == AF_LINK) {
            if (strncmp(dev->name, dl->sdl_data, dl->sdl_nlen) == 0) {
                memcpy(dst, LLADDR(dl), size);
                return 0;
            }
        }
    }
    return -1;
}
