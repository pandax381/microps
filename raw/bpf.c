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
#include "bpf.h"

#define BPF_DEVICE_NUM 4

struct bpf_dev {
    int fd;
    int size;
    char *buf;
};

int
bpf_dev_open (char *name) {
    struct bpf_dev *dev;
    int index, disable = 0, enable = 1;
    char path[16];
    struct ifreq ifr;

    dev = malloc(sizeof(struct bpf_dev));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    dev->fd = -1;
    dev->size = 0;
    dev->buf = NULL;
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
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(dev->fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        goto ERROR;
    }
    if (ioctl(dev->fd, BIOCGBLEN, &dev->size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    dev->buf = malloc(dev->size);
    if (!dev->buf) {
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
        bpf_dev_close(dev);
    }
    return NULL;
}

void
bpf_dev_close (struct bpf_dev *dev) {
    if (dev->fd != -1) {
        close(dev->fd);
        free(dev->buf);
    }
    free(dev);
}

void
bpf_dev_rx (struct bpf_dev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct pollfd pfd;
    int ret;
    ssize_t len;
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
    len = read(dev->fd, dev->buf, dev->size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            perror("read");
        }
        return;
    }
    hdr = (struct bpf_hdr *)dev->buf;
    while ((caddr_t)hdr < (caddr_t)dev->buf + len) {
        callback((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen, arg);
        hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
    }
}

ssize_t
bpf_dev_tx (struct bpf_dev *dev, const uint8_t *buf, size_t len) {
    return write(dev->fd, buf, len);
}

int
bpf_dev_addr (char *name, uint8_t *dst, size_t size) {
    struct ifaddrs *ifas, *ifa;
    struct sockaddr_dl *dl;

    if (getifaddrs(&ifas) == -1) {
        perror("getifaddrs");
        return -1;
    }
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        dl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (dl->sdl_family == AF_LINK) {
            if (strncmp(name, dl->sdl_data, dl->sdl_nlen) == 0) {
                memcpy(dst, LLADDR(dl), size);
                return 0;
            }
        }
    }
    return -1;
}
