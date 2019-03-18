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

struct raw_bpf_priv {
    int fd;
    int buffer_size;
    char *buffer;
};

static int
raw_bpf_open (struct rawdev *dev) {
    struct raw_bpf_priv *priv;
    int index, disable = 0, enable = 1;
    char path[16];
    struct ifreq ifr;

    priv = malloc(sizeof(struct raw_bpf_priv));
    if (!priv) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    priv->fd = -1;
    priv->buffer_size = 0;
    priv->buffer = NULL;
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", index);
        priv->fd = open(path, O_RDWR, 0);
        if (priv->fd != -1) {
            break;
        }
    }
    if (priv->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);
    if (ioctl(priv->fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        goto ERROR;
    }
    if (ioctl(priv->fd, BIOCGBLEN, &priv->buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    priv->buffer = malloc(priv->buffer_size);
    if (!priv->buffer) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    if (ioctl(priv->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl [BIOCPROMISC]");
        goto ERROR;
    }
    if (ioctl(priv->fd, BIOCSSEESENT, &disable) == -1) {
        perror("ioctl [BIOCSSEESENT]");
        goto ERROR;
    }
    if (ioctl(priv->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl [BIOCIMMEDIATE]");
        goto ERROR;
    }
    if (ioctl(priv->fd, BIOCSHDRCMPLT, &enable) == -1) {
        perror("ioctl [BIOCSHDRCMPLT]");
        goto ERROR;
    }
#ifdef BIOCFEEDBACK
    if (ioctl(priv->fd, BIOCFEEDBACK, &enable) == -1) {
        perror("ioctl [BIOCFEEDBACK]");
        goto ERROR;
    }
#endif
    dev->priv = priv;
    return 0;

ERROR:
    if (priv) {
        if (priv->fd != -1) {
            close(priv->fd);
            free(priv->buffer);
        }
        free(priv);
    }
    return -1;
}

static void
raw_bpf_close (struct rawdev *dev) {
    struct raw_bpf_priv *priv;

    priv = (struct raw_bpf_priv *)dev->priv;
    if (priv) {
        if (priv->fd != -1) {
            close(priv->fd);
            free(priv->buffer);
        }
        free(priv);
    }
    dev->priv = NULL;
}

static void
raw_bpf_rx (struct rawdev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct raw_bpf_priv *priv;
    struct pollfd pfd;
    int ret;
    ssize_t length;
    struct bpf_hdr *hdr;

    priv = (struct raw_bpf_priv *)dev->priv;
    pfd.fd = priv->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        if (ret == -1 && errno != EINTR) {
            perror("poll");
        }
        return;
    }
    length = read(priv->fd, priv->buffer, priv->buffer_size);
    if (length <= 0) {
        if (length == -1 && errno != EINTR) {
            perror("read");
        }
        return;
    }
    hdr = (struct bpf_hdr *)priv->buffer;
    while ((caddr_t)hdr < (caddr_t)priv->buffer + length) {
        callback((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen, arg);
        hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
    }
}

static ssize_t
raw_bpf_tx (struct rawdev *dev, const uint8_t *buffer, size_t length) {
    struct raw_bpf_priv *priv;

    priv = (struct raw_bpf_priv *)dev->priv;
    return write(priv->fd, buffer, length);
}

static int
raw_bpf_addr (struct rawdev *dev, uint8_t *dst, size_t size) {
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

struct rawdev_ops raw_bpf_ops = {
    .open = raw_bpf_open,
    .close = raw_bpf_close,
    .rx = raw_bpf_rx,
    .tx = raw_bpf_tx,
    .addr = raw_bpf_addr
};

int
raw_bpf_init (void) {
    return rawdev_register(RAWDEV_TYPE_BPF, &raw_bpf_ops);
}
