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
#include <net/bpf.h>
#include <net/if.h>
#include "device.h"
#include "util.h"

#define BPF_DEVICE_NUM 4

struct device {
    int fd;
    int buffer_size;
    char *buffer;
};

device_t *
device_open (const char *name) {
    device_t *device;
    int index, enable = 1;
    char dev[16];
    struct ifreq ifr;

    if ((device = malloc(sizeof(device_t))) == NULL) {
        perror("malloc");
        goto ERROR;
    }
    device->fd = -1;
    device->buffer_size = 0;
    device->buffer = NULL;
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", index);
        if ((device->fd = open(dev, O_RDWR, 0)) != -1) {
            break;
        }
    }
    if (device->fd == -1) {
        perror("open");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(device->fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCGBLEN, &device->buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    if ((device->buffer = malloc(device->buffer_size)) == NULL) {
        perror("malloc");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl [BIOCPROMISC]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCSSEESENT, &enable) == -1) {
        perror("ioctl [BIOCSSEESENT]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl [BIOCIMMEDIATE]");
        goto ERROR;
    }
    if (ioctl(device->fd, BIOCSHDRCMPLT, &enable) == -1) {
        perror("ioctl [BIOCSHDRCMPLT]");
        goto ERROR;
    }
    return device;
ERROR:
    if (device) {
        device_close(device);
    }
    return NULL;
}

void
device_close (device_t *device) {
    if (device->fd != -1) {
        close(device->fd);
        device->fd = -1;
    }
    free(device->buffer);
    free(device);
}

void
device_input (device_t *device, void (*callback)(uint8_t *, size_t), int timeout) {
    struct pollfd pfd;
    ssize_t length;
    struct bpf_hdr *hdr;

    pfd.fd = device->fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout) <= 0) {
        return;
    }
    length = read(device->fd, device->buffer, device->buffer_size);
    if (length <= 0) {
        return;
    }
    hdr = (struct bpf_hdr *)device->buffer;
    while ((caddr_t)hdr < (caddr_t)device->buffer + length) {
        callback((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen);
        hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
    }
}

ssize_t
device_output (device_t *device, const uint8_t *buffer, size_t length) {
    return write(device->fd, buffer, length);
}
