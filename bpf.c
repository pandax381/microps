#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include "device.h"
#include "util.h"

#define BPF_DEVICE_NUM 4

struct device_fd {
    int fd;
    int buffer_size;
    char *buffer;
};

device_fd_t *
device_open (const char *name) {
    device_fd_t *devfd;
	int index, enable = 1;
	char dev[16];
	struct ifreq ifr;

    if ((devfd = malloc(sizeof(*devfd))) == NULL) {
        perror("malloc");
        goto ERROR;
    }
    devfd->fd = -1;
    devfd->buffer = NULL;
	for (index = 0; index < BPF_DEVICE_NUM; index++) {
		snprintf(dev, sizeof(dev), "/dev/bpf%d", index);
		if ((devfd->fd = open(dev, O_RDWR, 0)) != -1) {
			break;
		}
	}
	if (devfd->fd == -1) {
		perror("open");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(devfd->fd, BIOCSETIF, &ifr) == -1) {
		perror("ioctl [BIOCSETIF]");
		goto ERROR;
	}
    if (ioctl(devfd->fd, BIOCGBLEN, &devfd->buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        goto ERROR;
    }
    if ((devfd->buffer = malloc(devfd->buffer_size)) == NULL) {
        perror("malloc");
        goto ERROR;
    }
	if (ioctl(devfd->fd, BIOCPROMISC, NULL) == -1) {
		perror("ioctl [BIOCPROMISC]");
		goto ERROR;
	}
	if (ioctl(devfd->fd, BIOCSSEESENT, &enable) == -1) {
		perror("ioctl [BIOCSSEESENT]");
		goto ERROR;
	}
	if (ioctl(devfd->fd, BIOCIMMEDIATE, &enable) == -1) {
		perror("ioctl [BIOCIMMEDIATE]");
		goto ERROR;
	}
	if (ioctl(devfd->fd, BIOCSHDRCMPLT, &enable) == -1) {
		perror("ioctl [BIOCSHDRCMPLT]");
		goto ERROR;
	}
	return devfd;
ERROR:
    if (devfd) {
        device_close(devfd);
    }
	return NULL;
}

void
device_close (device_fd_t *devfd) {
    if (devfd->fd != -1) {
        close(devfd->fd);
    }
    free(devfd->buffer);
}

void
device_input (device_fd_t *devfd, void (*callback)(uint8_t *, size_t), int timeout) {
    struct pollfd pollfd;
    ssize_t ret, length;
    struct bpf_hdr *hdr;

    pollfd.fd = devfd->fd;
    pollfd.events = POLLIN;
    ret = poll(&pollfd, 1, timeout);
    if (ret <= 0) {
        return;
    }
    length = read(devfd->fd, devfd->buffer, devfd->buffer_size);
    if (length <= 0) {
        return;
    }
    hdr = (struct bpf_hdr *)devfd->buffer;
    while ((caddr_t)hdr < (caddr_t)devfd->buffer + length) {
        callback((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen);
        hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
    }
}

ssize_t
device_output (device_fd_t *devfd, const uint8_t *buffer, size_t len) {
	return write(devfd->fd, buffer, len);
}
