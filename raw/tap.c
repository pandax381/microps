#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/sockios.h>
#include <linux/if_tun.h>
#elif __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#else
#error "This platform does not supported."
#endif
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include "util.h"
#include "tap.h"

#ifdef __linux__
#define CLONE_DEVICE "/dev/net/tun"
#else
#define TAP_DEVICE_NUM 10
#endif

struct tap_dev {
    int fd;
};

void
tap_dev_close (struct tap_dev *dev);

struct tap_dev *
tap_dev_open (char *name) {
    struct tap_dev *dev;
#ifdef __linux__
    struct ifreq ifr;
#else
    int index;
    char path[16];
#endif

    dev = malloc(sizeof(struct tap_dev));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
#ifdef __linux__
    dev->fd = open(CLONE_DEVICE, O_RDWR);
#else
    for (index = 0; index < TAP_DEVICE_NUM; index++) {
        snprintf(path, sizeof(path), "/dev/tap%d", index);
        dev->fd = open(path, O_RDWR);
        if (dev->fd != -1) {
            break;
        }
    }
#endif
    if (dev->fd == -1) {
        perror("open");
        goto ERROR;
    }
#ifdef __linux
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(dev->fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl [TUNSETIFF]");
        goto ERROR;
    }
#endif
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
    if (ret <= 0) {
        return;
    }
    len = read(dev->fd, buf, sizeof(buf));
    if (len <= 0) {
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
#ifdef __linux__
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
#else
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
#endif
}
