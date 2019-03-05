#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include "util.h"
#include "raw.h"

struct raw_device {
    char name[IFNAMSIZ];
    int fd;
};

struct raw_device *
raw_open (const char *name) {
    struct raw_device *dev;
    struct ifreq ifr;
    struct sockaddr_ll sockaddr;

    dev = malloc(sizeof(struct raw_device));
    if (!dev) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    dev->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL));
    if (dev->fd == -1) {
        perror("socket");
        goto ERROR;
    }
    strncpy(dev->name, name, sizeof(dev->name) - 1);
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(dev->fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl [SIOCGIFINDEX]");
        goto ERROR;
    }
    memset(&sockaddr, 0x00, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = hton16(ETH_P_ALL);
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(dev->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
        perror("bind");
        goto ERROR;
    }
    if (ioctl(dev->fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCGIFFLAGS]");
        goto ERROR;
    }
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(dev->fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCSIFFLAGS]");
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
        perror("ioctl");
        close(soc);
        return -1;
    }
    memcpy(dst, ifr.ifr_hwaddr.sa_data, size);
    close(soc);
    return 0;
}
