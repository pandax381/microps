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
#include "device.h"
#include "util.h"

struct device {
    int fd;
};

device_t *
device_open (const char *name) {
    device_t *device;
    struct ifreq ifr;
    struct sockaddr_ll sockaddr;

    if ((device = malloc(sizeof(*device))) == NULL) {
        perror("malloc");
        goto ERROR;
    }
    if ((device->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL))) == -1) {
        perror("socket");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(device->fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl [SIOCGIFINDEX]");
        goto ERROR;
    }
    memset(&sockaddr, 0x00, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = hton16(ETH_P_ALL);
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(device->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
        perror("bind");
        goto ERROR;
    }
    if (ioctl(device->fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCGIFFLAGS]");
        goto ERROR;
    }
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(device->fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCSIFFLAGS]");
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
    }
    free(device);
}

void
device_input (device_t *device, void (*callback)(uint8_t *, size_t, void *), void *args, int timeout) {
    struct pollfd pfd;
    ssize_t ret, length;
    uint8_t buffer[2048];

    pfd.fd = device->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        return;
    }
    length = read(device->fd, buffer, sizeof(buffer));
    if (length <= 0) {
        return;
    }
    callback(buffer, length, device);
}

ssize_t
device_output (device_t *device, const uint8_t *buffer, size_t length) {
    return write(device->fd, buffer, length);
}
