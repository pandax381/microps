#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include "device.h"
#include "util.h"

struct device_fd {
    int fd;
};

device_fd_t *
device_open (const char *name) {
    device_fd_t *devfd;
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;

    if ((devfd = malloc(sizeof(*devfd))) == NULL) {
        perror("malloc");
        goto ERROR;
    }
	if ((devfd->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL))) == -1) {
		perror("socket");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(devfd->fd, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl [SIOCGIFINDEX]");
		goto ERROR;
	}
	memset(&sockaddr, 0x00, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = hton16(ETH_P_ALL);
	sockaddr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(devfd->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		perror("bind");
		goto ERROR;
	}
	if (ioctl(devfd->fd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCGIFFLAGS]");
		goto ERROR;
	}
	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl(devfd->fd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCSIFFLAGS]");
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
}

void
device_input (device_fd_t *devfd, void (*callback)(uint8_t *, size_t), int timeout) {
    struct pollfd pollfd;
    ssize_t ret, length;
    uint8_t buffer[2048];

    pollfd.fd = devfd->fd;
    pollfd.events = POLLIN;
    ret = poll(&pollfd, 1, timeout);
    if (ret <= 0) {
        return;
    }
    length = read(devfd->fd, buffer, sizeof(buffer));
    if (length <= 0) {
        return;
    }
    callback(buffer, length);
}

ssize_t
device_output (device_fd_t *devfd, const uint8_t *buffer, size_t len) {
    return write(devfd->fd, buffer, len);
}
