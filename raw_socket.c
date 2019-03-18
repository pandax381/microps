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

struct raw_socket_priv {
    int fd;
};

static int
raw_socket_open (struct rawdev *dev) {
    struct raw_socket_priv *priv;
    struct ifreq ifr;
    struct sockaddr_ll sockaddr;

    priv = malloc(sizeof(struct raw_socket_priv));
    if (!priv) {
        fprintf(stderr, "malloc: failure\n");
        goto ERROR;
    }
    priv->fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL));
    if (priv->fd == -1) {
        perror("socket");
        goto ERROR;
    }
    strncpy(ifr.ifr_name, dev->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(priv->fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl [SIOCGIFINDEX]");
        goto ERROR;
    }
    memset(&sockaddr, 0x00, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = hton16(ETH_P_ALL);
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(priv->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
        perror("bind");
        goto ERROR;
    }
    if (ioctl(priv->fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCGIFFLAGS]");
        goto ERROR;
    }
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(priv->fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl [SIOCSIFFLAGS]");
        goto ERROR;
    }
    dev->priv = priv;
    return 0;

ERROR:
    if (priv) {
        if (priv->fd == -1) {
            close(priv->fd);
        }
        free(priv);
    }
    return -1;
}

static void
raw_socket_close (struct rawdev *dev) {
    struct raw_socket_priv *priv;

    priv = (struct raw_socket_priv *)dev->priv;
    if (priv) {
        if (priv->fd != -1) {
            close(priv->fd);
        }
        free(priv);
    }
    dev->priv = NULL;
}

static void
raw_socket_rx (struct rawdev *dev, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    struct raw_socket_priv *priv;
    struct pollfd pfd;
    ssize_t ret, length;
    uint8_t buffer[2048];

    priv = (struct raw_socket_priv *)dev->priv;
    pfd.fd = priv->fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        return;
    }
    length = read(priv->fd, buffer, sizeof(buffer));
    if (length <= 0) {
        return;
    }
    callback(buffer, length, arg);
}

static ssize_t
raw_socket_tx (struct rawdev *dev, const uint8_t *buffer, size_t length) {
    struct raw_socket_priv *priv;

    priv = (struct raw_socket_priv *)dev->priv;
    return write(priv->fd, buffer, length);
}

static int
raw_socket_addr (struct rawdev *dev, uint8_t *dst, size_t size) {
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

static struct rawdev_ops raw_socket_ops = {
    .open = raw_socket_open,
    .close = raw_socket_close,
    .rx = raw_socket_rx,
    .tx = raw_socket_tx,
    .addr = raw_socket_addr,
};

int
raw_socket_init (void) {
    return rawdev_register(RAWDEV_TYPE_SOCKET, &raw_socket_ops);
}

