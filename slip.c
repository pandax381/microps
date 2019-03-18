#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include "util.h"
#include "net.h"
#include "ethernet.h"
#include "slip.h"

#define END     0x0c
#define ESC     0xdb
#define ESC_END 0xdc
#define ESC_ESC 0xdd

#define SLIP_TYPE_IP 0x0800

#define SLIP_MUT_DEFAULT 1006

struct slip_priv {
    struct netdev *dev;
    int fd;
    int terminate;
    pthread_t thread;
    pthread_mutex_t mutex;
};

void
slip_dump (struct netdev *dev, uint8_t *packet, size_t plen) {
    fprintf(stderr, " device: %s\n", dev->name);
    fprintf(stderr, " length: %zu octets\n", plen);
    hexdump(stderr, packet, plen);
}

static int
slip_open (struct netdev *dev, int opt) {
    struct slip_priv *priv;
    struct stat st;
    struct sockaddr_un addr;

    (void)opt;
    priv = malloc(sizeof(struct slip_priv));
    if (!priv) {
        fprintf(stderr, "malloc(): error\n");
        return -1;
    }
    priv->dev = dev;
    if (stat(priv->dev->name, &st) == -1) {
        perror("stat");
        free(priv);
        return -1;
    }
    switch (st.st_mode & S_IFMT) {
    case S_IFCHR:
        priv->fd = open(priv->dev->name, O_RDWR | O_NOCTTY | O_NDELAY);
        if (priv->fd == -1) {
            perror("open");
            free(priv);
            return -1;
        }
        break;
    case S_IFSOCK:
        priv->fd = socket(PF_UNIX, SOCK_STREAM, 0);
        if (priv->fd == -1) {
            perror("socket");
            free(priv);
            return -1;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, priv->dev->name);
        if (connect(priv->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            perror("connect");
            close(priv->fd);
            free(priv);
            return -1;
        }
        break;
    default:
        fprintf(stderr, "slip_priv_open(): support Charcter Device or UNIX Domain Socket only\n");
        free(priv);
        return -1;
    }
    priv->terminate = 0;
    pthread_mutex_init(&priv->mutex, NULL);
    dev->priv = priv;
    return 0;
}

static int
slip_close (struct netdev *dev) {
    struct slip_priv *priv;

    priv = (struct slip_priv *)dev->priv;
    close(priv->fd);
    free(priv);
    return 0;
}

static void *
slip_rx_thread (void *arg) {
    struct netdev *dev;
    struct slip_priv *priv;
    struct pollfd pfd;
    int c, overflow = 0;
    uint8_t buf[1024];
    ssize_t len = 0;

    dev = (struct netdev *)arg;
    priv = (struct slip_priv *)dev->priv;
    pfd.fd = priv->fd;
    pfd.events = POLLIN;

    while (!priv->terminate) {
        if (poll(&pfd, 1, 1000) <= 0) {
            continue;
        }
        c = fdgetc(priv->fd);
        switch (c) {
        case END:
            if (len) {
                if (!overflow) {
#ifdef DEBUG
                    fprintf(stderr, ">>> slip_rx_thread <<<\n");
                    slip_dump(dev, buf, len);
#endif
                    dev->rx_handler(dev, SLIP_TYPE_IP, buf, len);
                }
                overflow = 0;
                len = 0;
            }
            break;
        case ESC:
            c = fdgetc(priv->fd);
            switch (c) {
            case ESC_END:
                c = END;
                break;
            case ESC_ESC:
                c = ESC;
                break;
            }
            /* fallthrough */
        default:
            if (!overflow) {
                if (len == sizeof(buf)) {
                    fprintf(stderr, "slip_rx_thread: warnging, rx buffer is overflow !!!\n");
                    overflow = 1;
                    break;
                }
                buf[len++] = c;
            }
            break;
        }
    }
    return NULL;
}

static int
slip_run (struct netdev *dev) {
    struct slip_priv *priv;
    int err;

    priv = (struct slip_priv *)dev->priv;
    err = pthread_create(&priv->thread, NULL, slip_rx_thread, dev);
    if (err) {
        fprintf(stderr, "pthread_create(): error, code=%d\n", err);
        return -1;
    }
    return 0;
}

static int
slip_stop (struct netdev *dev) {
    struct slip_priv *priv;

    priv = dev->priv;
    priv->terminate = 1;
    pthread_join(priv->thread, NULL);
    priv->thread = pthread_self();
    priv->terminate = 0;
    return 0;
}

static ssize_t
slip_tx (struct netdev *dev, uint16_t type, const uint8_t *payload, size_t plen, const void *dst) {
    struct slip_priv *priv;
    uint8_t *p;

    (void)dst;
    if (type != ETHERNET_TYPE_IP) {
        return -1;
    }
    priv = (struct slip_priv *)dev->priv;
    p = (uint8_t *)payload;
    pthread_mutex_lock(&priv->mutex);
    fdputc(priv->fd, END);
    while (plen--) {
        switch (*p) {
        case END:
            fdputc(priv->fd, ESC);
            fdputc(priv->fd, ESC_END);
            break;
        case ESC:
            fdputc(priv->fd, ESC);
            fdputc(priv->fd, ESC_ESC);
            break;
        default:
            fdputc(priv->fd, *p);
            break;
        }
        p++;
    }
    fdputc(priv->fd, END);
    pthread_mutex_unlock(&priv->mutex);
    return plen;
}

static struct netdev_ops slip_ops = {
    .open = slip_open,
    .close = slip_close,
    .run = slip_run,
    .stop = slip_stop,
    .tx = slip_tx,
};

int
slip_init (void) {
    netdev_register_driver(NETDEV_TYPE_SLIP, SLIP_MUT_DEFAULT, NETDEV_FLAG_NOARP, 0, 0, &slip_ops);
    return 0;
}
