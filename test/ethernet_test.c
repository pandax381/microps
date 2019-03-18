#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "raw.h"
#include "net.h"
#include "ethernet.h"

static int
setup (void) {
    if (ethernet_init() == -1) {
        fprintf(stderr, "ethernet_init(): failure\n");
        return -1;
    }
    return 0;
}

int
main (int argc, char *argv[]) {
    sigset_t sigset;
    int signo;
    struct netdev *dev;

    if (argc != 2) {
        fprintf(stderr, "usage: %s interface\n", argv[0]);
        return -1;
    }
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    if (setup() == -1) {
        return -1;
    }
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        return -1;
    }
    strncpy(dev->name, argv[1], sizeof(dev->name) -1);
    if (dev->ops->open(dev, RAWDEV_TYPE_AUTO) == -1) {
        return -1;
    }
    dev->ops->run(dev);
    while (1) {
        sigwait(&sigset, &signo);
        if (signo == SIGINT) {
            break;
        }
    }
    if (dev->ops->close) {
        dev->ops->close(dev);
    }
    return 0;
}
