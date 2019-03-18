#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "raw.h"
#include "net.h"
#include "ethernet.h"
#include "arp.h"

static int
setup (void) {
    ethernet_init();
    arp_init();
    return 0;
}

int
main (int argc, char *argv[]) {
    char *ifname, *hwaddr = NULL, *ipaddr;
    sigset_t sigset;
    int signo;
    struct netdev *dev;
    struct netif_ip iface = {};

    switch (argc) {
    case 4:
        hwaddr = argv[2];
        /* fall through */
    case 3:
        ipaddr = argv[argc-1];
        ifname = argv[1];
        break;
    default:
        fprintf(stderr, "usage: %s interface [mac_address] ip_address\n", argv[0]);
        return -1;
    }
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    setup();
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        return -1;
    }
    strncpy(dev->name, ifname, sizeof(dev->name) -1);
    if (hwaddr) {
        ethernet_addr_pton(hwaddr, (ethernet_addr_t *)dev->addr);
    }
    if (dev->ops->open(dev, RAWDEV_TYPE_AUTO) == -1) {
        return -1;
    }
    iface.netif.family = NETIF_FAMILY_IPV4;
    ip_addr_pton(ipaddr, &iface.unicast);
    netdev_add_netif(dev, (struct netif *)&iface);
    dev->ops->run(dev);
    while (1) {
        sigwait(&sigset, &signo);
        if (signo == SIGINT) {
            break;
        }
    }
    dev->ops->close(dev);
    return 0;
}
