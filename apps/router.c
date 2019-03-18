#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include "microps.h"
#include "raw.h"
#include "ethernet.h"
#include "ip.h"
#include "util.h"

struct interface {
    char *ifname;
    char *hwaddr;
    char *ipaddr;
    char *netmask;
    char *gateway;
};

static struct interface ifces[] = {
    {
        .ifname = "tap0",
        .hwaddr = "00:00:5E:00:53:00",
        .ipaddr = "172.16.0.1",
        .netmask = "255.255.255.0",
        .gateway = NULL
    },
    {
        .ifname = "tap10",
        .hwaddr = "00:00:5E:00:53:10",
        .ipaddr = "172.16.1.1",
        .netmask = "255.255.255.0",
        .gateway = NULL
    }
};

static int
ifsetup (struct interface *ifc) {
    struct netdev *dev;
    struct netif *netif;

    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        fprintf(stderr, "netdev_alloc(): error\n");
        return -1;
    }
    strncpy(dev->name, ifc->ifname, sizeof(dev->name) -1);
    if (ifc->hwaddr) {
        ethernet_addr_pton(ifc->hwaddr, (ethernet_addr_t *)dev->addr);
    }
    if (dev->ops->open(dev, RAWDEV_TYPE_AUTO) == -1) {
        fprintf(stderr, "dev->ops->open(): error\n");
        return -1;
    }
    netif = ip_netif_register(dev, ifc->ipaddr, ifc->netmask, ifc->gateway);
    if (!netif) {
        fprintf(stderr, "ip_register_interface(): error\n");
        return -1;
    }
    dev->ops->run(dev);
    return 0;
}

static void
cleanup (void) {
    microps_cleanup();
}

int
main (void) {
    sigset_t sigset;
    int signo;
    struct interface *ifc;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    if (microps_init() == -1) {
        fprintf(stderr, "microps_init(): error\n");
        goto ERROR;
    }
    if (!ip_set_forwarding(1)) {
        fprintf(stderr, "ip_set_forwarding(): error\n");
        goto ERROR;
    }
    for (ifc = ifces; ifc < array_tailof(ifces); ifc++) {
        if (ifsetup(ifc) == -1) {
            fprintf(stderr, "ifsetup(): error\n");
            goto ERROR;
        }
    }
    fprintf(stderr, "running...\n");
    while (1) {
        sigwait(&sigset, &signo);
        if (signo == SIGINT) {
            break;
        }
    }
    fprintf(stderr, "shutdown.\n");
    return 0;

ERROR:
    cleanup();
    return -1;
}
