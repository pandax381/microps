#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "microps.h"
#include "util.h"
#include "raw.h"
#include "net.h"
#include "ethernet.h"
#include "dhcp.h"
#include "tcp.h"

#define ECHO_SERVER_PORT (7)

struct netdev *dev;

static void
usage (const char *name) {
    fprintf(stderr, "usage: %s interface [hwaddr] static|dhcp [params...]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "       %s interface [hwaddr] static ipaddr netmask [gateway]\n", name);
    fprintf(stderr, "       %s interface [hwaddr] dhcp\n", name);
}

static int
init (int argc, char *argv[]) {
    char *ifname, *hwaddr = NULL, *ipaddr = "0.0.0.0", *netmask = "0.0.0.0", *gateway = NULL;
    int dhcp = 0;
    struct netif *netif;

    switch (argc) {
    case 3:
        if (strcmp(argv[2], "dhcp") != 0) {
            usage(argv[0]);
            return -1;
        }
        dhcp = 1;
        break;
    case 4:
        if (strcmp(argv[3], "dhcp") != 0) {
            usage(argv[0]);
            return -1;
        }
        dhcp = 1;
        hwaddr = argv[2];
        break;
    case 5:
        if (strcmp(argv[2], "static") != 0) {
            usage(argv[0]);
            return -1;
        }
        ipaddr = argv[3];
        netmask = argv[4];
        break;
    case 6:
        if (strcmp(argv[2], "static") != 0) {
            if (strcmp(argv[3], "static") != 0) {
                usage(argv[0]);
                return -1;
            }
            hwaddr = argv[2];
            ipaddr = argv[4];
            netmask = argv[5];
            break;
        }
        ipaddr = argv[3];
        netmask = argv[4];
        gateway = argv[5];
        break;
    case 7:
        if (strcmp(argv[3], "static") != 0) {
            usage(argv[0]);
            return -1;
        }
        hwaddr = argv[2];
        ipaddr = argv[4];
        netmask = argv[5];
        gateway = argv[6];
        break;
    default:
        usage(argv[0]);
        return -1;
    }
    ifname = argv[1];
    if (microps_init() == -1) {
        fprintf(stderr, "microps_init(): error\n");
        return -1;
    }
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        fprintf(stderr, "netdev_alloc(): error\n");
        return -1;
    }
    strncpy(dev->name, ifname, sizeof(dev->name) -1);
    if (hwaddr) {
        ethernet_addr_pton(hwaddr, (ethernet_addr_t *)dev->addr);
    }
    if (dev->ops->open(dev, RAWDEV_TYPE_AUTO) == -1) {
        fprintf(stderr, "dev->ops->open(): error\n");
        return -1;
    }
    netif = ip_netif_register(dev, ipaddr, netmask, gateway);
    if (!netif) {
        fprintf(stderr, "ip_register_interface(): error\n");
        return -1;
    }
    dev->ops->run(dev);
    if (dhcp) {
        if (dhcp_init(netif) == -1) {
            fprintf(stderr, "dhcp_init(): failure\n");
            return -1;
        }
    }
    return 0;
}

static void
cleanup (void) {
    microps_cleanup();
}

int
main (int argc, char *argv[]) {
    int soc = -1, acc;
    uint8_t buf[65536];
    ssize_t len;

    if (init(argc, argv) == -1) {
        goto ERROR;
    }
    soc = tcp_api_open();
    if (soc == -1) {
        goto ERROR;
    }
    if (tcp_api_bind(soc, hton16(ECHO_SERVER_PORT)) == -1) {
        goto ERROR;
    }
    tcp_api_listen(soc);
    fprintf(stderr, "waiting for connection...\n");
    acc = tcp_api_accept(soc);
    if (acc == -1) {
        goto ERROR;
    }
    fprintf(stderr, "accept success, soc=%d, acc=%d\n", soc, acc);
    while (1) {
        len = tcp_api_recv(acc, buf, sizeof(buf));
        if (len <= 0) {
            break;
        }
        hexdump(stderr, buf, len);
        tcp_api_send(acc, buf, len);
    }
    tcp_api_close(acc);
    cleanup();
    return  0;

ERROR:
    if (soc != -1) {
        tcp_api_close(soc);
    }
    cleanup();
    return -1;
}
