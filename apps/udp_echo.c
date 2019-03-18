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
#include "udp.h"
#include "dhcp.h"

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
    int soc = -1;
    uint8_t buf[65536];
    ssize_t len;
    ip_addr_t peer_addr;
    uint16_t peer_port;
    char addr[IP_ADDR_STR_LEN+1];

    if (init(argc, argv) == -1) {
        goto ERROR;
    }
    soc = udp_api_open();
    if (soc == -1) {
        goto ERROR;
    }
    if (udp_api_bind(soc, NULL, hton16(ECHO_SERVER_PORT)) == -1) {
        goto ERROR;
    }
    fprintf(stderr, "waiting for messsage...\n");
    while (1) {
        len = udp_api_recvfrom(soc, buf, sizeof(buf), &peer_addr, &peer_port, -1);
        if (len <= 0) {
            break;
        }
        fprintf(stderr, "message form: %s:%u\n", ip_addr_ntop(&peer_addr, addr, sizeof(addr)), ntoh16(peer_port));
        hexdump(stderr, buf, len);
        udp_api_sendto(soc, buf, len, &peer_addr, peer_port);
    }
    udp_api_close(soc);
    cleanup();
    return  0;

ERROR:
    if (soc != -1) {
        udp_api_close(soc);
    }
    cleanup();
    return -1;
}
