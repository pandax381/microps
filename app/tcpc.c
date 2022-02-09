#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt();
    close(0);
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int opt, soc;
    long int port;
    struct sockaddr_in local = { .sin_family=AF_INET }, foreign;
    uint8_t buf[1024];

    /*
     * Parse command line parameters
     */
    while ((opt = getopt(argc, argv, "s:p:")) != -1) {
        switch (opt) {
        case 's':
            if (ip_addr_pton(optarg, &local.sin_addr) == -1) {
                errorf("ip_addr_pton() failure, addr=%s", optarg);
                return -1;
            }
            break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            if (port < 0 || port > UINT16_MAX) {
                errorf("invalid port, port=%s", optarg);
                return -1;
            }
            local.sin_port = hton16(port);
            break;
        default:
            fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
            return -1;
        }
    }
    if (argc - optind != 1) {
        fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
        return -1;
    }
    if (sockaddr_pton(argv[optind], (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        errorf("sockaddr_pton() failure, %s", argv[optind]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    /*
     *  Application Code
     */
    soc = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    if (local.sin_port) {
        if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
            errorf("sock_bind() failure");
            return -1;
        }
    }
    if (sock_connect(soc, (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        errorf("sock_connect() failure");
        return -1;
    }
    infof("connection established");
    while (!terminate) {
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;
        }
        if (sock_send(soc, buf, strlen((char *)buf)) == -1) {
            errorf("sock_send() failure");
            break;
        }
    }
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
