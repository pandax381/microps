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

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt = 1;
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
    int soc, acc;
    long int port;
    struct ip_endpoint local = {}, foreign;
    char ep[IP_ENDPOINT_STR_LEN];
    uint8_t buf[1024];
    ssize_t ret;

    /*
     * Parse command line parameters
     */
    switch (argc) {
    case 3:
        if (ip_addr_pton(argv[argc-2], &local.addr) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", optarg);
            return -1;
        }
        /* fall through */
    case 2:
        port = strtol(argv[argc-1], NULL, 10);
        if (port < 0 || port > UINT16_MAX) {
            errorf("invalid port, port=%s", optarg);
            return -1;
        }
        local.port = hton16(port);
        break;
    default:
        fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
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
    soc = tcp_open();
    if (soc == -1) {
        errorf("tcp_open() failure");
        return -1;
    }
    if (tcp_bind(soc, &local) == -1) {
        errorf("tcp_bind() failure");
        return -1;
    }
    if (tcp_listen(soc, 1) == -1) {
        errorf("tcp_listen() failure");
        return -1;
    }
    acc = tcp_accept(soc, &foreign);
    if (acc == -1) {
        errorf("tcp_accept() failure");
        return -1;
    }
    infof("connection accepted, foreign=%s", ip_endpoint_ntop(&foreign, ep, sizeof(ep)));
    while (!terminate) {
        ret = tcp_receive(acc, buf, sizeof(buf));
        if (ret == -1) {
            errorf("tcp_receive() failure");
            break;
        }
        if (ret == 0) {
            debugf("connection closed");
            break;
        }
        infof("%zu bytes received", ret);
        hexdump(stderr, buf, ret);
        if (tcp_send(acc, buf, ret) == -1) {
            errorf("tcp_send() failure");
            break;
        }
    }
    tcp_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
