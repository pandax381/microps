#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
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

static void
cleanup(void)
{
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    int soc;
    struct ip_endpoint local, foreign;
    uint8_t buf[1024];
    ssize_t ret;
    char ep[IP_ENDPOINT_STR_LEN];

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    soc = udp_open();
    if (soc == -1) {
        errorf("udp_open() failure");
        return -1;
    }
    ip_endpoint_pton("0.0.0.0:7", &local);
    if (udp_bind(soc, &local) == -1) {
        errorf("udp_bind() failure");
        udp_close(soc);
        return -1;
    }
    debugf("waiting for data...");
    while (!terminate) {
        ret = udp_recvfrom(soc, buf, sizeof(buf), &foreign);
        if (ret == -1) {
            errorf("udp_recvfrom() failure");
            break;
        }
        debugf("%zd bytes data form %s", ret, ip_endpoint_ntop(&foreign, ep, sizeof(ep)));
        hexdump(stderr, buf, ret);
        if (udp_sendto(soc, buf, ret, &foreign) == -1) {
            errorf("udp_sendto() failure");
            break;
        }
    }
    udp_close(soc);
    cleanup();
    return 0;
}
