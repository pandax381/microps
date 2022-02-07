#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/null.h"
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

int
main(int argc, char *argv[])
{
    int opt, noop = 0;
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t src = IP_ADDR_ANY, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    /*
     * Parse command line parameters
     */
    while ((opt = getopt(argc, argv, "n")) != -1) {
        switch (opt) {
        case 'n':
            noop = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
            return -1;
        }
    }
    switch (argc - optind) {
    case 2:
        if (ip_addr_pton(argv[optind], &src) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        /* fall through */
    case 1:
        if (ip_addr_pton(argv[optind], &dst) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        break;
    case 0:
        if (noop) {
            break;
        }
        /* fall through */
    default:
        fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = null_init();
    if (!dev) {
        errorf("null_init() failure");
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
    /*
     * Test Code
     */
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        if (!noop) {
            if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
                errorf("icmp_output() failure");
                break;
            }
        }
        sleep(1);
    }
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
