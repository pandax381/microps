#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/null.h"
#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static void
icmp_dummy_handler(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    debugf("iface=%s, src=%s, dst=%s, len=%zu",
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(src, addr2, sizeof(addr2)),
        ip_addr_ntop(dst, addr3, sizeof(addr3)),
        len);
    debugdump(data, len);
}

int
main(int argc, char *argv[])
{
    int opt, noop = 0;
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t src = IP_ADDR_ANY, dst;
    size_t offset = IP_HDR_SIZE_MIN;

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
    if (ip_protocol_register("ICMP", IP_PROTOCOL_ICMP, icmp_dummy_handler) == -1) {
        errorf("ip_protocol_register() failure");
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
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    /*
     * Test Code
     */
    while (!terminate) {
        if (!noop) {
            if (ip_output(IP_PROTOCOL_ICMP, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
                errorf("ip_output() failure");
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
