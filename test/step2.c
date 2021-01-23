#include <stdio.h>
#include <signal.h>

#include "util.h"
#include "net.h"

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

int
main(void)
{
    struct net_device *dev1, *dev2;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev1 = null_init();
    if (!dev1) {
        errorf("null_init() failure");
        return -1;
    }
    dev2 = loopback_init();
    if (!dev2) {
        errorf("loopback_init() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    while (!terminate) {
        if (net_device_output(dev2, 0x0800, test_data, sizeof(test_data), NULL) == -1) {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    net_shutdown();
    return 0;
}
