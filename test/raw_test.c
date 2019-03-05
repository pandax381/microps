#include <stdio.h>
#include <signal.h>
#include "util.h"
#include "raw.h"

volatile sig_atomic_t terminate;

static void
on_signal (int s) {
    (void)s;
    terminate = 1;
}

static void
dump (uint8_t *frame, size_t len, void *arg) {
    char *name;

    name = (char *)arg;
    fprintf(stderr, "%s: receive %zu octets\n", name, len);
    hexdump(stderr, frame, len);
}

int
main (int argc, char *argv[]) {
    char *ifname;
    struct raw_device *dev;

    if (argc != 2) {
        fprintf(stderr, "usage: %s interface\n", argv[0]);
        return -1;
    }
    ifname = argv[1];
    signal(SIGINT, on_signal);
    dev = raw_open(ifname);
    if (!dev) {
        fprintf(stderr, "raw_open(): failure - (%s)\n", ifname);
        return -1;
    }
    while (!terminate) {
        raw_rx(dev, dump, ifname, 1000);
    }
    raw_close(dev);
    return 0;
}
