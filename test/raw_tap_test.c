#include <stdio.h>
#include <signal.h>
#include "raw/tap.h"

volatile sig_atomic_t terminate;

static void
on_signal (int s) {
    terminate = 1;
}

static void
rx_handler (uint8_t *frame, size_t len, void *arg) {
    fprintf(stderr, "receive %zu octets\n", len);
}

int
main (int argc, char *argv[]) {
    char *name;
    struct tap_dev *dev;
    uint8_t addr[6];

    signal(SIGINT, on_signal);
    if (argc != 2) {
        fprintf(stderr, "usage: %s device\n", argv[0]);
        return -1;
    }
    name = argv[1];
    dev = tap_dev_open(argv[1]);
    if (!dev) {
        return -1;
    }
    tap_dev_addr(name, addr, sizeof(addr));
    fprintf(stderr, "[%s] %02x:%02x:%02x:%02x:%02x:%02x\n",
        name, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    while (!terminate) {
        tap_dev_rx(dev, rx_handler, dev, 1000);
    }
    tap_dev_close(dev);
    return 0;
}
