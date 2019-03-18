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
    struct rawdev *raw;

    signal(SIGINT, on_signal);
    if (argc != 2) {
        fprintf(stderr, "usage: %s interface\n", argv[0]);
        return -1;
    }
    if (rawdev_init() == -1) {
        fprintf(stderr, "rawdev_init(): error\n");
        return -1;
    }
    raw = rawdev_alloc(RAWDEV_TYPE_AUTO, argv[1]);
    if (!raw) {
        fprintf(stderr, "rawdev_alloc(): error\n");
        return -1;
    }
    if (raw->ops->open(raw) == -1) {
        fprintf(stderr, "raw_device_open(): failure - (%s)\n", raw->name);
        return -1;
    }
    while (!terminate) {
        raw->ops->rx(raw, dump, raw->name, 1000);
    }
    raw->ops->close(raw);
    return 0;
}
