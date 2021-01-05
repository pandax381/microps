#include <stdio.h>
#include <signal.h>
#include <unistd.h>

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

    /*
     * Parse command line parameters
     */
    while ((opt = getopt(argc, argv, "n")) != -1) {
        switch (opt) {
        case 'n':
            noop = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-n]\n", argv[0]);
            return -1;
        }
    }
    switch (argc - optind) {
    case 0:
        break;
    default:
        fprintf(stderr, "Usage: %s [-n]\n", argv[0]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    signal(SIGINT, on_signal);
    /*
     * Test Code
     */
    while (!terminate) {
        if (!noop) {
            /* ... */
        }
        sleep(1);
    }
    /*
     * Cleanup protocol stack
     */
    return 0;
}
