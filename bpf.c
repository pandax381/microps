#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include "device.h"
#include "util.h"

#define BPF_DEVICE_NUM 4

static struct {
	int bpf;
	char *buffer;
	int buffer_size;
	int terminate;
	pthread_t thread;
	__device_handler_t handler;
} g_device;

void
device_init (void) {
    g_device.bpf = -1;
    g_device.buffer = NULL;
    g_device.buffer_size = 0;
    g_device.terminate = 0;
    g_device.thread = pthread_self();
    g_device.handler = NULL;
}

int
device_open (const char *device_name) {
	int index, flag;
	char dev[16];
	struct ifreq ifr;

	for (index = 0; index < BPF_DEVICE_NUM; index++) {
		snprintf(dev, sizeof(dev), "/dev/bpf%d", index);
		if ((g_device.bpf = open(dev, O_RDWR, 0)) != -1) {
			break;
		}
	}
	if (g_device.bpf == -1) {
		perror("open");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);
	if (ioctl(g_device.bpf, BIOCSETIF, &ifr) == -1) {
		perror("ioctl [BIOCSETIF]");
		goto ERROR;
	}
	if (ioctl(g_device.bpf, BIOCGBLEN, &g_device.buffer_size) == -1) {
		perror("ioctl [BIOCGBLEN]");
		goto ERROR;
	}
	if ((g_device.buffer = malloc(g_device.buffer_size)) == NULL) {
		perror("malloc");
		goto ERROR;
	}
	if (ioctl(g_device.bpf, BIOCPROMISC, NULL) == -1) {
		perror("ioctl [BIOCPROMISC]");
		goto ERROR;
	}
	flag = 1;
	if (ioctl(g_device.bpf, BIOCSSEESENT, &flag) == -1) {
		perror("ioctl [BIOCSSEESENT]");
		goto ERROR;
	}
	flag = 1;
	if (ioctl(g_device.bpf, BIOCIMMEDIATE, &flag) == -1) {
		perror("ioctl [BIOCIMMEDIATE]");
		goto ERROR;
	}
	flag = 1;
	if (ioctl(g_device.bpf, BIOCSHDRCMPLT, &flag) == -1) {
		perror("ioctl [BIOCSHDRCMPLT]");
		goto ERROR;
	}
	return  0;

ERROR:
	device_close();
	return -1;
}

void
device_close (void) {
	if (pthread_equal(g_device.thread, pthread_self()) == 0) {
        g_device.terminate = 1;
		pthread_join(g_device.thread, NULL);
	}
	if (g_device.bpf != -1) {
		close(g_device.bpf);
	}
	free(g_device.buffer);
}

void
device_set_handler (__device_handler_t handler) {
    g_device.handler = handler;
}

static void *
device_rthread (void *arg) {
	ssize_t len = 0;
	struct bpf_hdr *hdr;

	(void)arg;
	while (!g_device.terminate) {
		if (len <= 0) {
			len = read(g_device.bpf, g_device.buffer, g_device.buffer_size);
			if (len == -1) {
				continue;
			}
			hdr = (struct bpf_hdr *)g_device.buffer;
		} else {
			hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
		}
        g_device.handler((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen);
		len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	}
	pthread_exit(NULL);
}

int
device_dispatch (void) {
    int err;

    if (!g_device.handler) {
        fprintf(stderr, "device handler is not set\n");
        return -1;
    }
	if ((err = pthread_create(&g_device.thread, NULL, device_rthread, NULL)) != 0) {
		fprintf(stderr, "pthread_create: error, code=%d\n", err);
        return -1;
	}
    return 0;
}

ssize_t
device_write (const uint8_t *buffer, size_t len) {
	if (!buffer) {
		return -1;
	}
	return write(g_device.bpf, buffer, len);
}

#ifdef _DEVICE_UNIT_TEST
#include <signal.h>

void
debug_handler (uint8_t *buf, size_t len) {
	printf("device read: %ld octets\n", len);
	hexdump(stderr, buf, len);
}

int
main (int argc, char *argv[]) {
	sigset_t sigset;
	int signo;

	if (argc != 2) {
		fprintf(stderr, "usage: %s device-name\n", argv[0]);
		return -1;
	}
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
    device_init();
    if (device_open(argv[1]) == -1) {
        return -1;
    }
    device_set_handler(debug_handler);
    if (device_dispatch() == -1) {
        device_close();
		return -1;
	}
	sigwait(&sigset, &signo);
	device_close();
	return  0;
}
#endif
