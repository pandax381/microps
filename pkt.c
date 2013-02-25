#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "device.h"
#include "util.h"

struct {
	int soc;
	int terminate;
	pthread_t thread;
	__device_handler_t handler;
} g_device;

void
device_init (void) {
    g_device.soc = -1;
    g_device.terminate = 0;
    g_device.thread = pthread_self();
    g_device.handler = NULL;
}

int
device_open (const char *device_name) {
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;

	if ((g_device.soc = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL))) == -1) {
		perror("socket");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);
	if (ioctl(g_device.soc, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl [SIOCGIFINDEX]");
		goto ERROR;
	}
	memset(&sockaddr, 0x00, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = hton16(ETH_P_ALL);
	sockaddr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(g_device.soc, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		perror("bind");
		goto ERROR;
	}
	if (ioctl(g_device.soc, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCGIFFLAGS]");
		goto ERROR;
	}
	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl(g_device.soc, SIOCSIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCSIFFLAGS]");
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
    if (g_device.soc != -1) {
        close(g_device.soc);
    }
}

void
device_set_handler (__device_handler_t handler) {
    g_device.handler = handler;
}

static void *
device_rthread (void *arg) {
	uint8_t buf[2048];
	ssize_t len;

	(void)arg;
	while (!g_device.terminate) {
		len = read(g_device.soc, buf, sizeof(buf));
		if (len == -1) {
			continue;
		}
		if (g_device.handler) {
			g_device.handler(buf, len);
		}
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
	return write(g_device.soc, buffer, len);
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
	return 0;
}
#endif
