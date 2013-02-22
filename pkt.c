#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "device.h"
#include "util.h"

struct {
	int fd;  
	int terminate;
	pthread_t thread;
	__device_interrupt_handler_t handler;
} g_device;

static void *
device_reader_thread (void *arg);

int
device_init (const char *device_name, __device_interrupt_handler_t handler) {
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;
	int err;

	g_device.thread = pthread_self();
	if ((g_device.fd = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL))) == -1) {
		perror("socket");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);
	if (ioctl(g_device.fd, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl [SIOCGIFINDEX]");
		goto ERROR;
	}
	memset(&sockaddr, 0x00, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = hton16(ETH_P_ALL);
	sockaddr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(g_device.fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		perror("bind");
		goto ERROR;
	}
	if (ioctl(g_device.fd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCGIFFLAGS]");
		goto ERROR;
	}
	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl(g_device.fd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCSIFFLAGS]");
		goto ERROR;
	}
	g_device.handler = handler;
	if ((err = pthread_create(&g_device.thread, NULL, device_reader_thread, NULL)) != 0) {
		fprintf(stderr, "pthread_create: error.\n");
		goto ERROR;
	}
	return  0;

ERROR:
	device_cleanup();
	return -1;
}

void
device_cleanup (void) {
	g_device.terminate = 1;
	if (pthread_equal(g_device.thread, pthread_self()) == 0) {
		pthread_join(g_device.thread, NULL);
		g_device.thread = pthread_self();
	}
	g_device.terminate = 0;
	if (g_device.fd != -1) {
		close(g_device.fd);
		g_device.fd = -1;
	}
	g_device.handler = NULL;
}

static void *
device_reader_thread (void *arg) {
	uint8_t buf[2048];
	ssize_t len;

	(void)arg;
	while (!g_device.terminate) {
		len = read(g_device.fd, buf, sizeof(buf));
		if (len == -1) {
			continue;
		}
		if (g_device.handler) {
			g_device.handler(buf, len);
		}
	}
	pthread_exit(NULL);
}

ssize_t
device_write (const uint8_t *buffer, size_t len) {
	if (!buffer) {
		return -1;
	}
	return write(g_device.fd, buffer, len);
}

ssize_t
device_writev (const struct iovec *iov, int iovcnt) {
	return writev(g_device.fd, iov, iovcnt);
}

#ifdef _DEVICE_UNIT_TEST

#include "util.h"

void
interrupt_handler (uint8_t *buf, size_t len) {
	printf("device input: %ld octets\n", len);
	hexdump(stderr, buf, len);
}

int
main (int argc, char *argv[]) {
	sigset_t sigset;
	int signo;

	if (argc != 2) {
		fprintf(stderr, "usage: %s device-name\n", argv[0]);
		goto ERROR;
	}
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (device_init(argv[1], interrupt_handler) == -1) {
		goto ERROR;
	}
	sigwait(&sigset, &signo);
	device_cleanup();
	return  0;

ERROR:
	return -1;
}

#endif
