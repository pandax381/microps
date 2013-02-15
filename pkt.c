#include "pkt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

struct pkt {
	int soc;
};

pkt_t *
pkt_open (const char *name) {
	pkt_t *obj;
	struct ifreq ifr;
	struct sockaddr_ll sockaddr;

	if (name == NULL || name[0] == '\0') {
		goto ERROR;
	}
	if ((obj = malloc(sizeof(pkt_t))) == NULL) {
		perror("malloc");
		goto ERROR;
	}
	if ((obj->soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		goto ERROR;
	}
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(obj->soc, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl [SIOCGIFINDEX]");
		goto ERROR;
	}
	memset(&sockaddr, 0x00, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ALL);
	sockaddr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(obj->soc, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		perror("bind");
		goto ERROR;
	}
	if (ioctl(obj->soc, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCGIFFLAGS]");
		goto ERROR;
	}
	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	if (ioctl(obj->soc, SIOCSIFFLAGS, &ifr) == -1) {
		perror("ioctl [SIOCSIFFLAGS]");
		goto ERROR;
	}
	return obj;

ERROR:
	pkt_close(obj);
	return NULL;
}

void
pkt_close (pkt_t *obj) {
	if (obj) {
		if (obj->soc != -1) {
			close(obj->soc);
		}
		free(obj);
	}
}

ssize_t
pkt_write (pkt_t *obj, const uint8_t *buffer, size_t length) {
	if (!obj || !buffer) {
		return -1;
	}
	return write(obj->soc, buffer, length);
}

ssize_t
pkt_read (pkt_t *obj, uint8_t *buffer, size_t length) {
	if (!obj || !buffer) {
		return -1;
	}
	return read(obj->soc, buffer, length);
}
