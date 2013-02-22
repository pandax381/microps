#include "udp.h"
#include "ip.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/queue.h>

#define UDP_PORT_TABLE_SIZE 65536
#define UDP_PORT_DINAMIC_MIN 49152

struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t sum;
};

struct udp_dsc {
	int used;
	uint16_t port;
	struct queue_head queue;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct udp_queue_hdr {
	ip_addr_t addr;
	uint16_t port;
	uint16_t len;
	uint8_t data[0];
};

struct {
	struct udp_dsc port_table[UDP_PORT_TABLE_SIZE];
} g_udp;

void
udp_init (void) {
	int index;

	for (index = 0; index < UDP_PORT_TABLE_SIZE; index++) {
		g_udp.port_table[index].used = 0;
		g_udp.port_table[index].port = index;
		g_udp.port_table[index].queue.next = NULL;
		g_udp.port_table[index].queue.tail = NULL;
		pthread_mutex_init(&g_udp.port_table[index].mutex, NULL);
		pthread_cond_init(&g_udp.port_table[index].cond, NULL);
	}
}

struct udp_dsc *
udp_api_open (const char *port) {
	long portno;
	struct udp_dsc *dsc;
	int index;

	// specific port
	if (port) {
		portno = strtol(port, NULL, 10);
		if (portno < 0 || portno > 65535) {
			return NULL;
		}
		dsc = &g_udp.port_table[portno];
		pthread_mutex_lock(&dsc->mutex);
		if (dsc->used) {
			pthread_mutex_unlock(&dsc->mutex);
			return NULL;
		}
		dsc->used = 1;
		dsc->queue.next = NULL;
		dsc->queue.tail = NULL;
		dsc->queue.num = 0;
		pthread_mutex_unlock(&dsc->mutex);
		return dsc;
	}
	// dynamic port
	for (index = 0; index < UDP_PORT_TABLE_SIZE; index++) {
		dsc = &g_udp.port_table[index];
		pthread_mutex_lock(&dsc->mutex);
		if (!dsc->used) {
			dsc->used = 1;
			pthread_mutex_unlock(&dsc->mutex);
			return dsc;
		}
		pthread_mutex_unlock(&dsc->mutex);
	}
	return NULL;
}

void
udp_api_close (struct udp_dsc *dsc) {
	struct queue_entry *entry;

	pthread_mutex_lock(&dsc->mutex);
	dsc->used = 0;
	while ((entry = queue_pop(&dsc->queue)) != NULL) {
		free(entry->data);
		free(entry);
	}
	dsc->queue.next = dsc->queue.tail = NULL;
	pthread_mutex_unlock(&dsc->mutex);
}

ssize_t
udp_api_recv (struct udp_dsc *dsc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port) {
	struct queue_entry *entry;
	ssize_t len;
	struct udp_queue_hdr *queue_hdr;

	pthread_mutex_lock(&dsc->mutex);
	if (!dsc->used) {
		pthread_mutex_unlock(&dsc->mutex);
		return -1;
	}
	while ((entry = queue_pop(&dsc->queue)) == NULL) {
		pthread_cond_wait(&dsc->cond, &dsc->mutex);
	}
	pthread_mutex_unlock(&dsc->mutex);
	queue_hdr = (struct udp_queue_hdr *)entry->data;
	*peer = queue_hdr->addr;
	*port = queue_hdr->port;
	len = (size < queue_hdr->len) ? size : queue_hdr->len;
	memcpy(buf, queue_hdr + 1, len);
	free(entry->data);
	free(entry);
	return len;
}

ssize_t
udp_api_send (struct udp_dsc *dsc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
	return udp_send (dsc, buf, len, peer, port);
}

void
udp_recv (uint8_t *dgram, size_t dlen, ip_addr_t *src, ip_addr_t *dst) {
	struct udp_hdr *hdr;
	uint32_t pseudo = 0;
	struct udp_dsc *dsc;
	void *data;
	struct udp_queue_hdr *queue_hdr;

	if (dlen < sizeof(struct udp_hdr)) {
		return;
	}
	hdr = (struct udp_hdr *)dgram;
	pseudo += *src >> 16;
	pseudo += *src & 0xffff;
	pseudo += *dst >> 16;
	pseudo += *dst & 0xffff;
	pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
	pseudo += hton16(dlen);
	if (cksum16((uint16_t *)hdr, dlen, pseudo) != 0) {
		return;
	}
	dsc = &g_udp.port_table[ntoh16(hdr->dport)];
	pthread_mutex_lock(&dsc->mutex);
	if (dsc->used) {
		data = malloc(sizeof(struct udp_queue_hdr) + (dlen - sizeof(struct udp_hdr)));
		if (!data) {
			pthread_mutex_unlock(&dsc->mutex);
			return;
		}
		queue_hdr = data;
		queue_hdr->addr = *src;
		queue_hdr->port = ntoh16(hdr->sport);
		queue_hdr->len = dlen - sizeof(struct udp_hdr);
		memcpy(queue_hdr + 1, hdr + 1, dlen - sizeof(struct udp_hdr));
		queue_push(&dsc->queue, data, sizeof(struct udp_queue_hdr) + (dlen - sizeof(struct udp_hdr)));
		pthread_cond_signal(&dsc->cond);
	} else {
		// icmp_send_destination_unreachable();
	}
	pthread_mutex_unlock(&dsc->mutex);
}

ssize_t
udp_send (struct udp_dsc *dsc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
	char packet[65536];
	struct udp_hdr *hdr;
	uint32_t pseudo = 0;
	ip_addr_t *self;

	hdr = (struct udp_hdr *)packet;
	hdr->sport = hton16(dsc->port);
	hdr->dport = hton16(port);
	hdr->len = hton16(sizeof(struct udp_hdr) + len);
	hdr->sum = 0;
	memcpy(hdr + 1, buf, len);
	self = ip_get_addr();
	pseudo += (*self >> 16) & 0xffff;
	pseudo += *self & 0xffff;
	pseudo += (*peer >> 16) & 0xffff;
	pseudo += *peer & 0xffff;
	pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
	pseudo += hton16(sizeof(struct udp_hdr) + len);
	hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, pseudo);
	return ip_send(IP_PROTOCOL_UDP, (uint8_t *)packet, sizeof(struct udp_hdr) + len, peer);
}


#ifdef _UDP_UNIT_TEST
#include "device.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

int
main (int argc, char *argv[]) {
	struct udp_dsc *dsc;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;
	ssize_t len;

	if (argc != 6) {
		fprintf(stderr, "usage: %s device-name ethernet-addr ip-addr netmask default-gw\n", argv[0]);
		goto ERROR;
	}
	udp_init();
	if (ip_set_addr(argv[3], argv[4]) == -1) {
		fprintf(stderr, "error: ip-addr/netmask is invalid\n");
		goto ERROR;
	}
	if (ip_set_gw(argv[5]) == -1) {
		fprintf(stderr, "error: default-gw is invalid\n");
		goto ERROR;
	}
	ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
	ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
	arp_init();
    if (ethernet_set_addr(argv[2]) == -1) {
		fprintf(stderr, "error: ethernet-addr invalid\n");
		goto ERROR;
	}
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(argv[1], ethernet_recv) == -1) {
		fprintf(stderr, "error: device-name invalid\n");
        goto ERROR;
    }
	arp_send_garp();
	dsc = udp_api_open("7");
	if (!dsc) {
		goto ERROR;
	}
	while (1) {
		len = udp_api_recv(dsc, buf, sizeof(buf), &peer_addr, &peer_port);
		if (len < 0) {
			break;
		}
		fprintf(stderr, "udp_api_recv(): %ld\n", len);
		hexdump(stderr, buf, len);
		udp_api_send(dsc, buf, len, &peer_addr, peer_port);
	}
	udp_api_close(dsc);
    device_cleanup();
    return  0;

ERROR:
    return -1;
}
#endif
