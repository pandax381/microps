#include "udp.h"
#include "ip.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/queue.h>

#define UDP_CB_TABLE_SIZE 16
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t sum;
};

struct udp_queue_hdr {
	ip_addr_t addr;
	uint16_t port;
	uint16_t len;
	uint8_t data[0];
};

struct udp_cb {
    int used;
    uint16_t port;
    struct queue_head queue;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct {
	struct udp_cb cb[UDP_CB_TABLE_SIZE];
    uint8_t pool[UDP_SOURCE_PORT_MAX - UDP_SOURCE_PORT_MIN];
} udp;

int
udp_init (void) {
	int index;

	for (index = 0; index < UDP_CB_TABLE_SIZE; index++) {
		udp.cb[index].used = 0;
		udp.cb[index].port = 0;
		udp.cb[index].queue.next = NULL;
		udp.cb[index].queue.tail = NULL;
		pthread_mutex_init(&udp.cb[index].mutex, NULL);
		pthread_cond_init(&udp.cb[index].cond, NULL);
	}
    if (ip_add_protocol(IP_PROTOCOL_UDP, udp_recv) == -1) {
        return -1;
    }
    return 0;
}

void
udp_recv (uint8_t *dgram, size_t dlen, ip_addr_t *src, ip_addr_t *dst) {
	struct udp_hdr *hdr;
	uint32_t pseudo = 0;
    int index;
	struct udp_cb *cb;
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
    for (index = 0; index < UDP_CB_TABLE_SIZE; index++) {
        cb = &udp.cb[index];
        pthread_mutex_lock(&cb->mutex);
        if (cb->used && cb->port == ntoh16(hdr->dport)) {
            data = malloc(sizeof(struct udp_queue_hdr) + (dlen - sizeof(struct udp_hdr)));
            if (!data) {
                pthread_mutex_unlock(&cb->mutex);
                return;
            }
            queue_hdr = data;
            queue_hdr->addr = *src;
            queue_hdr->port = ntoh16(hdr->sport);
            queue_hdr->len = dlen - sizeof(struct udp_hdr);
            memcpy(queue_hdr + 1, hdr + 1, dlen - sizeof(struct udp_hdr));
            queue_push(&cb->queue, data, sizeof(struct udp_queue_hdr) + (dlen - sizeof(struct udp_hdr)));
            pthread_cond_signal(&cb->cond);
            pthread_mutex_unlock(&cb->mutex);
            return;
        }
        pthread_mutex_unlock(&cb->mutex);
    }
    // icmp_send_destination_unreachable();
}

ssize_t
udp_send (uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
	char packet[65536];
	struct udp_hdr *hdr;
	uint32_t pseudo = 0;
	ip_addr_t self;

	hdr = (struct udp_hdr *)packet;
	hdr->sport = hton16(sport);
	hdr->dport = hton16(port);
	hdr->len = hton16(sizeof(struct udp_hdr) + len);
	hdr->sum = 0;
	memcpy(hdr + 1, buf, len);
    ip_get_addr(&self);
	pseudo += (self >> 16) & 0xffff;
	pseudo += self & 0xffff;
	pseudo += (*peer >> 16) & 0xffff;
	pseudo += *peer & 0xffff;
	pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
	pseudo += hton16(sizeof(struct udp_hdr) + len);
	hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, pseudo);
	return ip_send(IP_PROTOCOL_UDP, (uint8_t *)packet, sizeof(struct udp_hdr) + len, peer);
}

int
udp_api_open (void) {
	int index;
	struct udp_cb *cb;

	for (index = 0; index < UDP_CB_TABLE_SIZE; index++) {
        cb = &udp.cb[index];
		pthread_mutex_lock(&cb->mutex);
        if (!cb->used) {
            cb->used = 1;
            pthread_mutex_unlock(&cb->mutex);
            return index;
        }
        pthread_mutex_unlock(&cb->mutex);
	}
    return -1;
}

int
udp_api_close (int soc) {
    struct udp_cb *cb;
	struct queue_entry *entry;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    cb = &udp.cb[soc];
	pthread_mutex_lock(&cb->mutex);
	cb->used = 0;
    if (cb->port >= UDP_SOURCE_PORT_MIN && cb->port <= UDP_SOURCE_PORT_MAX) {
        udp.pool[cb->port - UDP_SOURCE_PORT_MIN] = 0;
    }
    cb->port = 0;
	while ((entry = queue_pop(&cb->queue)) != NULL) {
		free(entry->data);
		free(entry);
	}
	cb->queue.next = cb->queue.tail = NULL;
	pthread_mutex_unlock(&cb->mutex);
    return 0;
}

int
udp_api_bind (int soc, uint16_t port) {
    struct udp_cb *cb;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    cb = &udp.cb[soc];
	pthread_mutex_lock(&cb->mutex);
	if (!cb->used) {
		pthread_mutex_unlock(&cb->mutex);
		return -1;
	}
    cb->port = port;
    pthread_mutex_unlock(&cb->mutex);
    if (port >= UDP_SOURCE_PORT_MIN && port <= UDP_SOURCE_PORT_MAX) {
        udp.pool[port - UDP_SOURCE_PORT_MIN] = 1;
    }
    return 0;
}

ssize_t
udp_api_recv (int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port) {
    struct udp_cb *cb;
	struct queue_entry *entry;
	ssize_t len;
	struct udp_queue_hdr *queue_hdr;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    cb = &udp.cb[soc];
	pthread_mutex_lock(&cb->mutex);
	if (!cb->used) {
		pthread_mutex_unlock(&cb->mutex);
		return -1;
	}
	while ((entry = queue_pop(&cb->queue)) == NULL) {
		pthread_cond_wait(&cb->cond, &cb->mutex);
	}
	pthread_mutex_unlock(&cb->mutex);
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
udp_api_send (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port) {
    struct udp_cb *cb;
    int index;
    uint16_t sport;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    cb = &udp.cb[soc];
	pthread_mutex_lock(&cb->mutex);
	if (!cb->used) {
		pthread_mutex_unlock(&cb->mutex);
		return -1;
	}
    if (!cb->port) {
        for (index = UDP_SOURCE_PORT_MIN; index <= UDP_SOURCE_PORT_MAX; index++) {
            if (!udp.pool[index - UDP_SOURCE_PORT_MIN]) {
                cb->port = index;
                break;
            }
        }
        if (index == UDP_SOURCE_PORT_MAX + 1) {
            return -1;
        }
    }
    sport = cb->port;
    pthread_mutex_unlock(&cb->mutex);
	return udp_send(sport, buf, len, peer, port);
}
