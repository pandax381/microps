#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "device.h"
#include "util.h"

#define ETHERNET_PROTOCOL_TABLE_SIZE 8

struct ethernet_hdr {
	ethernet_addr_t dst;
	ethernet_addr_t src;
	uint16_t type;
} __attribute__ ((packed));

struct ethernet_protocol {
    uint16_t type;
    void (*callback)(uint8_t *, size_t, ethernet_addr_t *, ethernet_addr_t *);
    struct ethernet_protocol *next;
};

static struct {
    ethernet_addr_t addr;
    device_t *device;
    int terminate;
    pthread_t thread;
    struct {
        struct ethernet_protocol table[ETHERNET_PROTOCOL_TABLE_SIZE];
        struct ethernet_protocol *head;
        struct ethernet_protocol *pool;
    } protocol;
} ethernet;

const ethernet_addr_t ETHERNET_ADDR_BCAST = {"\xff\xff\xff\xff\xff\xff"};

int
ethernet_addr_pton (const char *p, ethernet_addr_t *n) {
	int index;
	char *ep;
	long val;

	if (!p || !n) {
        return -1;
	}
	for (index = 0; index < ETHERNET_ADDR_LEN; index++) {
		val = strtol(p, &ep, 16);
		if (ep == p || val < 0 || val > 0xff || (index < ETHERNET_ADDR_LEN - 1 && *ep != ':')) {
			break;
		}
		n->addr[index] = (uint8_t)val;
		p = ep + 1;
	}
	if (index != ETHERNET_ADDR_LEN || *ep != '\0') {
        return -1;
	}
	return  0;
}

char *
ethernet_addr_ntop (const ethernet_addr_t *n, char *p, size_t size) {
	if (!n || !p || size < ETHERNET_ADDR_STR_LEN + 1) {
        return NULL;
	}
	snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->addr[4], n->addr[5]);
	return p;
}

int
ethernet_init (void) {
	int index;
    struct ethernet_protocol *protocol;

    memset(&ethernet.addr, 0, sizeof(ethernet.addr));
    ethernet.device = NULL;
    ethernet.terminate = 0;
    ethernet.thread = pthread_self();
	for (index = 0; index < ETHERNET_PROTOCOL_TABLE_SIZE; index++) {
        protocol = ethernet.protocol.table + index;
		protocol->type = 0;
		protocol->callback = NULL;
        protocol->next = (index != ETHERNET_PROTOCOL_TABLE_SIZE) ? (protocol + 1) : NULL;
	}
    ethernet.protocol.head = NULL;
    ethernet.protocol.pool = ethernet.protocol.table;
    return 0;
}

ethernet_addr_t *
ethernet_get_addr (ethernet_addr_t *dst) {
    return memcpy(dst, &ethernet.addr, sizeof(ethernet_addr_t));
}

int
ethernet_add_protocol (uint16_t type, void (*callback)(uint8_t *, size_t, ethernet_addr_t *, ethernet_addr_t *)) {
    struct ethernet_protocol *protocol;

    protocol = ethernet.protocol.pool;
    if (!protocol) {
        return -1;
    }
    protocol->type = hton16(type);
    protocol->callback = callback;
    ethernet.protocol.pool = protocol->next;
    protocol->next = ethernet.protocol.head;
    ethernet.protocol.head = protocol;
    return 0;
}

void
ethernet_input (uint8_t *frame, size_t flen) {
	struct ethernet_hdr *hdr;
	uint8_t *payload;
	size_t plen;
    struct ethernet_protocol *protocol;

	if (flen < (ssize_t)sizeof(struct ethernet_hdr)) {
		return;
	}
	hdr = (struct ethernet_hdr *)frame;
    if (memcmp(&ethernet.addr, &hdr->dst, sizeof(ethernet_addr_t)) != 0) {
        if (memcmp(&ETHERNET_ADDR_BCAST, &hdr->dst, sizeof(ethernet_addr_t)) != 0) {
			return;
		}
	}
	payload = (uint8_t *)(hdr + 1);
	plen = flen - sizeof(struct ethernet_hdr);
    for (protocol = ethernet.protocol.head; protocol; protocol = protocol->next) {
        if (protocol->type == hdr->type) {
            return protocol->callback(payload, plen, &hdr->src, &hdr->dst);
        }
    }
}

ssize_t
ethernet_output (uint16_t type, const uint8_t *payload, size_t plen, const ethernet_addr_t *dst) {
	uint8_t frame[ETHERNET_FRAME_SIZE_MAX];
	struct ethernet_hdr *hdr;
	size_t flen;

	if (!payload || plen > ETHERNET_PAYLOAD_SIZE_MAX || !dst) {
		return -1;
	}
	memset(frame, 0, sizeof(frame));
	hdr = (struct ethernet_hdr *)frame;
	memcpy(hdr->dst.addr, dst->addr, ETHERNET_ADDR_LEN);
	memcpy(hdr->src.addr, ethernet.addr.addr, ETHERNET_ADDR_LEN);
	hdr->type = hton16(type);
	memcpy(hdr + 1, payload, plen);
	flen = sizeof(struct ethernet_hdr) + (plen < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : plen);
	return device_output(ethernet.device, frame, flen) == (ssize_t)flen ? (ssize_t)plen : -1;
}

int
ethernet_device_open (const char *name, const char *addr) {
	if (ethernet_addr_pton(addr, &ethernet.addr) == -1) {
        return -1;
    }
    if ((ethernet.device = device_open(name)) == NULL) {
        return -1;
    }
    return 0;
}

void
ethernet_device_close (void) {
    if (!pthread_equal(ethernet.thread, pthread_self())) {
        ethernet.terminate = 1;
        pthread_join(ethernet.thread, NULL);
    }
    device_close(ethernet.device);
}

void *
ethernet_device_input_thread (void *arg) {
    device_t *device;

    device = (device_t *)arg;
    while (!ethernet.terminate) {
        device_input(device, ethernet_input, 1000);
    }
    return NULL;
}

int
ethernet_device_run (void) {
    int err;

    if ((err = pthread_create(&ethernet.thread, NULL, ethernet_device_input_thread, ethernet.device)) != 0) {
        fprintf(stderr, "pthread_create: error, code=%d\n", err);
        return -1;
    }
    return 0;
}
