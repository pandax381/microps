#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "device.h"
#include "arp.h"
#include "util.h"

#define ETHERNET_DEVICE_TABLE_SIZE 4
#define ETHERNET_PROTOCOL_TABLE_SIZE 8

struct ethernet_hdr {
    ethernet_addr_t dst;
    ethernet_addr_t src;
    uint16_t type;
} __attribute__ ((packed));

struct ethernet_protocol {
    uint8_t used;
    uint16_t type;
    void (*callback)(uint8_t *, size_t, void *);
};

struct ethernet_device {
    uint8_t used;
    device_t *device;
    ethernet_addr_t addr;
    pthread_t thread;
};

static struct {
    int terminate;
    struct ethernet_device device_table[ETHERNET_DEVICE_TABLE_SIZE];
    struct ethernet_protocol protocol_table[ETHERNET_PROTOCOL_TABLE_SIZE];
} ethernet;

#define ETHERNET_DEVICE_TABLE_FOREACH(x) \
    for (x = ethernet.device_table; x != ethernet.device_table + ETHERNET_DEVICE_TABLE_SIZE; x++)
#define ETHERNET_DEVICE_TABLE_OFFSET(x) \
    ((x - ethernet.device_table) / sizeof(*x))
#define ETHERNET_PROTOCOL_TABLE_FOREACH(x) \
    for (x = ethernet.protocol_table; x != ethernet.protocol_table + ETHERNET_PROTOCOL_TABLE_SIZE; x++)
#define ETHERNET_PROTOCOL_TABLE_OFFSET(x) \
    ((x - ethernet.protocol_table) / sizeof(*x))

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
    struct ethernet_device *device;

    ethernet.terminate = 0;
    ETHERNET_DEVICE_TABLE_FOREACH(device) {
        device->thread = pthread_self();
    }
    return 0;
}

int
ethernet_add_protocol (uint16_t type, void (*callback)(uint8_t *, size_t, void *)) {
    struct ethernet_protocol *protocol;

    ETHERNET_PROTOCOL_TABLE_FOREACH(protocol) {
        if (!protocol->used) {
            protocol->used = 1;
            protocol->type = hton16(type);
            protocol->callback = callback;
            break;
        }
    }
    if (ETHERNET_PROTOCOL_TABLE_OFFSET(protocol) == ETHERNET_PROTOCOL_TABLE_SIZE) {
        return -1;
    }
    return 0;
}

static void
ethernet_input (uint8_t *frame, size_t flen, void *arg) {
    struct ethernet_device *device;
    struct ethernet_hdr *hdr;
    uint8_t *payload;
    size_t plen;
    struct ethernet_protocol *protocol;

    device = (struct ethernet_device *)arg;
    if (flen < (ssize_t)sizeof(struct ethernet_hdr)) {
        return;
    }
    hdr = (struct ethernet_hdr *)frame;
    if (memcmp(&device->addr, &hdr->dst, sizeof(ethernet_addr_t)) != 0) {
        if (memcmp(&ETHERNET_ADDR_BCAST, &hdr->dst, sizeof(ethernet_addr_t)) != 0) {
            return;
        }
    }
    payload = (uint8_t *)(hdr + 1);
    plen = flen - sizeof(struct ethernet_hdr);
    ETHERNET_PROTOCOL_TABLE_FOREACH(protocol) {
        if (protocol->used && protocol->type == hdr->type) {
            return protocol->callback(payload, plen, device);
        }
    }
}

ssize_t
ethernet_output (struct ethernet_device *device, uint16_t type, const uint8_t *payload, size_t plen, const ethernet_addr_t *dst) {
    uint8_t frame[ETHERNET_FRAME_SIZE_MAX];
    struct ethernet_hdr *hdr;
    size_t flen;

    if (!payload || plen > ETHERNET_PAYLOAD_SIZE_MAX || (!dst)) {
        return -1;
    }
    memset(frame, 0, sizeof(frame));
    hdr = (struct ethernet_hdr *)frame;
    memcpy(hdr->dst.addr, dst->addr, ETHERNET_ADDR_LEN);
    memcpy(hdr->src.addr, device->addr.addr, ETHERNET_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr + 1, payload, plen);
    flen = sizeof(struct ethernet_hdr) + (plen < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : plen);
    return device_output(device->device, frame, flen) == (ssize_t)flen ? (ssize_t)plen : -1;
}

struct ethernet_device *
ethernet_device_open (const char *name, const char *addr) {
    struct ethernet_device *device;

    ETHERNET_DEVICE_TABLE_FOREACH(device) {
        if (!device->used) {
            if (ethernet_addr_pton(addr, &device->addr) == -1) {
                return NULL;
            }
            device->device = device_open(name);
            if (!device->device) {
                return NULL;
            }
            device->used = 1;
            return device;
        }
    }
    return NULL;
}

void
ethernet_device_close (struct ethernet_device *device) {
    if (!device) {
        return;
    }
    if (!pthread_equal(device->thread, pthread_self())) {
        ethernet.terminate = 1;
        pthread_join(device->thread, NULL);
    }
    if (device->device) {
        device_close(device->device);
    }
}

ethernet_addr_t *
ethernet_device_addr (struct ethernet_device *device, ethernet_addr_t *dst) {
    return memcpy(dst, &device->addr, sizeof(ethernet_addr_t));
}

void *
ethernet_device_input_thread (void *arg) {
    struct ethernet_device *device;

    device = (struct ethernet_device *)arg;
    while (!ethernet.terminate) {
        device_input(device->device, ethernet_input, device, 1000);
    }
    return NULL;
}

int
ethernet_device_run (struct ethernet_device *device) {
    int err;

    if ((err = pthread_create(&device->thread, NULL, ethernet_device_input_thread, device)) != 0) {
        fprintf(stderr, "pthread_create: error, code=%d\n", err);
        return -1;
    }
    return 0;
}
