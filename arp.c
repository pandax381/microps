#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "arp.h"
#include "util.h"

#define ARP_HRD_ETHERNET 0x0001
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2
#define ARP_TABLE_SIZE 4096
#define ARP_LOOKUP_TIMEOUT_SEC 1

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
} __attribute__ ((packed));

struct arp_ethernet {
    struct arp_hdr hdr;
    ethernet_addr_t sha;
    ip_addr_t spa;
    ethernet_addr_t tha;
    ip_addr_t tpa;
} __attribute__ ((packed));

struct arp_entry {
    ip_addr_t pa;
    ethernet_addr_t ha;
    time_t timestamp;
    pthread_cond_t cond;
    void *data;
    size_t len;
    struct arp_entry *next;
};

static struct {
    time_t timestamp;
    struct {
        struct arp_entry table[ARP_TABLE_SIZE];
        struct arp_entry *head;
        struct arp_entry *pool;
    } table;
    pthread_mutex_t mutex;
} arp;

static void
arp_input (uint8_t *packet, size_t plen, void *device);

int
arp_init (void) {
    int index;
    struct arp_entry *entry;

    time(&arp.timestamp);
    for (index = 0; index < ARP_TABLE_SIZE; index++) {
        entry = arp.table.table + index;
        entry->pa = 0;
        entry->timestamp = 0;
        memset(&entry->ha, 0, sizeof(ethernet_addr_t));
        pthread_cond_init(&entry->cond, NULL);
        entry->data = NULL;
        entry->len = 0;
        entry->next = (index != ARP_TABLE_SIZE) ? (entry + 1) : NULL;
    }
    arp.table.head = NULL;
    arp.table.pool = arp.table.table;
    pthread_mutex_init(&arp.mutex, NULL);
    ethernet_add_protocol(ETHERNET_TYPE_ARP, arp_input);
    return 0;
}

static int
arp_table_select (const ip_addr_t *pa, ethernet_addr_t *ha) {
    struct arp_entry *entry;

    for (entry = arp.table.head; entry; entry = entry->next) {
        if (entry->pa == *pa) {
            memcpy(ha, &entry->ha, sizeof(ethernet_addr_t));
            return 0;
        }
    }
    return -1;
}

static int
arp_table_update (struct ethernet_device *device, const ip_addr_t *pa, const ethernet_addr_t *ha) {
    struct arp_entry *entry;

    for (entry = arp.table.head; entry; entry = entry->next) {
        if (entry->pa == *pa) {
            memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
            time(&entry->timestamp);
            pthread_cond_broadcast(&entry->cond);
            if (entry->data) {
                ethernet_output(device, ETHERNET_TYPE_IP, (uint8_t *)entry->data, entry->len, &entry->ha);
                free(entry->data);
                entry->data = NULL;
                entry->len = 0;
            }
            return 0;
        }
    }
    return -1;
}

static int
arp_table_insert (const ip_addr_t *pa, const ethernet_addr_t *ha) {
    struct arp_entry *entry;

    entry = arp.table.pool;
    if (!entry) {
        return -1;
    }
    entry->pa = *pa;
    memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
    time(&entry->timestamp);
    arp.table.pool = entry->next;
    entry->next = arp.table.head;
    arp.table.head = entry;
    pthread_cond_broadcast(&entry->cond);
    return 0;
}

static void
arp_table_check_timeout (void) {
    struct arp_entry *prev, *entry;

    prev = NULL;
    entry = arp.table.head;
    while (entry) {
        if (arp.timestamp - entry->timestamp > 300) {
            entry->pa = 0;
            memset(&entry->ha, 0, sizeof(ethernet_addr_t));
            entry->timestamp = 0;
            if (prev) {
                prev->next = entry->next;
            } else {
                arp.table.head = entry->next;
            }
            entry->next = arp.table.pool;
            arp.table.pool = entry;
            entry = prev ? prev->next : arp.table.head;
        } else {
            entry = entry->next;
        }
    }
}

static int
arp_send_request (struct ethernet_device *device, const ip_addr_t *tpa) {
    struct arp_ethernet request;

    if (!tpa) {
        return -1;
    }
    request.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    request.hdr.pro = hton16(ETHERNET_TYPE_IP);
    request.hdr.hln = 6;
    request.hdr.pln = 4;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    ethernet_device_addr(device, &request.sha);
    ip_get_addr(device, &request.spa);
    memset(&request.tha, 0, ETHERNET_ADDR_LEN);
    request.tpa = *tpa;
    if (ethernet_output(device, ETHERNET_TYPE_ARP, (uint8_t *)&request, sizeof(request), &ETHERNET_ADDR_BCAST) < 0) {
        return -1;
    }
    return  0;
}

static int
arp_send_reply (struct ethernet_device *device, const ethernet_addr_t *tha, const ip_addr_t *tpa, const ethernet_addr_t *dst) {
    struct arp_ethernet reply;

    if (!tha || !tpa) {
        return -1;
    }
    reply.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    reply.hdr.pro = hton16(ETHERNET_TYPE_IP);
    reply.hdr.hln = 6;
    reply.hdr.pln = 4;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    ethernet_device_addr(device, &reply.sha);
    ip_get_addr(device, &reply.spa);
    reply.tha = *tha;
    reply.tpa = *tpa;
    if (ethernet_output(device, ETHERNET_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst) < 0) {
        return -1;
    }
    return 0;
}

static void
arp_input (uint8_t *packet, size_t plen, void *device) {
    struct arp_ethernet *message;
    time_t timestamp;
    int marge = 0;

    if (plen < sizeof(struct arp_ethernet)) {
        return;
    }
    message = (struct arp_ethernet *)packet;
    if (ntoh16(message->hdr.hrd) != ARP_HRD_ETHERNET) {
        return;
    }
    if (ntoh16(message->hdr.pro) != ETHERNET_TYPE_IP) {
        return;
    }
    if (message->hdr.hln != ETHERNET_ADDR_LEN) {
        return;
    }
    if (message->hdr.pln != IP_ADDR_LEN) {
        return;
    }
    pthread_mutex_lock(&arp.mutex);
    time(&timestamp);
    if (timestamp - arp.timestamp > 10) {
        arp.timestamp = timestamp;
        arp_table_check_timeout();
    }
    marge = (arp_table_update(device, &message->spa, &message->sha) == 0) ? 1 : 0;
    pthread_mutex_unlock(&arp.mutex);
    if (message->tpa == ip_get_addr(device, NULL)) {
        if (!marge) {
            pthread_mutex_lock(&arp.mutex);
            arp_table_insert(&message->spa, &message->sha);
            pthread_mutex_unlock(&arp.mutex);
        }
        if (ntoh16(message->hdr.op) == ARP_OP_REQUEST) {
            arp_send_reply(device, &message->sha, &message->spa, &message->sha);
        }
    }
}

int
arp_resolve (struct ethernet_device *device, const ip_addr_t *pa, ethernet_addr_t *ha, const void *data, size_t len) {
    struct arp_entry *entry;

    pthread_mutex_lock(&arp.mutex);
    if (arp_table_select(pa, ha) == 0) {
        pthread_mutex_unlock(&arp.mutex);
        return 1;
    }
    if (!data) {
        pthread_mutex_unlock(&arp.mutex);
        return -1;
    }
    entry = arp.table.pool;
    if (!entry) {
        pthread_mutex_unlock(&arp.mutex);
        return -1;
    }
    entry->data = malloc(len);
    if (!entry->data) {
        pthread_mutex_unlock(&arp.mutex);
        return -1;
    }
    memcpy(entry->data, data, len);
    entry->len = len;
    arp.table.pool = entry->next;
    entry->next = arp.table.head;
    arp.table.head = entry;
    entry->pa = *pa;
    time(&entry->timestamp);
    arp_send_request(device, pa);
    pthread_mutex_unlock(&arp.mutex);
    return  0;
}
