#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
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
    pthread_cond_t cond;
    struct arp_entry *next;
};

static struct {
    struct {
        struct arp_entry table[ARP_TABLE_SIZE];
        struct arp_entry *head;
        struct arp_entry *pool;
    } table;
    pthread_mutex_t mutex;
} arp;

static int
arp_send_request (const ip_addr_t *tpa);
static int
arp_send_reply (const ethernet_addr_t *tha, const ip_addr_t *tpa, const ethernet_addr_t *dst);

int
arp_init (void) {
    int index;

    for (index = 0; index < ARP_TABLE_SIZE; index++) {
        pthread_cond_init(&arp.table.table[index].cond, NULL);
        if (index < ARP_TABLE_SIZE - 1) {
            arp.table.table[index].next = &arp.table.table[index + 1];
        } else {
            arp.table.table[index].next = NULL;
        }
    }
    arp.table.head = NULL;
    arp.table.pool = &arp.table.table[0];
	pthread_mutex_init(&arp.mutex, NULL);
    ethernet_add_protocol(ETHERNET_TYPE_ARP, arp_recv);
    return 0;
}

int
arp_table_lookup (const ip_addr_t *pa, ethernet_addr_t *ha) {
    struct arp_entry *entry;
    struct timeval tv;
    struct timespec timeout;
    int ret;

	pthread_mutex_lock(&arp.mutex);
    for (entry = arp.table.head; entry; entry = entry->next) {
        if (entry->pa == *pa) {
            memcpy(ha, &entry->ha, sizeof(ethernet_addr_t));
            pthread_mutex_unlock(&arp.mutex);
            return 0;
        }
    }
    entry = arp.table.pool;
    if (!entry) {
        pthread_mutex_unlock(&arp.mutex);
        return -1;
    }
    arp.table.pool = entry->next;
    entry->next = arp.table.head;
    arp.table.head = entry;
    entry->pa = *pa;
    arp_send_request(pa);
    gettimeofday(&tv, NULL);
    timeout.tv_sec = tv.tv_sec + ARP_LOOKUP_TIMEOUT_SEC;
    timeout.tv_nsec = tv.tv_usec * 1000;
    do {
        ret = pthread_cond_timedwait(&entry->cond, &arp.mutex, &timeout);
        if (ret == ETIMEDOUT) {
            pthread_mutex_unlock(&arp.mutex);
            return -1;
        }
    } while (ret != 0);
    memcpy(ha, &entry->ha, sizeof(ethernet_addr_t));
    pthread_mutex_unlock(&arp.mutex);
    return 0;
}

int
arp_table_update (const ethernet_addr_t *ha, const ip_addr_t *pa) {
    struct arp_entry *entry;

    pthread_mutex_lock(&arp.mutex);
    for (entry = arp.table.head; entry; entry = entry->next) {
        if (entry->pa == *pa) {
			memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
            pthread_cond_broadcast(&entry->cond);
            pthread_mutex_unlock(&arp.mutex);
			return 0;
        }
    }
    entry = arp.table.pool;
    if (!entry) {
        pthread_mutex_unlock(&arp.mutex);
        return -1;
    }
    arp.table.pool = entry->next;
    entry->next = arp.table.head;
    arp.table.head = entry;
    entry->pa = *pa;
    memcpy(&entry->ha, ha, sizeof(ethernet_addr_t));
	pthread_mutex_unlock(&arp.mutex);
	return 0;
}

void
arp_recv (uint8_t *packet, size_t plen, ethernet_addr_t *src, ethernet_addr_t *dst) {
	struct arp_ethernet *message;

	(void)dst;
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
    switch (ntoh16(message->hdr.op)) {
        case ARP_OP_REQUEST:
            if (message->tpa == ip_get_addr(NULL)) {
                arp_send_reply(&message->sha, &message->spa, src);
            } else if (message->spa != message->tpa) {
                break;
            }
            arp_table_update(&message->sha, &message->spa);
            break;
        case ARP_OP_REPLY:
            if (message->tpa == ip_get_addr(NULL)) {
                arp_table_update(&message->sha, &message->spa);
            }
            break;
    }
}

static int
arp_send_request (const ip_addr_t *tpa) {
	struct arp_ethernet request;

	if (!tpa) {
		goto ERROR;
	}
	request.hdr.hrd = hton16(ARP_HRD_ETHERNET);
	request.hdr.pro = hton16(ETHERNET_TYPE_IP);
	request.hdr.hln = 6;
	request.hdr.pln = 4;
	request.hdr.op = hton16(ARP_OP_REQUEST);
    ethernet_get_addr(&request.sha);
    ip_get_addr(&request.spa);
	memset(&request.tha, 0, ETHERNET_ADDR_LEN);
    request.tpa = *tpa;
	if (ethernet_output(ETHERNET_TYPE_ARP, (uint8_t *)&request, sizeof(request), &ETHERNET_ADDR_BCAST) < 0) {
		goto ERROR;
	}
	return  0;

ERROR:
	return -1;
}

static int
arp_send_reply (const ethernet_addr_t *tha, const ip_addr_t *tpa, const ethernet_addr_t *dst) {
	struct arp_ethernet reply;

	if (!tha || !tpa) {
		goto ERROR;
	}
	reply.hdr.hrd = hton16(ARP_HRD_ETHERNET);
	reply.hdr.pro = hton16(ETHERNET_TYPE_IP);
	reply.hdr.hln = 6;
	reply.hdr.pln = 4;
	reply.hdr.op = hton16(ARP_OP_REPLY);
    ethernet_get_addr(&reply.sha);
    ip_get_addr(&reply.spa);
    reply.tha = *tha;
    reply.tpa = *tpa;
	if (ethernet_output(ETHERNET_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst) < 0) {
		goto ERROR;
	}
	return  0;

ERROR:
	return -1;
}
