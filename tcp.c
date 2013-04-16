#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "tcp.h"
#include "ip.h"
#include "util.h"

#define TCP_CB_TABLE_SIZE 128

#define TCP_CB_STATE_CLOSED      0
#define TCP_CB_STATE_LISTEN      1
#define TCP_CB_STATE_SYN_SENT    2
#define TCP_CB_STATE_SYN_RCVD    3
#define TCP_CB_STATE_ESTABLISHED 4
#define TCP_CB_STATE_FIN_WAIT1   5
#define TCP_CB_STATE_FIN_WAIT2   6
#define TCP_CB_STATE_CLOSING     7
#define TCP_CB_STATE_TIME_WAIT   8
#define TCP_CB_STATE_CLOSE_WAIT  9
#define TCP_CB_STATE_LAST_ACK    10

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off;
    uint8_t  flg;
    uint16_t win;
    uint16_t sum;
    uint16_t urg;
};

struct tcp_txq_entry {
    struct tcp_hdr *segment;
    uint16_t len;
    struct timeval timestamp;
    struct tcp_txq_entry *next;
};

struct tcp_txq_head {
    struct tcp_txq_entry *head;
    struct tcp_txq_entry *tail;
};

struct tcp_cb {
    uint8_t state;
    uint16_t port;
    uint32_t seq;
    uint32_t ack;
    struct tcp_txq_head txq;
    struct {
        ip_addr_t addr;
        uint16_t port;
        uint32_t seq;
        uint32_t ack;
        struct timeval timestamp;
    } peer;
    uint8_t window[65536];
    uint16_t len;
    pthread_cond_t cond;
    struct tcp_cb *backlog;
    struct tcp_cb *parent;
    struct tcp_cb *next;
};

static void
tcp_input (uint8_t *segment, size_t len, ip_addr_t *src, ip_addr_t *dst);
static ssize_t
tcp_output (struct tcp_cb *cb, uint8_t *buf, size_t len, uint8_t flg);

struct {
    pthread_t thread;
    struct {
        struct tcp_cb table[TCP_CB_TABLE_SIZE];
        struct tcp_cb *head;
        struct tcp_cb *pool;
        pthread_mutex_t mutex;
    } cb;
} tcp;

static void *
tcp_timer_thread (void *arg) {
    struct timeval timestamp;
    struct tcp_cb *cb;
    struct tcp_txq_entry *txq, *prev;
    ip_addr_t peer;

    while (1) {
        gettimeofday(&timestamp, NULL);
        pthread_mutex_lock(&tcp.cb.mutex);
        for (cb = tcp.cb.head; cb; cb = cb->next) {
            if (cb->peer.ack == cb->seq) {
                continue;
            }
            prev = NULL;
            for (txq = cb->txq.head; txq; txq = txq->next) {
                if (txq->segment->seq > hton32(cb->peer.ack)) {
                    if (timestamp.tv_sec - txq->timestamp.tv_sec > 3) {
                        peer = hton32(cb->peer.addr);
                        ip_send(IP_PROTOCOL_TCP, (uint8_t *)txq->segment, txq->len, &peer);
                        txq->timestamp = timestamp;
                    }
                } else {
                    if (prev) {
                        prev->next = txq->next;
                        if (!prev->next) {
                            cb->txq.tail = prev;
                        }
                    } else {
                        cb->txq.head = cb->txq.tail = txq->next;
                    }
                }
                prev = txq;
            }
        }
        pthread_mutex_unlock(&tcp.cb.mutex);
        usleep(100000);
    }
    return NULL;
}

int
tcp_init (void) {
    int index;

    for (index = 0; index < TCP_CB_TABLE_SIZE - 1; index++) {
        tcp.cb.table[index].next = tcp.cb.table + (index + 1);
        pthread_cond_init(&tcp.cb.table[index].cond, NULL);
    }
    pthread_cond_init(&tcp.cb.table[index].cond, NULL);
    pthread_mutex_init(&tcp.cb.mutex, NULL);
    tcp.cb.pool = tcp.cb.table;
    if (ip_add_protocol(IP_PROTOCOL_TCP, tcp_input) == -1) {
        return -1;
    }
    if (pthread_create(&tcp.thread, NULL, tcp_timer_thread, NULL) == -1) {
        return -1;
    }
    return 0;
}



static void
tcp_statemachine (struct tcp_hdr *hdr, size_t len, struct tcp_cb *cb) {
    size_t hlen;

    if (hdr->flg & TCP_FLG_RST) {
        return;
    }
    fprintf(stderr, "state: %u\n", cb->state);
    switch (cb->state) {
        case TCP_CB_STATE_CLOSED:
            tcp_output(cb, NULL, 0, TCP_FLG_RST);
            break;
        case TCP_CB_STATE_LISTEN:
            if ((hdr->flg & 0x3f) == TCP_FLG_SYN) {
                cb->state = TCP_CB_STATE_SYN_RCVD;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->peer.ack = 0;
                cb->seq = 1024;
                cb->ack = cb->peer.seq + 1;
                tcp_output(cb, NULL, 0, TCP_FLG_SYN | TCP_FLG_ACK);
                cb->seq++;
            }
            break;
        case TCP_CB_STATE_SYN_SENT:
            if ((hdr->flg & 0x3f) & TCP_FLG_SYN) {
                if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
                    if (ntoh32(hdr->ack) != cb->seq) {
                        return;
                    }
                    cb->state = TCP_CB_STATE_ESTABLISHED;
                    cb->peer.seq = ntoh32(hdr->seq);
                    cb->peer.ack = ntoh32(hdr->ack);
                    cb->ack = cb->peer.seq + 1;
                    tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                    pthread_cond_signal(&cb->cond);
                } else {
                    cb->state = TCP_CB_STATE_SYN_RCVD;
                    cb->peer.seq = ntoh32(hdr->seq);
                    cb->peer.ack = 0;
                    cb->seq = 1024;
                    cb->ack = cb->peer.seq + 1;
                    tcp_output(cb, NULL, 0, TCP_FLG_SYN | TCP_FLG_ACK);
                    cb->seq++;
                }
            }
            break;
        case TCP_CB_STATE_SYN_RCVD:
            if ((hdr->flg & 0x3f) == TCP_FLG_ACK) {
                if (ntoh32(hdr->ack) != cb->seq) {
                    return;
                }
                cb->state = TCP_CB_STATE_ESTABLISHED;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->peer.ack = ntoh32(hdr->ack);
                pthread_cond_signal(&cb->parent->cond);
            } else if ((hdr->flg & 0x3f) == TCP_FLG_SYN && ntoh32(hdr->seq) == cb->peer.seq) {
                cb->seq--;
                tcp_output(cb, NULL, 0, TCP_FLG_SYN | TCP_FLG_ACK);
                cb->seq++;
            }
            break;
        case TCP_CB_STATE_ESTABLISHED:
            if (ntoh32(hdr->ack) != cb->seq) {
fprintf(stderr, ">>1\n");
                return;
            }
            hlen = (hdr->off >> 4) << 2;
            cb->peer.ack = ntoh32(hdr->ack);
            if (len - hlen > 0) {
fprintf(stderr, ">>2\n");
                cb->peer.seq = ntoh32(hdr->seq);
                cb->ack = cb->peer.seq + (len - hlen);
                tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                memcpy(cb->window + cb->len, (uint8_t *)hdr + hlen, len - hlen);
                cb->len += len - hlen;
                pthread_cond_signal(&cb->cond);
            }
            if ((hdr->flg & 0x3f) & TCP_FLG_FIN) {
                cb->state = TCP_CB_STATE_CLOSE_WAIT;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->ack = cb->peer.seq + 1;
                tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                cb->state = TCP_CB_STATE_LAST_ACK;
                tcp_output(cb, NULL, 0, TCP_FLG_FIN | TCP_FLG_ACK);
            }
            break;
        case TCP_CB_STATE_FIN_WAIT1:
            if ((hdr->flg & 0x3f) & TCP_FLG_FIN) {
                if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
                    cb->state = TCP_CB_STATE_TIME_WAIT;
                    cb->peer.seq = ntoh32(hdr->seq);
                    cb->ack = cb->peer.seq + 1;
                    tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                    pthread_cond_signal(&cb->cond);
                } else {
                    cb->state = TCP_CB_STATE_CLOSING;
                    cb->peer.seq = ntoh32(hdr->seq);
                    cb->ack = cb->peer.seq + 1;
                    tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                }
            } else if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
                if (ntoh32(hdr->ack) != cb->seq) {
                    return;
                }
                cb->state = TCP_CB_STATE_FIN_WAIT2;
                cb->peer.seq = ntoh32(hdr->seq);
            }
            break;
        case TCP_CB_STATE_FIN_WAIT2:
            if ((hdr->flg & 0x3f) & TCP_FLG_FIN) {
                if (ntoh32(hdr->ack) != cb->seq) {
                    return;
                }
                cb->state = TCP_CB_STATE_TIME_WAIT;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->ack = cb->peer.seq + 1;
                tcp_output(cb, NULL, 0, TCP_FLG_ACK);
                pthread_cond_signal(&cb->cond);
            }
            break;
        case TCP_CB_STATE_CLOSING:
            if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
                if (ntoh32(hdr->ack) != cb->seq) {
                    return;
                }
                cb->state = TCP_CB_STATE_TIME_WAIT;
                cb->len = 0;
                pthread_cond_signal(&cb->cond);
            }
            break;
        case TCP_CB_STATE_TIME_WAIT:
            // none
            break;
        case TCP_CB_STATE_CLOSE_WAIT:
            // none
            break;
        case TCP_CB_STATE_LAST_ACK:
            if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
                if (ntoh32(hdr->ack) != cb->seq) {
                    return;
                }
                cb->state = TCP_CB_STATE_CLOSED;
                cb->len = 0;
                pthread_cond_signal(&cb->cond);
            }
            break;
    }
}

static void
tcp_input (uint8_t *segment, size_t len, ip_addr_t *src, ip_addr_t *dst) {
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;
    struct tcp_cb *cb, *backlog;

    if (len < sizeof(struct tcp_hdr)) {
        return;
    }
    hdr = (struct tcp_hdr *)segment;
    pseudo += *src >> 16;
    pseudo += *src & 0xffff;
    pseudo += *dst >> 16;
    pseudo += *dst & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(len);
    if (cksum16((uint16_t *)hdr, len, pseudo) != 0) {
        return;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    for (cb = tcp.cb.head; cb; cb = cb->next) {
        if (cb->port == ntoh16(hdr->dst)) {
            if (cb->state == TCP_CB_STATE_LISTEN) {
                for (backlog = cb->backlog; backlog; backlog = backlog->next) {
                    if (backlog->peer.addr == ntoh32(*src) && backlog->peer.port == ntoh16(hdr->src)) {
                        break;
                    }
                }
                if (!backlog) {
                    if ((hdr->flg & 0x3f) == TCP_FLG_SYN) {
                        backlog = tcp.cb.pool;
                    }
                    if (!backlog) {
                        pthread_mutex_unlock(&tcp.cb.mutex);
                        return;
                    }
                    tcp.cb.pool = backlog->next;
                    backlog->next = cb->backlog;
                    cb->backlog = backlog;
                    backlog->state = cb->state;
                    backlog->port = cb->port;
                    backlog->peer.addr = ntoh32(*src);
                    backlog->peer.port = ntoh16(hdr->src);
                    backlog->parent = cb;
                }
                cb = backlog;
            }
            if (cb->peer.addr == ntoh32(*src) && cb->peer.port == ntoh16(hdr->src)) {
                tcp_statemachine(hdr, len, cb);
                pthread_mutex_unlock(&tcp.cb.mutex);
                return;
            }
        }
    }
    pthread_mutex_unlock(&tcp.cb.mutex);
    fprintf(stderr, "%u -> %u\n", ntoh16(hdr->src), ntoh16(hdr->dst));
    return;
}

static int
tcp_txq_add (struct tcp_cb *cb, struct tcp_hdr *hdr, size_t len) {
    struct tcp_txq_entry *txq;

    txq = malloc(sizeof(struct tcp_txq_entry));
    if (!txq) {
        return -1;
    }
    txq->segment = malloc(len);
    if (!txq->segment) {
        free(txq);
        return -1;
    }
    memcpy(txq->segment, hdr, len);
    txq->len = len;
    gettimeofday(&txq->timestamp, NULL);
    txq->next = NULL;
    if (cb->txq.head == NULL) {
        cb->txq.head = cb->txq.tail = txq;
    } else {
        cb->txq.tail->next = txq;
    }
    return 0;
}

static ssize_t
tcp_output (struct tcp_cb *cb, uint8_t *buf, size_t len, uint8_t flg) {
    uint8_t segment[1500];
    struct tcp_hdr *hdr;
    ip_addr_t self, peer;
    uint32_t pseudo = 0;

    memset(&segment, 0, sizeof(segment));
    hdr = (struct tcp_hdr *)segment;
    hdr->src = hton16(cb->port);
    hdr->dst = hton16(cb->peer.port);
    hdr->seq = hton32(cb->seq);
    hdr->ack = (flg & TCP_FLG_ACK) ? hton32(cb->ack) : 0;
    hdr->off = (sizeof(struct tcp_hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->win = hton16(65535);
    hdr->sum = 0;
    hdr->urg = 0;
    memcpy(hdr + 1, buf, len);
    ip_get_addr(&self);
    peer = hton32(cb->peer.addr);
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (peer >> 16) & 0xffff;
    pseudo += peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(sizeof(struct tcp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct tcp_hdr) + len, pseudo);
    ip_send(IP_PROTOCOL_TCP, (uint8_t *)hdr, sizeof(struct tcp_hdr) + len, &peer);
    tcp_txq_add(cb, hdr, sizeof(struct tcp_hdr) + len);
    return len;
}

int
tcp_api_open (void) {
    struct tcp_cb *cb;

    pthread_mutex_lock(&tcp.cb.mutex);
    cb = tcp.cb.pool;
    if (!cb) {
        return -1;
    }
    tcp.cb.pool = cb->next;
    cb->next = tcp.cb.head;
    tcp.cb.head = cb;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return ((caddr_t)cb - (caddr_t)tcp.cb.table) / sizeof(struct tcp_cb);
}

int
tcp_api_close (int soc) {
    struct tcp_cb *cb, *prev = NULL;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    for (cb = tcp.cb.head; cb; cb = cb->next) {
        if (cb == tcp.cb.table + soc) {
            cb->port = 0;
            cb->state = TCP_CB_STATE_CLOSED;
            if (prev) {
                prev->next = cb->next;
            } else {
                tcp.cb.head = cb->next;
            }
            cb->next = tcp.cb.pool;
            tcp.cb.pool = cb;
            pthread_mutex_unlock(&tcp.cb.mutex);
            return 0;
        }
        prev = cb;
    }
    pthread_mutex_unlock(&tcp.cb.mutex);
    return -1;
}

int
tcp_api_connect (int soc, ip_addr_t *addr, uint16_t port) {
    struct tcp_cb *cb;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    cb->port = 40381;
    cb->state = TCP_CB_STATE_SYN_SENT;
    cb->peer.addr = ntoh32(*addr);
    cb->peer.port = port;
    cb->peer.seq = 0;
    cb->peer.ack = 0;
    cb->seq = 10000;
    cb->ack = 0;
    tcp_output(cb, NULL, 0, TCP_FLG_SYN);
    cb->seq++;
    while (cb->state == TCP_CB_STATE_SYN_SENT) {
        pthread_cond_wait(&tcp.cb.table[soc].cond, &tcp.cb.mutex);
    }
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_bind (int soc, uint16_t port) {
    struct tcp_cb *cb;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    for (cb = tcp.cb.head; cb; cb = cb->next) {
        if (cb->port == port) {
            pthread_mutex_unlock(&tcp.cb.mutex);
            return -1;
        }
    }
    tcp.cb.table[soc].port = port;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_listen (int soc) {
    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    tcp.cb.table[soc].state = TCP_CB_STATE_LISTEN;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_accept (int soc) {
    struct tcp_cb *backlog;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    if (tcp.cb.table[soc].state != TCP_CB_STATE_LISTEN) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    while (!(backlog = tcp.cb.table[soc].backlog)) {
        pthread_cond_wait(&tcp.cb.table[soc].cond, &tcp.cb.mutex);
    }
    tcp.cb.table[soc].backlog = backlog->next;
    backlog->next = tcp.cb.head;
    tcp.cb.head = backlog;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return ((caddr_t)backlog - (caddr_t)tcp.cb.table) / sizeof(struct tcp_cb);
}

ssize_t
tcp_api_recv (int soc, uint8_t *buf, size_t size) {
    struct tcp_cb *cb;
    ssize_t len;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (cb->len == 0) {
        if (cb->state != TCP_CB_STATE_ESTABLISHED && cb->state != TCP_CB_STATE_FIN_WAIT1) {
            return 0;
        }
        pthread_cond_wait(&cb->cond, &tcp.cb.mutex);
    }
    len = (size > cb->len) ? cb->len : size;
    memcpy(buf, cb->window, len);
    memmove(cb->window, cb->window + len, cb->len - len);
    cb->len -= len;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return len;
}

ssize_t
tcp_api_send (int soc, uint8_t *buf, size_t len) {
    struct tcp_cb *cb;

    if (soc < 0 || soc >= TCP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (cb->state != TCP_CB_STATE_ESTABLISHED && cb->state != TCP_CB_STATE_CLOSE_WAIT) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    tcp_output(cb, buf, len, TCP_FLG_ACK | TCP_FLG_PSH);
    cb->seq += len;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}
