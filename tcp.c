#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
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

static void
tcp_input (uint8_t *segment, size_t len, ip_addr_t *src, ip_addr_t *dst);

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

struct tcp_cb {
    uint8_t state;
    uint16_t port;
    uint32_t seq;
    uint32_t ack;
    struct {
        ip_addr_t addr;
        uint16_t port;
        uint32_t seq;
        uint32_t ack;
    } peer;
    uint8_t window[65536];
    uint16_t len;
    pthread_cond_t cond;
    struct tcp_cb *backlog;
    struct tcp_cb *parent;
    struct tcp_cb *next;
};

struct {
    struct {
        struct tcp_cb table[TCP_CB_TABLE_SIZE];
        struct tcp_cb *head;
        struct tcp_cb *pool;
        pthread_mutex_t mutex;
    } cb;
} tcp;

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
    return 0;
}

static void
tcp_send_flag (struct tcp_cb *cb, uint8_t flag) {
    struct tcp_hdr response;
    ip_addr_t self, peer;
    uint32_t pseudo = 0;

    memset(&response, 0, sizeof(response));
    response.src = hton16(cb->port);
    response.dst = hton16(cb->peer.port);
    response.seq = hton32(cb->seq);
    response.ack = hton32(cb->ack);
    response.off = (sizeof(struct tcp_hdr) >> 2) << 4;
    response.flg = flag;
    response.win = hton16(65535);
    response.sum = 0;
    response.urg = 0;
    ip_get_addr(&self);
    peer = hton32(cb->peer.addr);
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (peer >> 16) & 0xffff;
    pseudo += peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(sizeof(response));
    response.sum = cksum16((uint16_t *)&response, sizeof(response), pseudo);
    ip_send(IP_PROTOCOL_TCP, (uint8_t *)&response, sizeof(response), &peer);
    return;
}

static void
tcp_statemachine (struct tcp_hdr *hdr, size_t len, struct tcp_cb *cb) {
    size_t hlen;

    if (hdr->flg & TCP_FLG_RST) {
        return;
    }
    switch (cb->state) {
        case TCP_CB_STATE_CLOSED:
            break;
        case TCP_CB_STATE_LISTEN:
            if ((hdr->flg & 0x3f) == TCP_FLG_SYN) {
                cb->state = TCP_CB_STATE_SYN_RCVD;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->peer.ack = 0;
                cb->seq = 1024;
                cb->ack = cb->peer.seq + 1;
                tcp_send_flag(cb, TCP_FLG_SYN | TCP_FLG_ACK);
                cb->seq++;
            }
            break;
        case TCP_CB_STATE_SYN_SENT:
            break;
        case TCP_CB_STATE_SYN_RCVD:
            if ((hdr->flg & 0x3f) == TCP_FLG_ACK) {
                cb->state = TCP_CB_STATE_ESTABLISHED;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->peer.ack = ntoh32(hdr->ack);
                pthread_cond_signal(&cb->parent->cond);
            } else if ((hdr->flg & 0x3f) == TCP_FLG_SYN && ntoh32(hdr->seq) == cb->peer.seq) {
                cb->seq--;
                tcp_send_flag(cb, TCP_FLG_SYN | TCP_FLG_ACK);
                cb->seq++;
            }
            break;
        case TCP_CB_STATE_ESTABLISHED:
            hlen = (hdr->off >> 4) << 2;
            cb->peer.ack = ntoh32(hdr->ack);
            if (len - hlen > 0) {
                cb->peer.seq = ntoh32(hdr->seq);
                cb->ack = cb->peer.seq + (len - hlen);
                tcp_send_flag(cb, TCP_FLG_ACK);
                memcpy(cb->window, (uint8_t *)hdr + hlen, len - hlen);
                cb->len = len - hlen;
                pthread_cond_signal(&cb->cond);
            }
            if ((hdr->flg & 0x3f) & TCP_FLG_FIN) {
                cb->state = TCP_CB_STATE_CLOSE_WAIT;
                cb->peer.seq = ntoh32(hdr->seq);
                cb->ack = cb->peer.seq + 1;
                tcp_send_flag(cb, TCP_FLG_ACK);
                cb->state = TCP_CB_STATE_LAST_ACK;
                tcp_send_flag(cb, TCP_FLG_FIN | TCP_FLG_ACK);
            }
            break;
        case TCP_CB_STATE_FIN_WAIT1:
            break;
        case TCP_CB_STATE_FIN_WAIT2:
            break;
        case TCP_CB_STATE_CLOSING:
            break;
        case TCP_CB_STATE_TIME_WAIT:
            break;
        case TCP_CB_STATE_CLOSE_WAIT:
            break;
        case TCP_CB_STATE_LAST_ACK:
            if ((hdr->flg & 0x3f) & TCP_FLG_ACK) {
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

ssize_t
tcp_output (struct tcp_cb *cb, uint8_t *buf, size_t len) {
    uint8_t segment[1500];
    struct tcp_hdr *hdr;
    ip_addr_t self, peer;
    uint32_t pseudo = 0;

    memset(&segment, 0, sizeof(segment));
    hdr = (struct tcp_hdr *)segment;
    hdr->src = hton16(cb->port);
    hdr->dst = hton16(cb->peer.port);
    hdr->seq = hton32(cb->seq);
    hdr->ack = hton32(cb->ack);
    hdr->off = (sizeof(struct tcp_hdr) >> 2) << 4;
    hdr->flg = TCP_FLG_ACK | TCP_FLG_PSH;
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
    tcp_output(cb, buf, len);
    cb->seq += len;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}
