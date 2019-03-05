#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "util.h"
#include "tcp.h"

#define TCP_CB_TABLE_SIZE 128
#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

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

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y))

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
    uint8_t used;
    uint8_t state;
    struct netif *iface;
    uint16_t port;
    struct {
        ip_addr_t addr;
        uint16_t port;
    } peer;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
        uint16_t wnd;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t up;
        uint16_t wnd;
    } rcv;
    uint32_t irs;
    struct tcp_txq_head txq;
    uint8_t window[65535];
    struct tcp_cb *parent;
    struct queue_head backlog;
    pthread_cond_t cond;
};

#define TCP_CB_LISTENER_SIZE 128

struct {
    pthread_t thread;
    struct {
        struct tcp_cb table[TCP_CB_TABLE_SIZE];
        pthread_mutex_t mutex;
    } cb;
} tcp;

#define TCP_CB_TABLE_FOREACH(x) \
    for (x = tcp.cb.table; x != tcp.cb.table + TCP_CB_TABLE_SIZE; x++)
#define TCP_CB_TABLE_OFFSET(x) \
    (((caddr_t)x - (caddr_t)tcp.cb.table) / sizeof(*x))
#define TCP_CB_STATE_RX_ISREADY(x) \
    (x->state == TCP_CB_STATE_ESTABLISHED || \
    x->state == TCP_CB_STATE_FIN_WAIT1 || \
    x->state == TCP_CB_STATE_FIN_WAIT2)
#define TCP_CB_STATE_TX_ISREADY(x) \
    (x->state == TCP_CB_STATE_ESTABLISHED || \
    x->state == TCP_CB_STATE_CLOSE_WAIT)
#define TCP_SOCKET_ISINVALID(x) \
    (x < 0 || x >= TCP_CB_TABLE_SIZE)

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
tcp_tx (struct tcp_cb *cb, uint32_t seq, uint32_t ack, uint8_t flg, uint8_t *buf, size_t len) {
    uint8_t segment[1500];
    struct tcp_hdr *hdr;
    ip_addr_t self, peer;
    uint32_t pseudo = 0;

    memset(&segment, 0, sizeof(segment));
    hdr = (struct tcp_hdr *)segment;
    hdr->src = cb->port;
    hdr->dst = cb->peer.port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(struct tcp_hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->win = hton16(cb->rcv.wnd);
    hdr->sum = 0;
    hdr->urg = 0;
    memcpy(hdr + 1, buf, len);
    self = ((struct netif_ip *)cb->iface)->unicast;
    peer = cb->peer.addr;
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (peer >> 16) & 0xffff;
    pseudo += peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(sizeof(struct tcp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct tcp_hdr) + len, pseudo);
    ip_tx(cb->iface, IP_PROTOCOL_TCP, (uint8_t *)hdr, sizeof(struct tcp_hdr) + len, &peer);
    tcp_txq_add(cb, hdr, sizeof(struct tcp_hdr) + len);
    return len;
}

static void *
tcp_timer_thread (void *arg) {
    struct timeval timestamp;
    struct tcp_cb *cb;
    struct tcp_txq_entry *txq, *prev;
    ip_addr_t peer;

    while (1) {
        gettimeofday(&timestamp, NULL);
        pthread_mutex_lock(&tcp.cb.mutex);
        TCP_CB_TABLE_FOREACH (cb) {
            if (cb->snd.una == cb->snd.nxt) {
                continue;
            }
            prev = NULL;
            for (txq = cb->txq.head; txq; txq = txq->next) {
                if (txq->segment->seq >= hton32(cb->snd.una)) {
                    if (timestamp.tv_sec - txq->timestamp.tv_sec > 3) {
                        peer = cb->peer.addr;
                        ip_tx(cb->iface, IP_PROTOCOL_TCP, (uint8_t *)txq->segment, txq->len, &peer);
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

static void
tcp_incoming_event (struct tcp_cb *cb, struct tcp_hdr *hdr, size_t len) {
    uint32_t seq, ack;
    size_t hlen, plen;

    hlen = ((hdr->off >> 4) << 2);
    plen = len - hlen;
    switch (cb->state) {
        case TCP_CB_STATE_CLOSED:
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                return;
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                seq = ntoh32(hdr->ack);
                ack = 0;
            } else {
                seq = 0;
                ack = ntoh32(hdr->seq);
                if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
                    ack++;
                }
                if (plen) {
                    ack += plen;
                }
                if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
                    ack++;
                }
            }
            tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
            return;
        case TCP_CB_STATE_LISTEN:
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                return;
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                seq = ntoh32(hdr->ack);
                ack = 0;
                tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
                return;
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
                cb->rcv.nxt = ntoh32(hdr->seq) + 1;
                cb->irs = ntoh32(hdr->seq);
                cb->iss = (uint32_t)random();
                seq = cb->iss;
                ack = cb->rcv.nxt;
                tcp_tx(cb, seq, ack, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                cb->snd.nxt = cb->iss + 1;
                cb->snd.una = cb->iss;
                cb->state = TCP_CB_STATE_SYN_RCVD;
            }
            return;
        case TCP_CB_STATE_SYN_SENT:
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                if (ntoh32(hdr->ack) <= cb->iss || ntoh32(hdr->ack) > cb->snd.nxt) {
                    if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                        seq = ntoh32(hdr->ack);
                        ack = 0;
                        tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
                    }
                    return;
                }
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                    // TCB close
                }
                return;
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
                cb->rcv.nxt = ntoh32(hdr->seq) + 1;
                cb->irs = ntoh32(hdr->seq);
                if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                    cb->snd.una = ntoh32(hdr->ack);
                    // delete TX queue
                    if (cb->snd.una > cb->iss) {
                        cb->state = TCP_CB_STATE_ESTABLISHED;
                        seq = cb->snd.nxt;
                        ack = cb->rcv.nxt;
                        tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
                        pthread_cond_signal(&cb->cond);
                    }
                    return;
                }
                seq = cb->iss;
                ack = cb->rcv.nxt;
                tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
            }
            return;
        default:
            break;
    }
    if (ntoh32(hdr->seq) != cb->rcv.nxt) {
        // TODO
        return;
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST | TCP_FLG_SYN)) {
        // TODO
        return;
    }
    if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
        // TODO
        return;
    }
    switch (cb->state) {
        case TCP_CB_STATE_SYN_RCVD:
            if (cb->snd.una <= ntoh32(hdr->ack) && ntoh32(hdr->ack) <= cb->snd.nxt) {
                cb->state = TCP_CB_STATE_ESTABLISHED;
                queue_push(&cb->parent->backlog, cb, sizeof(*cb));
                pthread_cond_signal(&cb->parent->cond);
                break;
            }
            break;
        case TCP_CB_STATE_ESTABLISHED:
        case TCP_CB_STATE_FIN_WAIT1:
        case TCP_CB_STATE_FIN_WAIT2:
        case TCP_CB_STATE_CLOSE_WAIT:
        case TCP_CB_STATE_CLOSING:
            if (cb->snd.una < ntoh32(hdr->ack) && ntoh32(hdr->ack) <= cb->snd.nxt) {
                cb->snd.una = ntoh32(hdr->ack);
            } else if (ntoh32(hdr->ack) > cb->snd.nxt) {
                tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
                return;
            }
            // send window update
            if (cb->state == TCP_CB_STATE_FIN_WAIT1) {
                if (ntoh32(hdr->ack) == cb->snd.nxt) {
                    cb->state = TCP_CB_STATE_FIN_WAIT2;
                }
            } else if (cb->state == TCP_CB_STATE_CLOSING) {
                if (ntoh32(hdr->ack) == cb->snd.nxt) {
                    cb->state = TCP_CB_STATE_TIME_WAIT;
                    pthread_cond_signal(&cb->cond);
                }
                return;
            }
            break;
        case TCP_CB_STATE_LAST_ACK:
            cb->state = TCP_CB_STATE_CLOSED;
            pthread_cond_signal(&cb->cond);
            return;
    }
    if (plen) {
        switch (cb->state) {
            case TCP_CB_STATE_ESTABLISHED:
            case TCP_CB_STATE_FIN_WAIT1:
            case TCP_CB_STATE_FIN_WAIT2:
                memcpy(cb->window + (sizeof(cb->window) - cb->rcv.wnd), (uint8_t *)hdr + hlen, plen);
                cb->rcv.nxt = ntoh32(hdr->seq) + plen;
                cb->rcv.wnd -= plen;
                seq = cb->snd.nxt;
                ack = cb->rcv.nxt;
                tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
                pthread_cond_signal(&cb->cond);
                break;
            default:
                break;
        }
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        cb->rcv.nxt++;
        tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        switch (cb->state) {
            case TCP_CB_STATE_SYN_RCVD:
            case TCP_CB_STATE_ESTABLISHED:
                cb->state = TCP_CB_STATE_CLOSE_WAIT;
                pthread_cond_signal(&cb->cond);
                break;
            case TCP_CB_STATE_FIN_WAIT1:
                cb->state = TCP_CB_STATE_FIN_WAIT2;
                break;
            case TCP_CB_STATE_FIN_WAIT2:
                cb->state = TCP_CB_STATE_TIME_WAIT;
                pthread_cond_signal(&cb->cond);
                break;
            default:
                break;
        }
        return;
    }
    return;
}

static void
tcp_rx (uint8_t *segment, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *iface) {
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;
    struct tcp_cb *cb, *fcb = NULL, *lcb = NULL;

    if (*dst != ((struct netif_ip *)iface)->unicast) {
        return;
    }
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
        fprintf(stderr, "tcp checksum error\n");
        return;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    TCP_CB_TABLE_FOREACH (cb) {
        if (!cb->used) {
            if (!fcb) {
                fcb = cb;
            }
        }
        else if ((!cb->iface || cb->iface == iface) && cb->port == hdr->dst) {
            if (cb->peer.addr == *src && cb->peer.port == hdr->src) {
                break;
            }
            if (cb->state == TCP_CB_STATE_LISTEN && !lcb) {
                lcb = cb;
            }
        }
    }
    if (TCP_CB_TABLE_OFFSET(cb) == TCP_CB_TABLE_SIZE) {
        if (!lcb || !fcb || !TCP_FLG_IS(hdr->flg, TCP_FLG_SYN)) {
            // send RST
            pthread_mutex_unlock(&tcp.cb.mutex);
            return;
        }
        cb = fcb;
        cb->used = 1;
        cb->state = lcb->state;
        cb->iface = iface;
        cb->port = lcb->port;
        cb->peer.addr = *src;
        cb->peer.port = hdr->src;
        cb->rcv.wnd = sizeof(cb->window);
        cb->parent = lcb;
    }
    tcp_incoming_event(cb, hdr, len);
    pthread_mutex_unlock(&tcp.cb.mutex);
    return;
}

int
tcp_api_open (void) {
    struct tcp_cb *cb;

    pthread_mutex_lock(&tcp.cb.mutex);
    TCP_CB_TABLE_FOREACH (cb) {
        if (!cb->used) {
            cb->used = 1;
            pthread_mutex_unlock(&tcp.cb.mutex);
            return TCP_CB_TABLE_OFFSET(cb);
        }
    }
    pthread_mutex_unlock(&tcp.cb.mutex);
    return -1;
}

int
tcp_api_close (int soc) {
    struct tcp_cb *cb;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    switch (cb->state) {
        case TCP_CB_STATE_SYN_RCVD:
        case TCP_CB_STATE_ESTABLISHED:
            tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_FIN | TCP_FLG_ACK, NULL, 0);
            cb->state = TCP_CB_STATE_FIN_WAIT1;
            cb->snd.nxt++;
            pthread_cond_wait(&cb->cond, &tcp.cb.mutex);
            break;
        case TCP_CB_STATE_CLOSE_WAIT:
            tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_FIN | TCP_FLG_ACK, NULL, 0);
            cb->state = TCP_CB_STATE_LAST_ACK;
            cb->snd.nxt++;
            pthread_cond_wait(&cb->cond, &tcp.cb.mutex);
            break;
        default:
            break;
    }
    cb->used = 0;
    cb->state = TCP_CB_STATE_CLOSED;
    cb->port = 0;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_connect (int soc, ip_addr_t *addr, uint16_t port) {
    struct tcp_cb *cb, *tmp;
    uint32_t p;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used || cb->state != TCP_CB_STATE_CLOSED) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    if (!cb->port) {
        int offset = time(NULL) % 1024;
        for (p = TCP_SOURCE_PORT_MIN + offset; p <= TCP_SOURCE_PORT_MAX; p++) {
            TCP_CB_TABLE_FOREACH (tmp) {
                if (tmp->used && tmp->port == hton16((uint16_t)p)) {
                    break;
                }
            }
            if (TCP_CB_TABLE_OFFSET(tmp) == TCP_CB_TABLE_SIZE) {
                cb->port = hton16((uint16_t)p);
                break;
            }
        }
        if (!cb->port) {
            pthread_mutex_unlock(&tcp.cb.mutex);
            return -1;
        }
    }
    cb->peer.addr = *addr;
    cb->peer.port = port;
    cb->rcv.wnd = sizeof(cb->window);
    cb->iss = (uint32_t)random();
    tcp_tx(cb, cb->iss, 0, TCP_FLG_SYN, NULL, 0);
    cb->snd.nxt = cb->iss + 1;
    cb->state = TCP_CB_STATE_SYN_SENT;
    while (cb->state == TCP_CB_STATE_SYN_SENT) {
        pthread_cond_wait(&tcp.cb.table[soc].cond, &tcp.cb.mutex);
    }
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_bind (int soc, uint16_t port) {
    struct tcp_cb *cb;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    TCP_CB_TABLE_FOREACH (cb) {
        if (cb->port == port) {
            pthread_mutex_unlock(&tcp.cb.mutex);
            return -1;
        }
    }
    cb = &tcp.cb.table[soc];
    if (!cb->used || cb->state != TCP_CB_STATE_CLOSED) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    cb->port = port;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_listen (int soc) {
    struct tcp_cb *cb;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used || cb->state != TCP_CB_STATE_CLOSED || !cb->port) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    cb->state = TCP_CB_STATE_LISTEN;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_api_accept (int soc) {
    struct tcp_cb *cb, *backlog;
    struct queue_entry *entry;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    if (cb->state != TCP_CB_STATE_LISTEN) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    while ((entry = queue_pop(&cb->backlog)) == NULL) {
        pthread_cond_wait(&cb->cond, &tcp.cb.mutex);
    }
    backlog = entry->data;
    free(entry);
    pthread_mutex_unlock(&tcp.cb.mutex);
    return TCP_CB_TABLE_OFFSET(backlog);
}

ssize_t
tcp_api_recv (int soc, uint8_t *buf, size_t size) {
    struct tcp_cb *cb;
    size_t total, len;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    while (!(total = sizeof(cb->window) - cb->rcv.wnd)) {
        if (!TCP_CB_STATE_RX_ISREADY(cb)) {
            pthread_mutex_unlock(&tcp.cb.mutex);
            return 0;
        }
        pthread_cond_wait(&cb->cond, &tcp.cb.mutex);
    }
    len = size < total ? size : total;
    memcpy(buf, cb->window, len);
    memmove(cb->window, cb->window + len, total - len);
    cb->rcv.wnd += len;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return len;
}

ssize_t
tcp_api_send (int soc, uint8_t *buf, size_t len) {
    struct tcp_cb *cb;

    if (TCP_SOCKET_ISINVALID(soc)) {
        return -1;
    }
    pthread_mutex_lock(&tcp.cb.mutex);
    cb = &tcp.cb.table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    if (!TCP_CB_STATE_TX_ISREADY(cb)) {
        pthread_mutex_unlock(&tcp.cb.mutex);
        return -1;
    }
    tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_ACK | TCP_FLG_PSH, buf, len);
    cb->snd.nxt += len;
    pthread_mutex_unlock(&tcp.cb.mutex);
    return 0;
}

int
tcp_init (void) {
    struct tcp_cb *cb;

    TCP_CB_TABLE_FOREACH (cb) {
        pthread_cond_init(&cb->cond, NULL);
    }
    pthread_mutex_init(&tcp.cb.mutex, NULL);
    if (ip_add_protocol(IP_PROTOCOL_TCP, tcp_rx) == -1) {
        return -1;
    }
    if (pthread_create(&tcp.thread, NULL, tcp_timer_thread, NULL) == -1) {
        return -1;
    }
    return 0;
}
