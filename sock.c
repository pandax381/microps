#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

#include "sock.h"

static struct sock socks[128];

int
sockaddr_pton(const char *p, struct sockaddr *n, size_t size)
{
    struct ip_endpoint ep;

    if (ip_endpoint_pton(p, &ep) == 0) {
        if (size < sizeof(struct sockaddr_in)) {
            return -1;
        }
        ((struct sockaddr_in *)n)->sin_family = AF_INET;
        ((struct sockaddr_in *)n)->sin_port = ep.port;
        ((struct sockaddr_in *)n)->sin_addr = ep.addr;
        return 0;
    }
    return -1;
}

char *
sockaddr_ntop(const struct sockaddr *n, char *p, size_t size)
{
    struct ip_endpoint ep;

    switch (n->sa_family) {
    case AF_INET:
        if (size < IP_ENDPOINT_STR_LEN) {
            return NULL;
        }
        ep.port = ((struct sockaddr_in *)n)->sin_port;
        ep.addr = ((struct sockaddr_in *)n)->sin_addr;
        return ip_endpoint_ntop(&ep, p, size);
    }
    return NULL;
}

static struct sock *
sock_alloc(void)
{
    struct sock *entry;

    for (entry = socks; entry < tailof(socks); entry++) {
        if (!entry->used) {
            entry->used = 1;
            return entry;
        }
    }
    return NULL;
}

static int
sock_free(struct sock *s)
{
    memset(s, 0, sizeof(*s));
    return 0;
}

static struct sock *
sock_get(int id)
{
    if (id < 0 || id >= (int)countof(socks)) {
        /* out of range */
        return NULL;
    }
    return &socks[id];
}

int
sock_open(int domain, int type, int protocol)
{
    struct sock *s;

    if (domain != AF_INET) {
        return -1;
    }
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        return -1;
    }
    if (protocol != 0) { 
        return -1;
    }
    s = sock_alloc();
    if (!s) {
        return -1;
    }
    s->family = domain;
    s->type = type;
    switch (s->type) {
    case SOCK_STREAM:
        s->desc = tcp_open();
        break;
    case SOCK_DGRAM:
        s->desc = udp_open();
        break;
    }
    if (s->desc == -1) {
        return -1;
    }
    return indexof(socks, s);
}

int
sock_close(int id)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    switch (s->type) {
    case SOCK_STREAM:
        tcp_close(s->desc);
        break;    
    case SOCK_DGRAM:
        udp_close(s->desc);
        break;
    default:
        return -1;
    }
    return sock_free(s);
}

ssize_t
sock_recvfrom(int id, void *buf, size_t n, struct sockaddr *addr, int *addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;
    int ret;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_DGRAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        ret = udp_recvfrom(s->desc, (uint8_t *)buf, n, &ep);
        if (ret != -1) {
            ((struct sockaddr_in *)addr)->sin_addr = ep.addr;
            ((struct sockaddr_in *)addr)->sin_port = ep.port;
        }
        return ret;
    }
    return -1;
}

ssize_t
sock_sendto(int id, const void *buf, size_t n, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_DGRAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
        ep.port = ((struct sockaddr_in *)addr)->sin_port;
        return udp_sendto(s->desc, (uint8_t *)buf, n, &ep);
    }
    return -1;
}

int
sock_bind(int id, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    switch (s->type) {
    case SOCK_STREAM:
        switch (s->family) {
        case AF_INET:
            ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
            ep.port = ((struct sockaddr_in *)addr)->sin_port;
            return tcp_bind(s->desc, &ep);
        }
        return -1;
    case SOCK_DGRAM:
        switch (s->family) {
        case AF_INET:
            ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
            ep.port = ((struct sockaddr_in *)addr)->sin_port;
            return udp_bind(s->desc, &ep);
        }
        return -1;
    }
    return -1;
}

int
sock_listen(int id, int backlog)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        return tcp_listen(s->desc, backlog);
    }
    return -1;
}

int
sock_accept(int id, struct sockaddr *addr, int *addrlen)
{
    struct sock *s, *new_s;
    struct ip_endpoint ep;
    int ret;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        ret = tcp_accept(s->desc, &ep);
        if (ret == -1) {
            return -1;
        }
        ((struct sockaddr_in *)addr)->sin_family = s->family;
        ((struct sockaddr_in *)addr)->sin_addr = ep.addr;
        ((struct sockaddr_in *)addr)->sin_port = ep.port;
        new_s = sock_alloc();
        new_s->family = s->family;
        new_s->type = s->type;
        new_s->desc = ret;
        return indexof(socks, new_s);
    }
    return -1;
}

int
sock_connect(int id, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
        ep.port = ((struct sockaddr_in *)addr)->sin_port;
        return tcp_connect(s->desc, &ep);
    }
    return -1;
}

ssize_t
sock_recv(int id, void *buf, size_t n)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        return tcp_receive(s->desc, (uint8_t *)buf, n);
    }
    return -1;
}

ssize_t
sock_send(int id, const void *buf, size_t n)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        return tcp_send(s->desc, (uint8_t *)buf, n);
    }
    return -1;
}
