#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "sock.h"

struct sock {
    int used;
    int family;
    int type;
    int desc;
};

static lock_t lock = LOCK_INITIALIZER;
static struct sock socks[32];

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
sock_get(int desc)
{
    if (desc < 0 || desc >= (int)countof(socks)) {
        /* out of range */
        return NULL;
    }
    return &socks[desc];
}

int
sock_open(int domain, int type, int protocol)
{
    struct sock *s;
    int desc;

    if (domain != AF_INET) {
        return -1;
    }
    switch (type) {
    case SOCK_STREAM:
        if (protocol != 0 && protocol != IPPROTO_TCP) {
            return -1;
        }
        break;
    case SOCK_DGRAM:
        if (protocol != 0 && protocol != IPPROTO_UDP) {
            return -1;
        }
        break;
    default:
        return -1;
    }
    lock_acquire(&lock);
    s = sock_alloc();
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    s->family = domain;
    s->type = type;
    switch (s->type) {
    case SOCK_STREAM:
        s->desc = tcp_cmd_socket();
        break;
    case SOCK_DGRAM:
        s->desc = udp_cmd_open();
        break;
    }
    if (s->desc == -1) {
        lock_release(&lock);
        return -1;
    }
    desc = indexof(socks, s);
    lock_release(&lock);
    return desc;
}

int
sock_close(int desc)
{
    struct sock *s;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        return -1;
    }
    switch (s->family) {
    case AF_INET:
        switch (s->type) {
        case SOCK_STREAM:
            tcp_cmd_close(s->desc);
            break;
        case SOCK_DGRAM:
            udp_cmd_close(s->desc);
            break;
        default:
            warnf("unknown type %d", s->type);
            break;
        }
        break;
    default:
        errorf("unknown family %d", s->family);
        break;
    }
    sock_free(s);
    lock_release(&lock);
    return 0;
}

ssize_t
sock_recvfrom(int desc, void *buf, size_t n, struct sockaddr *addr, int *addrlen)
{
    struct sock *s, sock;
    ip_endp_t remote;
    int ret;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_DGRAM:
            ret = udp_cmd_recvfrom(sock.desc, (uint8_t *)buf, n, &remote);
            if (addr && addrlen) {
                ((struct sockaddr_in *)addr)->sin_addr.s_addr = remote.addr;
                ((struct sockaddr_in *)addr)->sin_port = remote.port;
                *addrlen = sizeof(struct sockaddr_in);
            }
            return ret;
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

ssize_t
sock_sendto(int desc, const void *buf, size_t n, const struct sockaddr *addr, int addrlen)
{
    struct sock *s, sock;
    ip_endp_t remote;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_DGRAM:
            remote.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            remote.port = ((struct sockaddr_in *)addr)->sin_port;
            return udp_cmd_sendto(sock.desc, (uint8_t *)buf, n, remote);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

int
sock_bind(int desc, const struct sockaddr *addr, int addrlen)
{
    struct sock *s, sock;
    ip_endp_t local;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        local.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
        local.port = ((struct sockaddr_in *)addr)->sin_port;
        switch (sock.type) {
        case SOCK_STREAM:
            return tcp_cmd_bind(sock.desc, local);
        case SOCK_DGRAM:
            return udp_cmd_bind(sock.desc, local);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

int
sock_listen(int desc, int backlog)
{
    struct sock *s, sock;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_STREAM:
            return tcp_cmd_listen(sock.desc, backlog);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

int
sock_accept(int desc, struct sockaddr *addr, int *addrlen)
{
    struct sock *s, sock, *new_s;
    ip_endp_t remote;
    int ret, new_desc;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_STREAM:
            ret = tcp_cmd_accept(sock.desc, &remote);
            if (ret == -1) {
                return -1;
            }
            if (addr && addrlen) {
                ((struct sockaddr_in *)addr)->sin_family = sock.family;
                ((struct sockaddr_in *)addr)->sin_addr.s_addr = remote.addr;
                ((struct sockaddr_in *)addr)->sin_port = remote.port;
                *addrlen = sizeof(struct sockaddr_in);
            }
            lock_acquire(&lock);
            new_s = sock_alloc();
            new_s->family = sock.family;
            new_s->type = sock.type;
            new_s->desc = ret;
            new_desc = indexof(socks, new_s);
            lock_release(&lock);
            return new_desc;
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

int
sock_connect(int desc, const struct sockaddr *addr, int addrlen)
{
    struct sock *s, sock;
    ip_endp_t remote;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_STREAM:
            remote.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            remote.port = ((struct sockaddr_in *)addr)->sin_port;
            return tcp_cmd_connect(sock.desc, remote);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

ssize_t
sock_recv(int desc, void *buf, size_t n)
{
    struct sock *s, sock;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_STREAM:
            return tcp_cmd_receive(sock.desc, (uint8_t *)buf, n);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}

ssize_t
sock_send(int desc, const void *buf, size_t n)
{
    struct sock *s, sock;

    lock_acquire(&lock);
    s = sock_get(desc);
    if (!s) {
        lock_release(&lock);
        return -1;
    }
    sock = *s;
    lock_release(&lock);
    switch (sock.family) {
    case AF_INET:
        switch (sock.type) {
        case SOCK_STREAM:
            return tcp_cmd_send(sock.desc, (uint8_t *)buf, n);
        default:
            errorf("unsupported type %d", sock.type);
            return -1;
        }
    default:
        errorf("unsupported family %d", sock.family);
        return -1;
    }
}
