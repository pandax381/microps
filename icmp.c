#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    union {
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;
        ip_addr_t gateway;
        uint8_t ptr;
        uint32_t unused;
    } un;
#define ih_ptr     un.ptr
#define ih_id      un.echo.id
#define ih_seq     un.echo.seq
#define ih_unused  un.unused
#define ih_gateway un.gateway
    uint8_t data[0];
};

#define ICMP_BUFSIZ (sizeof(struct icmp_hdr) + IP_HDR_SIZE_MAX + 8)

void
icmp_dump (struct netif *netif, ip_addr_t *src, ip_addr_t *dst, uint8_t *packet, size_t plen) {
    struct netif_ip *iface;
    char addr[IP_ADDR_STR_LEN+1];
    struct icmp_hdr *hdr;

    iface = (struct netif_ip *)netif;
    fprintf(stderr, "  dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    fprintf(stderr, "  src: %s\n", src ? ip_addr_ntop(src, addr, sizeof(addr)) : "(self)");
    fprintf(stderr, "  dst: %s\n", ip_addr_ntop(dst, addr, sizeof(addr)));
    hdr = (struct icmp_hdr *)packet;
    fprintf(stderr, " type: %u\n", hdr->type);
    fprintf(stderr, " code: %u\n", hdr->code);
    fprintf(stderr, "  sum: %u\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    case ICMP_TYPE_REDIRECT:
        fprintf(stderr, "   gw: %s\n", ip_addr_ntop(&hdr->ih_gateway, addr, sizeof(addr)));
        break;
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
    case ICMP_TYPE_TIMESTAMP:
    case ICMP_TYPE_TIMESTAMPREPLY:
    case ICMP_TYPE_INFO_REQUEST:
    case ICMP_TYPE_INFO_REPLY:
        fprintf(stderr, "   id: %u\n", ntoh16(hdr->ih_id));
        fprintf(stderr, "  seq: %u\n", ntoh16(hdr->ih_seq));
        break;
    }
    if (hdr->type == ICMP_TYPE_TIMESTAMP || hdr->type == ICMP_TYPE_TIMESTAMPREPLY) {
        /* TODO */
    }
    hexdump(stderr, packet, plen);
}

static int
icmp_tx (struct netif *netif, uint8_t *message, size_t len, ip_addr_t *dst) {
#ifdef DEBUG
    fprintf(stderr, ">>> icmp_tx <<<\n");
    icmp_dump(netif, NULL, dst, message, len);
#endif
    return ip_tx(netif, IP_PROTOCOL_ICMP, message, len, dst);
}

static void
icmp_rx (uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *netif) {
    struct icmp_hdr *hdr;

    (void)dst;
    if (plen < sizeof(struct icmp_hdr)) {
        return;
    }
#ifdef DEBUG
    fprintf(stderr, ">>> icmp_rx <<<\n");
    icmp_dump(netif, src, dst, packet, plen);
#endif
    hdr = (struct icmp_hdr *)packet;
    if (hdr->type == ICMP_TYPE_ECHO) {
        hdr->type = ICMP_TYPE_ECHOREPLY;
        hdr->sum = 0;
        hdr->sum = cksum16((uint16_t *)hdr, plen, 0);
        icmp_tx(netif, packet, plen, src);
    }
}

int
icmp_error_tx (struct netif *netif, uint8_t type, uint8_t code, uint8_t *dgram, size_t dlen) {
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr;
    struct ip_hdr *ip_hdr;
    size_t copy_len, msg_len;

    hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->ih_unused = 0;
    ip_hdr = (struct ip_hdr *)dgram;
    copy_len = ((ip_hdr->vhl & 0x0f) << 2) + 8;
    if (dlen < copy_len) {
        /* Original IP datagram is too short */
        return -1;
    }
    memcpy(hdr->data, dgram, copy_len);
    msg_len = sizeof(struct icmp_hdr) + copy_len;
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);
    icmp_tx(netif, buf, msg_len, &ip_hdr->src);
    return 0;
}

int
icmp_init (void) {
    ip_add_protocol(IP_PROTOCOL_ICMP, icmp_rx);
    return 0;
}
