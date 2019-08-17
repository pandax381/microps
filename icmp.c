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
#define ih_values  un.unused
#define ih_gateway un.gateway
    uint8_t data[0];
};

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

static char *
icmp_type_ntoa (uint8_t type) {
    switch (type) {
    case ICMP_TYPE_ECHOREPLY:
        return "Echo Reply";
    case ICMP_TYPE_DEST_UNREACH:
        return "Destination Unreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
        return "Source Quench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "Time Exceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "Parameter Problem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "Timestamp Reply";
    case ICMP_TYPE_INFO_REQUEST:
        return "Information Request";
    case ICMP_TYPE_INFO_REPLY:
        return "Information Reply";
    }
    return "UNKNOWN";
}

void
icmp_dump (struct netif *netif, ip_addr_t *src, ip_addr_t *dst, uint8_t *packet, size_t plen) {
    struct netif_ip *iface;
    char addr[IP_ADDR_STR_LEN];
    struct icmp_hdr *hdr;
    uint32_t *timestamp;

    iface = (struct netif_ip *)netif;
    fprintf(stderr, "   dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    fprintf(stderr, "   src: %s\n", src ? ip_addr_ntop(src, addr, sizeof(addr)) : "(self)");
    fprintf(stderr, "   dst: %s\n", ip_addr_ntop(dst, addr, sizeof(addr)));
    hdr = (struct icmp_hdr *)packet;
    fprintf(stderr, "  type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "  code: %u\n", hdr->code);
    fprintf(stderr, "   sum: %u\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
    case ICMP_TYPE_TIMESTAMP:
    case ICMP_TYPE_TIMESTAMPREPLY:
    case ICMP_TYPE_INFO_REQUEST:
    case ICMP_TYPE_INFO_REPLY:
        fprintf(stderr, "    id: %u\n", ntoh16(hdr->ih_id));
        fprintf(stderr, "   seq: %u\n", ntoh16(hdr->ih_seq));
        break;
    case ICMP_TYPE_REDIRECT:
        fprintf(stderr, "    gw: %s\n", ip_addr_ntop(&hdr->ih_gateway, addr, sizeof(addr)));
        break;
    }
    if (hdr->type == ICMP_TYPE_TIMESTAMP || hdr->type == ICMP_TYPE_TIMESTAMPREPLY) {
        timestamp = (uint32_t *)hdr->data;
        fprintf(stderr, " otime: %u\n", ntoh32(*timestamp++));
        fprintf(stderr, " rtime: %u\n", ntoh32(*timestamp++));
        fprintf(stderr, " ttime: %u\n", ntoh32(*timestamp++));
    }
    hexdump(stderr, packet, plen);
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
    switch (hdr->type) {
    case ICMP_TYPE_ECHO:
        icmp_tx(netif, ICMP_TYPE_ECHOREPLY, hdr->code, hdr->ih_values, hdr->data, plen - sizeof(struct icmp_hdr), src);
        break;
    }
}

int
icmp_tx (struct netif *netif, uint8_t type, uint8_t code, uint32_t values, uint8_t *data, size_t len, ip_addr_t *dst) {
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr;
    size_t msg_len;

    hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->ih_values = values;
    memcpy(hdr->data, data, len);
    msg_len = sizeof(struct icmp_hdr) + len;
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);
#ifdef DEBUG
    fprintf(stderr, ">>> icmp_tx <<<\n");
    icmp_dump(netif, NULL, dst, (uint8_t *)hdr, msg_len);
#endif
    return ip_tx(netif, IP_PROTOCOL_ICMP, (uint8_t *)hdr, msg_len, dst);
}

int
icmp_init (void) {
    ip_add_protocol(IP_PROTOCOL_ICMP, icmp_rx);
    return 0;
}
