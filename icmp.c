#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    union {
        uint8_t pointer;
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;
        uint32_t reserved;
        ip_addr_t gateway_addr;

    } var_format;
    uint8_t data[0];
};

static void
icmp_rx (uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *iface) {
    struct icmp_hdr *hdr;

    (void)dst;
    if (plen < sizeof(struct icmp_hdr)) {
        return;
    }
    hdr = (struct icmp_hdr *)packet;
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        hdr->type = ICMP_TYPE_ECHO_REPLY;
        hdr->sum = 0;
        hdr->sum = cksum16((uint16_t *)hdr, plen, 0);
        ip_tx(iface, IP_PROTOCOL_ICMP, packet, plen, src);
    }
}

int
icmp_error_tx (struct netif *iface, uint8_t type, uint8_t code, uint8_t *ip_dgram, size_t ip_dlen) {
    uint8_t packet[sizeof(struct icmp_hdr) + IP_HDR_SIZE_MAX + 8];
    struct icmp_hdr *hdr;
    size_t icmp_hlen;
    size_t icmp_dlen;
    struct ip_hdr *ip_hdr;
    size_t ip_hlen;

    ip_hdr = (struct ip_hdr *)ip_dgram;
    ip_hlen = (ip_hdr->vhl & 0x0f) << 2;
    icmp_hlen = sizeof(struct icmp_hdr);
    icmp_dlen = ip_hlen + 8;
    hdr = (struct icmp_hdr *)packet;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->var_format.reserved = 0;
    memcpy(hdr->data, ip_dgram, icmp_dlen);
    hdr->sum = cksum16((uint16_t *)hdr, icmp_hlen + icmp_dlen, 0);

    ip_tx((struct netif *)iface, IP_PROTOCOL_ICMP, packet, icmp_hlen + icmp_dlen, &ip_hdr->src);

    return 1;
}

int
icmp_init (void) {
    ip_add_protocol(IP_PROTOCOL_ICMP, icmp_rx);
    return 0;
}
