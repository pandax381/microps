#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
};

struct icmp_echo {
    struct icmp_hdr hdr;
    uint16_t id;
    uint16_t seq;
    uint8_t data[0];
};

struct icmp_error_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t unused;
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
    struct icmp_error_hdr *hdr;
    size_t icmp_hlen;
    size_t icmp_dlen;
    struct ip_hdr *ip_hdr;
    size_t ip_hlen;

    ip_hdr = (struct ip_hdr *)ip_dgram;
    ip_hlen = (ip_hdr->vhl & 0x0f) << 2;
    icmp_hlen = sizeof(struct icmp_error_hdr);
    icmp_dlen = ip_hlen + 8;
    uint8_t packet[icmp_hlen + icmp_dlen];
    hdr = (struct icmp_error_hdr *)packet;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->unused = 0;
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
