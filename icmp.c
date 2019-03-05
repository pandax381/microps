#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
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
icmp_init (void) {
    ip_add_protocol(IP_PROTOCOL_ICMP, icmp_rx);
    return 0;
}
