#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;

    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("unsupported hardware address");
        return;
    }
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("unsupported protocol address");
        return;
    }
    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

int
arp_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}
