#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "util.h"
#include "net.h"
#include "ethernet.h"
#include "ip.h"
#include "udp.h"

//#define DHCP_MESSAGE_MIN_LEN (sizeof(struct dhcp) + 64)
#define DHCP_MESSAGE_MIN_LEN (sizeof(struct dhcp) + 64 -4)
#define DHCP_MESSAGE_BUF_LEN (sizeof(struct dhcp) + 312 - 4)
#define DHCP_MAGIC_CODE "\x63\x82\x53\x63"
#define DHCP_FLAG_BROADCAST (0x8000)
#define DHCP_VENDOR_BYTE_SIZE 64
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_TYPE_NONE     0
#define DHCP_TYPE_DISCOVER 1
#define DHCP_TYPE_OFFER    2
#define DHCP_TYPE_REQUEST  3
#define DHCP_TYPE_DECLINE  4
#define DHCP_TYPE_ACK      5
#define DHCP_TYPE_NAK      6
#define DHCP_TYPE_RELEASE  7
#define DHCP_TYPE_INFORM   8

#define DEBUG 1

struct dhcp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4];
    uint8_t options[0];
};

struct dhcp_option {
    uint8_t code;
    uint8_t len;
    uint8_t data[0];
};

void
dhcp_dump (const uint8_t *buf, size_t n) {
    struct dhcp *p;
    char iaddr[IP_ADDR_STR_LEN+1];
    char chaddr[ETHERNET_ADDR_STR_LEN+1];
    uint8_t *opt;
    size_t len;

    p = (struct dhcp *)buf;
    if (!p || n < DHCP_MESSAGE_MIN_LEN) {
        fprintf(stderr, "Invalid DHCP message (%lu:%zu)\n", DHCP_MESSAGE_MIN_LEN, n);
        return;
    }
    fprintf(stderr, "    op: %x\n", p->op);
    fprintf(stderr, " htype: %x\n", p->htype);
    fprintf(stderr, "  hlen: %x\n", p->hlen);
    fprintf(stderr, "  hops: %x\n", p->hops);
    fprintf(stderr, "   xid: %x (%d)\n", ntoh32(p->xid), ntoh32(p->xid));
    fprintf(stderr, "  secs: %x\n", ntoh16(p->secs));
    fprintf(stderr, " flags: %x\n", ntoh16(p->flags));
    fprintf(stderr, "ciaddr: %s\n", ip_addr_ntop(&p->ciaddr, iaddr, sizeof(iaddr)));
    fprintf(stderr, "yiaddr: %s\n", ip_addr_ntop(&p->yiaddr, iaddr, sizeof(iaddr)));
    fprintf(stderr, "siaddr: %s\n", ip_addr_ntop(&p->siaddr, iaddr, sizeof(iaddr)));
    fprintf(stderr, "giaddr: %s\n", ip_addr_ntop(&p->giaddr, iaddr, sizeof(iaddr)));
    fprintf(stderr, "chaddr: %s\n", ethernet_addr_ntop((ethernet_addr_t *)p->chaddr, chaddr, sizeof(chaddr)));
    fprintf(stderr, " sname: %.64s\n", p->sname);
    fprintf(stderr, "  file: %.128s\n", p->file);
    fprintf(stderr, " magic: %02x %02x %02x %02x\n", p->magic[0], p->magic[1], p->magic[2], p->magic[3]);
    opt = (uint8_t *)p->options;
    while (*opt != 0xff && opt - (uint8_t *)p < (ssize_t)n) {
        fprintf(stderr, "option[%02x]", *opt);
        if (*opt++) {
            for (len = *opt++; len; len--) {
                fprintf(stderr, " %02x", *opt++);
            }
        } 
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "option[%02x]\n", *opt++);
    fprintf(stderr, "total %zu bytes (padding %lu bytes)\n", n, n - (opt - (uint8_t *)p));
}

static void
dhcp_build_discover_message (uint8_t *buf, size_t size, ethernet_addr_t chaddr, uint32_t xid) {
    struct dhcp *discover;
    uint8_t *opt;

    discover = (struct dhcp *)buf;
    // add discover packet info
    discover->op = 0x01;
    discover->htype = 0x01;
    discover->hlen = 0x06;
    discover->xid = hton32(xid);
    discover->flags = hton16(DHCP_FLAG_BROADCAST);
    memcpy(discover->chaddr, chaddr.addr, 6);
    memcpy(discover->magic, DHCP_MAGIC_CODE, 4);

    // add dhcp vendor info
    opt = discover->options;
    // discover
    *opt++ = 0x35;
    *opt++ = 0x01;
    *opt++ = 0x01;
    // client ID
    *opt++ = 0x3D;
    *opt++ = 0x07;
    *opt++ = 0x01;
    // MAC addr
    memcpy(opt, discover->chaddr, 6);
    opt += 6;
    // Option request
    *opt++ = 0x37;
    *opt++ = 0x04;
    *opt++ = 0x01;
    *opt++ = 0x03;
    *opt++ = 0x06;
    *opt++ = 0x0f;
    // Stopper
    *opt++ = 0xFF;
#ifdef DEBUG
    fprintf(stderr, ">>> dhcp_build_discover_message: (%zd octets) <<<\n", size);
    dhcp_dump(buf, size);
#endif
}

static void
dhcp_build_request_message (uint8_t *buf, size_t size, ethernet_addr_t chaddr, uint32_t yiaddr, uint32_t siaddr, uint32_t xid, ip_addr_t *serverid) {
    struct dhcp *request;
    uint8_t *opt;

    request = (struct dhcp *)buf;
    request->op = 0x01;
    request->htype = 0x01;
    request->hlen = 0x06;
    request->xid = hton32(xid);
    request->flags = hton16(DHCP_FLAG_BROADCAST);
    request->yiaddr = yiaddr;
    request->siaddr = siaddr;
    memcpy(request->chaddr, chaddr.addr, 6);
    memcpy(request->magic, DHCP_MAGIC_CODE, 4);

    // vender part
    opt = request->options;
    // request
    *opt++ = 0x35;
    *opt++ = 0x01;
    *opt++ = 0x03;
    // client id
    *opt++ = 0x3D;
    *opt++ = 0x07;
    *opt++ = 0x01;
    // MAC addr
    memcpy(opt, request->chaddr, 6);
    opt += 6;
    // request ip
    *opt++ = 0x32;
    *opt++ = 0x04;
    // user ip addr
    memcpy(opt, &request->yiaddr, 4);
    opt += 4;
    if (serverid) {
        *opt++ = 0x36;
        *opt++ = 0x04;
        memcpy(opt, serverid, 4);
        opt += 4;
    }
    // stopper
    *opt++ = 0xFF;
}

static void
dhcp_get_addr_fromack (struct dhcp *ack, size_t n, uint32_t *addr, uint32_t *netmask, uint32_t *gateway) {
    uint8_t *opt;

    opt = ack->options;
    *addr = ack->yiaddr;
    while (*opt != 0xff && opt - (uint8_t *)ack < (ssize_t)n){
        switch (*opt++) {
        case 0x00:
            continue;
        case 0x01:
            *netmask = *(uint32_t *)(opt + 1);
            break;
        case 0x03:
            *gateway = *(uint32_t *)(opt + 1);
            break;
        default:
            break;
        }
        opt += (*opt + 1);
    }
}

static struct dhcp_option *
dhcp_get_option (struct dhcp *message, size_t len, uint8_t code) {
    uint8_t *opt;

    opt = message->options;
    while (*opt != 0xff && opt - (uint8_t *)message < (ssize_t)len) {
        if (*opt == code) {
            return (struct dhcp_option *)opt;
        }
        switch (*opt++) {
        case 0x00:
            break;
        default:
            opt += (*opt + 1);
            break;
        }
    }
    return NULL;
}

static int 
dhcp_recv_message(int sock, uint8_t *buf, size_t size, uint32_t xid, uint8_t type, ip_addr_t *serverid, int timeout) {
    ssize_t len;
    struct dhcp *msg;
    struct dhcp_option *option;

    while (1) {
        len = udp_api_recvfrom(sock, buf, size, NULL, NULL, timeout);
        if (len == -1) {
            return -1;
        }
        if (len < (int)DHCP_MESSAGE_MIN_LEN) {
            continue;
        }
        msg = (struct dhcp *)buf;
        if (msg->op != 0x02) {
            continue;
        }
        if (msg->xid != hton32(xid)) {
            continue;
        }
        if (memcmp((uint32_t *)msg->magic, DHCP_MAGIC_CODE, 4)) {
            continue;
        }
        if (type) {
            option = dhcp_get_option(msg, len, 0x35);
            if (!option || option->len != 1) {
                continue;
            }
            if (option->data[0] != type) {
                continue;
            }
        }
        if (serverid) {
            option = dhcp_get_option(msg, len, 0x36);
            if (!option) {
                continue;
            }
            if (memcmp(option->data, serverid, 4) != 0) {
                continue;
            }
        }
#ifdef DEBUG
        fprintf(stderr, ">>> dhcp_recv_message: (%zd octets) <<<\n", len);
        dhcp_dump(buf, len);
#endif
        return len;
    }
    return -1;
}

int
dhcp_init(struct netif *iface) {
    int res, sock, len;
    uint8_t sbuf[DHCP_MESSAGE_MIN_LEN];
    uint8_t rbuf[DHCP_MESSAGE_BUF_LEN];
    uint32_t yiaddr, siaddr, nmaddr, gwaddr;
    uint32_t xid = (uint32_t)time(NULL);
    struct dhcp *offer, *answer;
    char addr[IP_ADDR_STR_LEN+1], netmask[IP_ADDR_STR_LEN+1], gateway[IP_ADDR_STR_LEN+1];
    ethernet_addr_t chaddr;
    ip_addr_t peer, serverid;
    uint16_t peer_port = hton16(DHCP_SERVER_PORT);
    struct dhcp_option *option;

    sock = udp_api_open();
    if (sock < 0) {
        fprintf(stderr, "udp sock open failed.\n");
        goto ERROR;
    }
    res = udp_api_bind_iface(sock, iface, hton16(DHCP_CLIENT_PORT));
    if (res < 0) {
        fprintf(stderr, "udp sock bind failed.\n");
        goto ERROR;
    }
    chaddr = *(ethernet_addr_t *)iface->dev->addr;
    peer = IP_ADDR_BROADCAST;
    /* DHCPDISCOVER */
    memset(sbuf, 0x00, sizeof(sbuf));
    dhcp_build_discover_message(sbuf, sizeof(sbuf), chaddr, xid);
    if (udp_api_sendto(sock, sbuf, sizeof(sbuf), &peer, peer_port) == -1) {
        fprintf(stderr, "udp_api_sendto(): failure\n");
        goto ERROR;
    }
    /* DHCPOFFER */
    len = dhcp_recv_message(sock, rbuf, sizeof(rbuf), xid, DHCP_TYPE_OFFER, NULL, 3);
    if (len == -1) {
        fprintf(stderr, "dhcp_recv_message(): failure\n");
        goto  ERROR;
    }
    offer = (struct dhcp *)rbuf;
    yiaddr = offer->yiaddr;
    siaddr = offer->siaddr;
    option = dhcp_get_option(offer, len, 0x36);
    if (!option || option->len != 4) {
        fprintf(stderr, "serverid not found\n");
        goto ERROR;
    }
    memcpy(&serverid, option->data, option->len);
    /* DHCPREQUEST */
    memset(sbuf, 0x00, sizeof(sbuf));
    dhcp_build_request_message(sbuf, sizeof(sbuf), chaddr, yiaddr, siaddr, xid, &serverid);
#ifdef DEBUG
    fprintf(stderr, ">>> dhcp request message (%zd octets) <<<\n", sizeof(sbuf));
    dhcp_dump(sbuf, sizeof(sbuf));
#endif
    if (udp_api_sendto(sock, sbuf, sizeof(sbuf), &peer, peer_port) == -1) {
        fprintf(stderr, "udp_api_sendto(): failure\n");
        goto ERROR;
    }
    /* DHCPACK or DHCPNAK */
    len = dhcp_recv_message(sock, rbuf, sizeof(rbuf), xid, DHCP_TYPE_NONE, &serverid, 3);
    if (len == -1) {
        fprintf(stderr, "dhcp_recv_message(): failure\n");
        goto ERROR;
    }
    answer = (struct dhcp *)rbuf;
    option = dhcp_get_option(answer, len, 0x35);
    if (!option || option->len != 1) {
        fprintf(stderr, "serverid not found\n");
        goto ERROR;
    }
    if (option->data[0] != DHCP_TYPE_ACK) {
        fprintf(stderr, "receive not ACK message (%d)\n", option->data[0]);
        goto ERROR;
    }
    udp_api_close(sock);
    dhcp_get_addr_fromack(answer, len, &yiaddr, &nmaddr, &gwaddr);
    ip_addr_ntop(&yiaddr, addr, sizeof(addr));
    ip_addr_ntop(&nmaddr, netmask, sizeof(netmask));
    ip_addr_ntop(&gwaddr, gateway, sizeof(gateway));
    fprintf(stderr, "dhcp_init(): success, addr=%s, netmask=%s, gateway=%s\n", addr, netmask, gateway);
    ip_netif_reconfigure(iface, addr, netmask, gateway);
    return 0;

ERROR:
    if (sock != -1) {
        udp_api_close(sock);
    }
    return -1;
}
