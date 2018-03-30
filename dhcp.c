#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ethernet.h"
#include "ip.h"
#include "udp.h"
#include "util.h"

#define DHCP_MESSAGE_MIN_LEN (sizeof(struct dhcp) + 64)
#define DHCP_MESSAGE_BUF_LEN (sizeof(struct dhcp) + 312)
#define DHCP_MAGIC_CODE "\x63\x82\x53\x63"
#define DHCP_FLAG_BROADCAST (0x8000)
#define DHCP_VENDOR_BYTE_SIZE 64
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

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
    uint8_t options[0];
};

void
dhcp_debug_message(const struct dhcp *p, size_t n) {
    char iaddr[IP_ADDR_STR_LEN+1];
    char chaddr[ETHERNET_ADDR_STR_LEN+1];
    uint8_t *opt;
    size_t len;

    fprintf(stderr, "========== DHCP Message Debug Print ==========\n");
    if (!p || n < DHCP_MESSAGE_MIN_LEN) {
        fprintf(stderr, "Invalid DHCP message (%d:%d)\n", DHCP_MESSAGE_MIN_LEN, n);
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
    opt = p->options;
    fprintf(stderr, " magic: %02x %02x %02x %02x\n", *opt++, *opt++, *opt++, *opt++);
    while (*opt != 0xff) {
        fprintf(stderr, "option[%02x]", *opt++);
        for (len = *opt++; len; len--) {
            fprintf(stderr, " %02x", *opt++);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "option:[%02x]\n", *opt++);
    fprintf(stderr, "total %d bytes (padding %d bytes)\n", n, n - (opt - (uint8_t *)p));
}

static void
dhcp_build_discover(struct dhcp *discover, ethernet_addr_t eth, uint32_t xid) {
    uint8_t *opt;    

    // add discover packet info    
    discover->op = 0x01;
    discover->htype = 0x01;
    discover->hlen = 0x06;
    discover->xid = hton32(xid);
    discover->flags = hton16(DHCP_FLAG_BROADCAST);
    memcpy(discover->chaddr, eth.addr, 6);

    // add dhcp vendor info
    opt = discover->options;
    // MAGIC
    memcpy(opt, DHCP_MAGIC_CODE, 4);
    opt += 4;
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
    // Stopper
    *opt++ = 0xFF;
}

static void
dhcp_build_request(struct dhcp *request, ethernet_addr_t eth, uint32_t yiaddr, uint32_t siaddr, uint32_t xid) {
    uint8_t *opt;    

    request->op = 0x01;
    request->htype = 0x01;
    request->hlen = 0x06;
    request->xid = hton32(xid);
    request->flags = hton16(DHCP_FLAG_BROADCAST);
    request->yiaddr = yiaddr;
    request->siaddr = siaddr;
    memcpy(request->chaddr, eth.addr, 6);

    // vender part
    opt = request->options;
    memcpy(opt, DHCP_MAGIC_CODE, 4);
    opt += 4;
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
    // stopper
    *opt++ = 0xFF;
}

static void
dhcp_get_addr_fromack(struct dhcp *ack, uint32_t *addr, uint32_t *netmask, uint32_t *gateway) {
    size_t len;
    uint8_t *options = ack->options;
    uint8_t opt_type;
    
    *addr = ack->yiaddr;
    // skip magic
    options += 4;

    while(*options != 0xFF){
        opt_type = *options++;
        len = *options++;
        switch(opt_type){
            case 0x01:
                *netmask = *(uint32_t *)options;
                break;
            case 0x03:
                *gateway = *(uint32_t *)options;
                break;
            default:
                break;
        }
        options += len;
    }
}

static int 
dhcp_recv_message(int sock, uint8_t *buf, size_t size, uint32_t xid, uint8_t *type) {
    int len;
    struct dhcp *msg;
    uint8_t *opt;
    
    while (1) {
        len = udp_api_recvfrom(sock, buf, size, NULL, NULL);
        if (len < DHCP_MESSAGE_MIN_LEN) {
            continue;
        }
        msg = (struct dhcp *)buf;
        if (msg->op != 0x02){
            continue;
        }
        if (msg->xid != hton32(xid)) {
            continue;
        }
        opt = msg->options;
        if (memcmp((uint32_t *)opt, DHCP_MAGIC_CODE, 4)) {
             continue;
        }
        opt += 4;
        while (*opt != 0xff) {
            if (*opt++ != 0x35) {
                opt += *opt;
                continue;
            }
            if (*opt++ != 0x01) {
                fprintf(stderr, "WARNING: Option 0x35 length is not one.\n");
            }
            break;
        }
        if (*type == 0) {
            *type = *opt;
        }
        if (*opt != *type) {
            continue;
        }
        break;
    }
    return len;
}

int
dhcp_init(char *ethernet_addr) { 
    int res, sock, len;
    uint8_t *opt, kind;
    uint8_t sbuf[DHCP_MESSAGE_MIN_LEN];
    uint8_t rbuf[DHCP_MESSAGE_BUF_LEN];
    uint32_t yiaddr, siaddr, nmaddr, gwaddr;
    uint32_t xid = (uint32_t)time(NULL);
    struct dhcp *discover, *offer, *request, *ack;
    char addr[IP_ADDR_STR_LEN+1],netmask[IP_ADDR_STR_LEN+1], gateway[IP_ADDR_STR_LEN+1];
    ethernet_addr_t eth_addr;
    ip_addr_t peer;
    uint16_t peer_port = hton16(DHCP_SERVER_PORT);
    
    sock = udp_api_open();
    if (sock < 0) {
        fprintf(stderr, "udp sock open failed.\n");
        goto ERROR;
    }

    res = udp_api_bind(sock, hton16(DHCP_CLIENT_PORT));
    if (res < 0) {
        fprintf(stderr, "udp sock bind failed.\n");
        goto ERROR;
    }
    
    ethernet_addr_pton(ethernet_addr, &eth_addr);
    peer = IP_ADDR_BCAST;

    memset(sbuf, 0x00, sizeof(sbuf));
    discover = (struct dhcp *)sbuf;
    dhcp_build_discover(discover, eth_addr, xid);
#ifdef DEBUG
    dhcp_debug_message(discover, sizeof(sbuf));
#endif

    // send discover
    len = udp_api_sendto(sock, sbuf, sizeof(sbuf), &peer, peer_port);  
    if (len < 0) {
        goto ERROR;
    }

    kind = 0x02;
    len = dhcp_recv_message(sock, rbuf, sizeof(rbuf), xid, &kind);

    
    offer = (struct dhcp *)rbuf;
#ifdef DEBUG
    dhcp_debug_message(offer, len);
#endif

    // get yi addr and si addr
    yiaddr = offer->yiaddr;
    siaddr = offer->siaddr;

    // build request packet
    memset(sbuf, 0x00, sizeof(sbuf));
    request = (struct dhcp *)sbuf;
    dhcp_build_request(request, eth_addr, yiaddr, siaddr, xid);
#ifdef DEBUG
    dhcp_debug_message(request, sizeof(sbuf));
#endif

    // send request packet
    len = udp_api_sendto(sock, sbuf, sizeof(sbuf), &peer, peer_port);
    if (len < 0) {
        goto ERROR;
    }

    // recv ack packet
    kind = 0;
    len = dhcp_recv_message(sock, rbuf, sizeof(rbuf), xid, &kind);

    if (kind != 0x05) {
        goto ERROR;
    }

    ack = (struct dhcp *)rbuf;
#ifdef DEBUG
    dhcp_debug_message(ack, len);
#endif 
   
    udp_api_close(sock);

    
    dhcp_get_addr_fromack(ack, &yiaddr, &nmaddr, &gwaddr);

    ip_addr_ntop(&yiaddr, addr, sizeof(addr));
    ip_addr_ntop(&nmaddr, netmask, sizeof(netmask)); 
    ip_addr_ntop(&gwaddr, gateway, sizeof(gateway));
    ip_init(addr, netmask, gateway, 1); 
    return 0;
ERROR:  
    if (sock != -1) {
        udp_api_close(sock);
    }
    return -1;
}
