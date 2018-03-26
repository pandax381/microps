#include <stdio.h>
#include <stdint.h>
#include "ethernet.h"
#include "ip.h"
#include "util.h"

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

#define DHCP_MESSAGE_MIN_LEN (sizeof(struct dhcp) + 64)
#define DHCP_MESSAGE_BUF_LEN (sizeof(struct dhcp) + 312)
#define DHCP_MAGIC_CODE "\x63\x82\x53\x63"
#define DHPC_FLAG_BROADCAST (0x8000)

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
    fprintf(stderr, "option[%02x]\n", *opt++);
    fprintf(stderr, "total %d bytes (padding %d bytes)\n", n, n - (opt - (uint8_t *)p));
}
