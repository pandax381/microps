#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include <stdio.h>
#include <netinet/in.h>

#define IP_HANDLER_TABLE_SIZE 16

static struct {
	ip_addr_t addr;
	struct {
		uint16_t type;
		__ip_handler_t handler;
	} handler_table[IP_HANDLER_TABLE_SIZE];
	int handler_num;
} g_ip = {0};

ip_addr_t *
ip_get_addr (void) {
	return &g_ip.addr;
}

int
ip_set_addr (const char *addr) {
	return ip_addr_pton(addr, &g_ip.addr);
}

int
ip_add_handler (uint16_t type, __ip_handler_t handler) {
	if (g_ip.handler_num >= IP_HANDLER_TABLE_SIZE) {
		return -1;
	}
	g_ip.handler_table[g_ip.handler_num].type = htons(type);
	g_ip.handler_table[g_ip.handler_num].handler = handler;
	g_ip.handler_num++;
	return 0;
}

void
ip_recv (uint8_t *buf, ssize_t len, int bcast) {
	fprintf(stderr, "ip_recv(): %ld (%s)\n", len, bcast ? "broadcast" : "unicast");
}

ssize_t
ip_send (const uint8_t *buf, size_t len, const ip_addr_t *addr) {
	return 0;
}

int
ip_addr_pton (const char *p, ip_addr_t *n) {
	return inet_pton(AF_INET, p, n, sizeof(*n));
}

char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size) {
	if (!inet_ntop(AF_INET, n, p, size)) {
		return NULL;
	}
	return p;
}

int
ip_addr_isself (const ip_addr_t *addr) {
	return (*addr == g_ip.addr);
}

#ifdef _IP_UNIT_TEST
#include "device.h"

void
icmp_recv (uint8_t *buf, ssize_t len) {

}

void
udp_recv (uint8_t *buf, ssize_t len) {

}

void
tcp_recv (uint8_t *buf, ssize_t len) {

}

int
main (int argc, char *argv[]) {
    char device[] = "en0";
    char ethernet_addr[] = "58:55:ca:fb:6e:9f";
	//char ip_addr[] = "10.10.2.228";
	char ip_addr[] = "10.13.100.100";
	ip_addr_t addr;
	char buf[128];

	ip_set_addr(ip_addr);
	ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
	ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
	ip_add_handler(IP_PROTOCOL_TCP, tcp_recv);
    ethernet_set_addr(ethernet_addr);
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(device, ethernet_recv) == -1) {
        goto ERROR;
    }

	//ip_addr_pton("10.13.0.1", &addr);
	//ip_send(buf, sizeof(buf), &addr);
	sleep(10);

    device_cleanup();
    return  0;

ERROR:
    device_cleanup();
    return -1;
}
#endif
