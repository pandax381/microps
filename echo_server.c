#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "microps.h"

struct microps_param param = {
    .ethernet_device = "en4",
    .ethernet_addr = "38:c9:86:24:63:49",
    .ip_addr = "10.50.39.249",
    .ip_netmask = "255.255.248.0",
    .ip_gateway = "10.50.32.1"
};

/*
struct microps_param param = {
    .ethernet_device = "enp0s8",
    .ethernet_addr = "08:00:27:0c:a1:27",
    .ip_addr = "0.0.0.0",
    .ip_netmask = "0.0.0.0",
    .ip_gateway = NULL,
    .use_dhcp = 1
};
*/
/*
struct microps_param param = {
    .ethernet_device = "0",
    .ethernet_addr = "00:1f:5b:fe:ef:cd",
    .ip_addr = "10.0.0.1",
    .ip_netmask = "255.255.255.0",
    .ip_gateway = NULL,
    .use_dhcp = 0
};
*/

#define UDP_ECHO_SERVER_PORT 7

int
main (int argc, char *argv[]) {
/*
    int soc = -1, ret;
    uint8_t buf[65535];
    ip_addr_t peer_addr;
    uint16_t peer_port;
    char addr[IP_ADDR_STR_LEN + 1];

    if (microps_init(&param) == -1) {
        goto ERROR;
    }
    soc = udp_api_open();
    if (soc == -1) {
        goto ERROR;
    }
    if (udp_api_bind(soc, NULL, hton16(UDP_ECHO_SERVER_PORT)) == -1) {
        goto ERROR;
    }
    while (1) {
        ret = udp_api_recvfrom(soc, buf, sizeof(buf), &peer_addr, &peer_port);
        if (ret <= 0) {
            break;
        }
        fprintf(stderr, "receive message, from %s:%d\n",
            ip_addr_ntop(&peer_addr, addr, sizeof(addr)) ,ntoh16(peer_port));
        hexdump(stderr, buf, ret);
        udp_api_sendto(soc, buf, ret, &peer_addr, peer_port);
    }
    udp_api_close(soc);
*/
    int soc = -1, acc;
    uint8_t buf[65536];
    ssize_t len;

    if (microps_init(&param) == -1) {
        goto ERROR;
    }
    soc = tcp_api_open();
    if (soc == -1) {
        goto ERROR;
    }
    if (tcp_api_bind(soc, hton16(7)) == -1) {
        goto ERROR;
    }
    tcp_api_listen(soc);
    acc = tcp_api_accept(soc);
    if (acc == -1) {
        goto ERROR;
    }
fprintf(stderr, "accept success, soc=%d, acc=%d\n", soc, acc);
    while (1) {
        len = tcp_api_recv(acc, buf, sizeof(buf));
        if (len <= 0) {
            break;
        }
        hexdump(stderr, buf, len);
        tcp_api_send(acc, buf, len);
    }
    tcp_api_close(acc);
/*
    ip_addr_t peer_addr;
    uint16_t peer_port;
    ip_addr_pton("72.21.215.232", &peer_addr);
    peer_port = hton16(80);
    tcp_api_connect(soc, &peer_addr, peer_port);
    strcpy(buf, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n");
    tcp_api_send(soc, (uint8_t *)buf, strlen(buf));
    while (1) {
        len = tcp_api_recv(soc, (uint8_t *)buf, sizeof(buf));
        //fprintf(stderr, "len: %ld\n", len);
        if (len <= 0) {
            break;
        }
        //hexdump(stderr, buf, len);
    }
    tcp_api_close(soc);
*/
    microps_cleanup();
    return  0;
ERROR:
    if (soc != -1) {
        tcp_api_close(soc);
    }
    microps_cleanup();
    return -1;
}
