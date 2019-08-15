#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "net.h"

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_ADDR_STR_LEN 18 /* "xx:xx:xx:xx:xx:xx\0" */

#define ETHERNET_HDR_SIZE 14
#define ETHERNET_TRL_SIZE 4
#define ETHERNET_FRAME_SIZE_MIN 64
#define ETHERNET_FRAME_SIZE_MAX 1518
#define ETHERNET_PAYLOAD_SIZE_MIN (ETHERNET_FRAME_SIZE_MIN - (ETHERNET_HDR_SIZE + ETHERNET_TRL_SIZE))
#define ETHERNET_PAYLOAD_SIZE_MAX (ETHERNET_FRAME_SIZE_MAX - (ETHERNET_HDR_SIZE + ETHERNET_TRL_SIZE))

#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_LOOPBACK 0x9000

extern const uint8_t ETHERNET_ADDR_ANY[ETHERNET_ADDR_LEN];
extern const uint8_t ETHERNET_ADDR_BROADCAST[ETHERNET_ADDR_LEN];

extern int
ethernet_addr_pton (const char *p, uint8_t *n);
extern char *
ethernet_addr_ntop (const uint8_t *n, char *p, size_t size);

extern int
ethernet_init (void);

#endif
