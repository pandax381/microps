#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

#define ICMP_HDR_SIZE 8

#define ICMP_TYPE_ECHOREPLY           0
#define ICMP_TYPE_DEST_UNREACH        3
#define ICMP_TYPE_SOURCE_QUENCH       4
#define ICMP_TYPE_REDIRECT            5
#define ICMP_TYPE_ECHO                8
#define ICMP_TYPE_TIME_EXCEEDED      11
#define ICMP_TYPE_PARAM_PROBLEM      12
#define ICMP_TYPE_TIMESTAMP          13
#define ICMP_TYPE_TIMESTAMPREPLY     14
#define ICMP_TYPE_INFO_REQUEST       15
#define ICMP_TYPE_INFO_REPLY         16

extern int
icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst);

extern int
icmp_init(void);

#endif
