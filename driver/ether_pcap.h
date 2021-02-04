#ifndef ETHER_PCAP_H
#define ETHER_PCAP_H

#include "net.h"

extern struct net_device *
ether_pcap_init(const char *name, const char *addr);

#endif
