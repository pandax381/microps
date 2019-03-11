#include <stdio.h>
#include <string.h>
#include "microps.h"
#include "ethernet.h"
#include "ip.h"
#include "util.h"

struct interface {
  char *ifname;
  char *hwaddr;
  char *ipaddr;
  char *netmask;
  char *gateway;
};

static int
init(void) {
  struct interface *interface;
  struct interface interfaces[] = {
    {
      .ifname = "tap0",
      .hwaddr = "00:00:5E:00:53:00",
      .ipaddr = "172.16.0.1",
      .netmask = "255.255.255.0",
      .gateway = NULL
    },
    {
      .ifname = "tap10",
      .hwaddr = "00:00:5E:00:53:10",
      .ipaddr = "172.16.1.1",
      .netmask = "255.255.255.0",
      .gateway = NULL
    }
  };
  struct netif *netif;

  if (microps_init() == -1) {
    fprintf(stderr, "microps_init(): error\n");
    return -1;
  }
  for(interface = interfaces; interface < array_tailof(interfaces); interface++) {
    struct netdev *dev;
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
      fprintf(stderr, "netdev_alloc(): error\n");
      return -1;
    }
    strncpy(dev->name, interface->ifname, sizeof(dev->name) -1);
    if (interface->hwaddr) {
      ethernet_addr_pton(interface->hwaddr, (ethernet_addr_t *)dev->addr);
    }
    if (dev->ops->open(dev) == -1) {
      fprintf(stderr, "dev->ops->open(): error\n");
      return -1;
    }
    netif = ip_netif_register(dev, interface->ipaddr, interface->netmask, interface->gateway);
    if (!netif) {
      fprintf(stderr, "ip_register_interface(): error\n");
      return -1;
    }
    dev->ops->run(dev);
  }
  return 0;
}

static void
cleanup (void) {
  microps_cleanup();
}

int
main (void) {
  if(init() == -1) {
    goto ERROR;
  }
  while(1){
    sleep(1);
  }

ERROR:
  cleanup();
  return -1;
}