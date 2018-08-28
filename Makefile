PROGRAM = echo_server

OBJECTS = microps.o dhcp.o tcp.o udp.o icmp.o ip.o arp.o ethernet.o util.o

CFLAGS  := $(CFLAGS) -g -W -Wall -Wno-unused-parameter 

ifeq ($(USE_DPDK),1)
  FILE = dpdk.mk
else
  FILE = kernel.mk
endif

include $(PWD)/mk/$(FILE)
