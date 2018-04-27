PROGRAM = echo_server

OBJECTS = microps.o tcp.o udp.o icmp.o ip.o arp.o ethernet.o util.o dhcp.o

CFLAGS  := $(CFLAGS) -g -W -Wall -Wno-unused-parameter 

ifeq ($(USE_DPDK),1)
  FILE = dpdk.mk
else
  FILE = kernel.mk
endif

include $(PWD)/mk/$(FILE)
