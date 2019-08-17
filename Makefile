APPS = apps/tcp_echo \
       apps/udp_echo \
       apps/router

TEST = test/raw_test \
       test/ethernet_test \
       test/slip_test \
       test/arp_test

OBJS = util.o \
       raw.o \
       net.o \
       ethernet.o \
       slip.o \
       arp.o \
       ip.o \
       icmp.o \
       udp.o \
       tcp.o \
       dhcp.o \
       microps.o

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -I .

ifeq ($(shell uname),Linux)
	OBJS := $(OBJS) raw/soc.o raw/tap_linux.o
	TEST := $(TEST) test/raw_soc_test test/raw_tap_test
	CFLAGS := $(CFLAGS) -pthread -DHAVE_PF_PACKET -DHAVE_TAP
endif

ifeq ($(shell uname),Darwin)
	OBJS := $(OBJS) raw/bpf.o
	TEST := $(TEST) test/raw_bpf_test.o
#	OBJS := $(OBJS) raw/tap_bsd.o
#	TEST := $(TEST) test/raw_tap_test.o
#	CFLAGS := $(CFLAGS) -DHAVE_TAP
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TEST)

$(APPS): % : %.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST): % : %.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:=.o) $(OBJS) $(TEST) $(TEST:=.o)
