APPS = app/udpc.exe \
       app/udps.exe \
       app/tcpc.exe \
       app/tcps.exe \

TESTS = test/test.exe \

DRIVERS = driver/null.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
       ether.o \
       arp.o \
       ip.o \
       icmp.o \
       udp.o \
       tcp.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       DRIVERS := $(DRIVERS) driver/ether_tap_linux.o driver/ether_pcap_linux.o
endif

ifeq ($(shell uname),Darwin)
       CFLAGS := $(CFLAGS)
       DRIVERS := $(DRIVERS)
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
