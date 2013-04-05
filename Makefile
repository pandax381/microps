PROGRAM = echo_server

OBJECTS = microps.o tcp.o udp.o icmp.o ip.o arp.o ethernet.o util.o

CFLAGS  := $(CFLAGS) -g -W -Wall -Wno-unused-parameter

ifeq ($(shell uname),Linux)
	OBJECTS := $(OBJECTS) pkt.o
	CFLAGS  := $(CFLAGS) -lpthread
endif

ifeq ($(shell uname),Darwin)
	OBJECTS := $(OBJECTS) bpf.o
endif


.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(PROGRAM)

$(PROGRAM): % : %.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(PROGRAM) $(PROGRAM:=.o) $(OBJECTS)
