PROGRAM = echo_server

OBJECTS = microps.o udp.o icmp.o ip.o arp.o ethernet.o util.o

ifeq ($(shell uname),Linux)
	OBJECTS := $(OBJECTS) pkt.o
endif

ifeq ($(shell uname),Darwin)
	OBJECTS := $(OBJECTS) bpf.o
endif

CFLAGS  := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -lpthread

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(PROGRAM)

$(PROGRAM): % : %.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(PROGRAM) $(PROGRAM:=.o) $(OBJECTS)
