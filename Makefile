PROGRAMS = apps/tcp_echo apps/udp_echo

TEST_DIR = test

TEST_PROGRAMS = $(TEST_DIR)/raw_test \
                $(TEST_DIR)/ethernet_test \
                $(TEST_DIR)/slip_test \
                $(TEST_DIR)/arp_test

OBJECTS = util.o \
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
	RAW = raw_tap.o
	CFLAGS := $(CFLAGS) -lpthread -pthread
endif

ifeq ($(shell uname),Darwin)
	RAW = raw_bpf.o
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean all_test

all: $(PROGRAMS)

$(PROGRAMS): % : %.o $(OBJECTS) $(RAW)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

raw_test: % : util.o $(TEST_DIR)/%.o $(OBJECTS) $(RAW)
	$(CC) $(CFLAGS) -o $(TEST_DIR)/$@ $^ $(LDFLAGS)

ethernet_test: % : util.o $(TEST_DIR)/%.o $(RAW) net.o ethernet.o
	$(CC) $(CFLAGS) -o $(TEST_DIR)/$@ $^ $(LDFLAGS)

slip_test: % : util.o $(TEST_DIR)/%.o net.o slip.o
	$(CC) $(CFLAGS) -o $(TEST_DIR)/$@ $^ $(LDFLAGS)

arp_test: % : util.o $(TEST_DIR)/%.o $(RAW) net.o ethernet.o arp.o ip.o
	$(CC) $(CFLAGS) -o $(TEST_DIR)/$@ $^ $(LDFLAGS)

all_test: raw_test ethernet_test slip_test arp_test

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(PROGRAMS) $(PROGRAMS:=.o) $(OBJECTS) $(RAW) $(TEST_PROGRAMS) $(TEST_PROGRAMS:=.o)
