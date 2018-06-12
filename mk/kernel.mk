ifeq ($(shell uname),Linux)
	OBJECTS := $(OBJECTS) pkt.o
	CFLAGS  := $(CFLAGS) -lpthread -pthread
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
