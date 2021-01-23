APPS = 

TEST = test/step1.exe \

DRIVERS = driver/null.o \

OBJS = util.o \
       net.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       TEST := $(TEST)
       DRIVERS := $(DRIVERS)
endif

ifeq ($(shell uname),Darwin)
       CFLAGS := $(CFLAGS)
       TEST := $(TEST)
       DRIVERS := $(DRIVERS)
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TEST)

$(APPS): % : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:=.o) $(OBJS) $(DRIVERS) $(TEST) $(TEST:.exe=.o)
