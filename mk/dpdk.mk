ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = $(PROGRAM)

# all source are stored in SRCS-y
SRCS-y = $(OBJECTS:%.o=%.c)
SRCS-y += $(APP).c
SRCS-y += dpdk.c

CFLAGS += -g -O3 -lpthread -pthread -DUSE_DPDK
#CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk


