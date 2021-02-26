#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;

struct net_device *
net_device_alloc(void)
{

}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{

}

static int
net_device_open(struct net_device *dev)
{

}

static int
net_device_close(struct net_device *dev)
{

}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{

}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{

}

int
net_run(void)
{

}

void
net_shutdown(void)
{

}

int
net_init(void)
{

}
