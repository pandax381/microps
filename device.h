#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef struct device_fd device_fd_t;

extern device_fd_t *
device_open (const char *name);
extern void
device_close (device_fd_t *devfd);
extern void
device_input (device_fd_t *devfd, void (*callback)(uint8_t *, size_t), int timeout);
extern ssize_t
device_output (device_fd_t *devfd, const uint8_t *buffer, size_t len);

#endif
