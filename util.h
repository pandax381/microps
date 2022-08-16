#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/*
 * Array
 */

#define countof(x) ((sizeof(x) / sizeof(x[0])))
#define tailof(x) (x + countof(x))
#define indexof(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))

/*
 * Time
 */

#define timeval_add_usec(x, y)         \
    do {                               \
        (x)->tv_sec += (y) / 1000000;  \
        (x)->tv_usec += (y) % 1000000; \
        if ((x)->tv_usec >= 1000000) { \
            (x)->tv_sec += 1;          \
            (x)->tv_usec -= 1000000;   \
        }                              \
    } while (0);

#define timespec_add_nsec(x, y)           \
    do {                                  \
        (x)->tv_sec += (y) / 1000000000;  \
        (x)->tv_nsec += (y) % 1000000000; \
        if ((x)->tv_nsec >= 1000000000) { \
            (x)->tv_sec += 1;             \
            (x)->tv_nsec -= 1000000000;   \
        }                                 \
    } while (0);

/*
 * Logging
 */

#define logf(lv, fmt, ...) lprintf(stderr, lv, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define errorf(fmt, ...) logf('E', fmt, ##__VA_ARGS__)
#define warnf(fmt, ...)  logf('W', fmt, ##__VA_ARGS__)
#define infof(fmt, ...)  logf('I', fmt, ##__VA_ARGS__)
#define debugf(fmt, ...) logf('D', fmt, ##__VA_ARGS__)

#ifdef HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

extern int
lprintf(FILE *fp, int level, const char *file, int line, const char *func, const char *fmt, ...);
extern void
hexdump(FILE *fp, const void *data, size_t size);

/*
 * Queue
 */

struct queue;

extern void
queue_init(struct queue *queue);
extern void *
queue_push(struct queue *queue, void *data);
extern void *
queue_pop(struct queue *queue);
extern void *
queue_peek(struct queue *queue);
extern size_t
queue_len(struct queue *queue);
extern void
queue_foreach(struct queue *queue, void (*func)(void *arg, void *data), void *arg);

/*
 * Byteorder
 */

extern uint16_t
hton16(uint16_t h);
extern uint16_t
ntoh16(uint16_t n);
extern uint32_t
hton32(uint32_t h);
extern uint32_t
ntoh32(uint32_t n);

/*
 * Checksum
 */

extern uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif
