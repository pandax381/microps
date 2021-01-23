#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define countof(x) ((sizeof(x) / sizeof(*x)))
#define tailof(x) (x + countof(x))
#define indexof(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))

#define timespec_add_nsec(x, y)          \
    do {                                 \
        (x)->tv_nsec += y;               \
        if ((x)->tv_nsec > 1000000000) { \
            (x)->tv_sec += 1;            \
            (x)->tv_nsec -= 1000000000;  \
        }                                \
    } while(0);

#define errorf(...) lprintf(stderr, 'E', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define warnf(...) lprintf(stderr, 'W', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define infof(...) lprintf(stderr, 'I', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define debugf(...) lprintf(stderr, 'D', __FILE__, __LINE__, __func__, __VA_ARGS__)

#ifdef HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

extern int
lprintf(FILE *fp, int level, const char *file, int line, const char *func, const char *fmt, ...);
extern void
hexdump(FILE *fp, const void *data, size_t size);

struct queue_entry;

struct queue_head {
    struct queue_entry *head;
    struct queue_entry *tail;
    unsigned int num;
};

extern void
queue_init(struct queue_head *queue);
extern void *
queue_push(struct queue_head *queue, void *data);
extern void *
queue_pop(struct queue_head *queue);
extern void *
queue_peek(struct queue_head *queue);

extern uint16_t
hton16(uint16_t h);
extern uint16_t
ntoh16(uint16_t n);
extern uint32_t
hton32(uint32_t h);
extern uint32_t
ntoh32(uint32_t n);

extern uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif
