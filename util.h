#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#define sizeof_member(s, m) sizeof(((s *)NULL)->m)
#define array_tailof(x) (x + (sizeof(x) / sizeof(*x)))
#define array_offset(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))

struct queue_entry {
    void *data;
    size_t size;
    struct queue_entry *next;
};

struct queue_head {
    struct queue_entry *next;
    struct queue_entry *tail;
    unsigned int num;
};

extern void
hexdump (FILE *fp, void *data, size_t size);
extern int
fdputc (int fd, int c);
extern int
fdgetc (int fd);
extern uint16_t
cksum16 (uint16_t *data, uint16_t size, uint32_t init);
extern struct queue_entry *
queue_push (struct queue_head *queue, void *data, size_t size);
extern struct queue_entry *
queue_pop (struct queue_head *queue);
extern uint16_t
hton16 (uint16_t h);
extern uint16_t
ntoh16 (uint16_t n);
extern uint32_t
hton32 (uint32_t h);
extern uint32_t
ntoh32 (uint32_t n);
extern void
maskset (uint32_t *mask, size_t size, size_t offset, size_t len);
extern int
maskchk (uint32_t *mask, size_t size, size_t offset, size_t len);
extern void
maskclr (uint32_t *mask, size_t size);
extern void
maskdbg (void *mask, size_t size);

#endif
