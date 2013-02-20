#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

struct queue_entry {
	void *data;
	size_t size;
	struct queue_entry *next;
};

struct queue_head {
	struct queue_entry *next;
	struct queue_entry *tail;
};

extern void
hexdump (FILE *fp, void *data, size_t size);
extern uint16_t
cksum16 (uint16_t *data, uint16_t size, uint32_t init);
extern struct queue_entry *
queue_push (struct queue_head *queue, void *data, size_t size);
extern struct queue_entry *
queue_pop (struct queue_head *queue);

#endif
