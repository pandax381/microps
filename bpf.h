#ifndef _MICROPS_BPF_H_
#define _MIDROPS_BPF_H_

#include <stdint.h>
#include <sys/types.h>

typedef struct bpf bpf_t;

extern bpf_t *
bpf_open (const char *name);
extern void
bpf_close (bpf_t *obj);
extern ssize_t
bpf_read (bpf_t *obj, void *buf, size_t nbyte);
extern ssize_t
bpf_write (bpf_t *obj, const void *buf, size_t nbyte);

#endif
