#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Memory
 */

static inline void *
memory_alloc(size_t size)
{
    return calloc(1, size);
}

static inline void
memory_free(void *ptr)
{
    free(ptr);
}

/*
 * Mutex
 */

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline int
mutex_init(mutex_t *mutex)
{
    return pthread_mutex_init(mutex, NULL);
}

static inline int
mutex_lock(mutex_t *mutex)
{
    return pthread_mutex_lock(mutex);
}

static inline int
mutex_unlock(mutex_t *mutex)
{
    return pthread_mutex_unlock(mutex);
}

/*
 * Scheduler
 */

struct sched_ctx {
    pthread_cond_t cond;
    int interrupted;
    int wc; /* wait count */
};

#define SCHED_CTX_INITIALIZER {PTHREAD_COND_INITIALIZER, 0, 0}

extern int
sched_ctx_init(struct sched_ctx *ctx);
extern int
sched_ctx_destroy(struct sched_ctx *ctx);
extern int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime);
extern int
sched_wakeup(struct sched_ctx *ctx);
extern int
sched_interrupt(struct sched_ctx *ctx);

/*
 * Interrupt
 */

extern int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *id), int flags, const char *name, void *dev);
extern int
intr_run(void);
extern int
intr_init(void);

static inline void
raise_softirq(void)
{
    kill(getpid(), SIGUSR1);
}

#endif
