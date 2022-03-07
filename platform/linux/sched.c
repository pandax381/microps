#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int
sched_ctx_init(struct sched_ctx *ctx)
{
}

int
sched_ctx_destroy(struct sched_ctx *ctx)
{
}

int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
}

int
sched_wakeup(struct sched_ctx *ctx)
{
}

int
sched_interrupt(struct sched_ctx *ctx)
{
}
