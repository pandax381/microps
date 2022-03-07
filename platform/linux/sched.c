#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int
sched_ctx_init(struct sched_ctx *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

int
sched_ctx_destroy(struct sched_ctx *ctx)
{
    return pthread_cond_destroy(&ctx->cond);
}

int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    if (ctx->interrupted) {
        errno = EINTR;
        return -1;
    }
    ctx->wc++;
    if (abstime) {
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    } else {
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--;
    if (ctx->interrupted) {
        if (!ctx->wc) {
            ctx->interrupted = 0;
        }
        errno = EINTR;
        return -1;
    }
    return ret;
}

int
sched_wakeup(struct sched_ctx *ctx)
{
    return pthread_cond_broadcast(&ctx->cond);
}

int
sched_interrupt(struct sched_ctx *ctx)
{
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}
