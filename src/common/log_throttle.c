#include "log_throttle.h"

#include <stddef.h>

int bm_log_throttle_check(struct bm_log_throttle *t, int64_t now, int64_t interval_seconds,
                          uint64_t *out_suppressed)
{
    /* 時計が巻き戻った場合(now < last_emit)も「間隔が空いた」とみなして出す。
     * 黙り続けて何も分からなくなるより、1行多く出るほうがまし */
    if (!t->emitted || now - t->last_emit >= interval_seconds || now < t->last_emit)
    {
        if (out_suppressed != NULL)
        {
            *out_suppressed = t->suppressed;
        }
        t->last_emit = now;
        t->suppressed = 0;
        t->emitted = 1;
        return 1;
    }
    t->suppressed++;
    return 0;
}
