#include "send_pipeline.h"

#include <stddef.h>

void *bm_send_pipeline_thread(void *arg)
{
    (void)arg;
    /* TODO(§1.1 send_pipeline_thread): send_request_queueをpopし、message_builder.cで
     * 平文payloadを組み立て、crypto.cで暗号化し、pow_request_queueへ投入する。
     * PoW完了通知(pow_result_queue)を待って完成ObjectをNetwork送信キューへ渡す。 */
    return NULL;
}
