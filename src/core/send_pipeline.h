#ifndef BM_CORE_SEND_PIPELINE_H
#define BM_CORE_SEND_PIPELINE_H

/* send_pipeline_thread(§1.1)。send_request_queueを受け取り、暗号化→PoW依頼→
 * broadcast_queueへ送出する。TODO: crypto.c/message_builder.c実装後に着手。 */

void *bm_send_pipeline_thread(void *arg);

#endif /* BM_CORE_SEND_PIPELINE_H */
