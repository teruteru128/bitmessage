#include "trial_decrypt.h"

#include <stddef.h>

void *bm_trial_decrypt_thread(void *arg)
{
    (void)arg;
    /* TODO(§1.1 decrypt_worker_thread): decrypt_request_queueをpopしてcrypto.cで
     * トライアル復号し、成功したらmessages_store.cのinboxへ保存する。 */
    return NULL;
}
