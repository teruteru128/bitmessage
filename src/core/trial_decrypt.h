#ifndef BM_CORE_TRIAL_DECRYPT_H
#define BM_CORE_TRIAL_DECRYPT_H

/* decrypt_worker_thread(§1.1)。decrypt_request_queueから新着objectを取り出し、
 * keyring内の全unlocked鍵でトライアル復号を試みる。TODO: crypto.c実装後に着手。 */

void *bm_trial_decrypt_thread(void *arg);

#endif /* BM_CORE_TRIAL_DECRYPT_H */
