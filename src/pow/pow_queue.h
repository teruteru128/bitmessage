#ifndef BM_POW_QUEUE_H
#define BM_POW_QUEUE_H

/*
 * §11 2026-11-03 項目38: PoWを呼び出し元スレッドから追い出すためのジョブキュー
 * (DESIGN.md §1.1のpow_worker_thread)。
 *
 * 背景: bm_pow_runは同期呼び出しで、呼び出し元スレッドをPoWが終わるまで止める。特に
 * object_sync.cのgetpubkey自応答はnetwork_epoll_threadを止めるため、その間すべての
 * ピア接続が停止していた(v4で実測20秒超、ポスト量子v5では期待141秒。DESIGN-PQ.md §8.4)。
 *
 * 形: ワーカースレッドは1本だけ立てる。bm_pow_run自体が内部で全コアへstride分割して
 * いるので、ワーカーを複数にしても過剰購読になるだけで総スループットは上がらない
 * (DESIGN.md §1.1の「pow_worker_thread × NumCPU」という記述が誤りだった件、§11項目38)。
 * ジョブは投入順に直列処理する。長いジョブ(v5 pubkey)が先行すると後続が待たされるが、
 * v1では優先度キューまでは作らない(既知の割り切り)。
 *
 * 当初の設計(DESIGN.md §1.2)はpow_request_queue/pow_result_queueの2本のbm_queue_tで
 * 結果を呼び出し元へ返す形だったが、現在の呼び出し元(Tier 1の3箇所)はどれも結果を
 * 待つ側がいない「撃ちっぱなし」なので、結果キューの代わりに完了コールバックを
 * ワーカースレッド上で呼ぶ形にした。dedupと上限のためにリストを走査する必要もあるので、
 * bm_queue_tではなく専用の連結リストを持つ。
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* dedupキーの最大長。getpubkey自応答のversion+stream+ripe(30byte)と、send_pipelineの
 * 'S'+msg_id(33byte、§11項目38 Tier 2)が収まる長さ。これを超えるキーを渡すと
 * submitは-1で拒否する(2026-11-03 Tier 2の実装中に、33byteのキーが黙って「キー無し」
 * 扱いになり再送のdedupが効いていなかったのをテストで見つけたため、黙って無視しない形にした) */
#define BM_POW_QUEUE_KEY_MAX 40

/*
 * 完了コールバック。PoWが終わるとワーカースレッド上で
 *   done(user_data, object, object_len, now)
 * が呼ばれる。objectは nonce(8byte BE) || payload で、所有権はコールバックへ移る
 * (コールバックがfreeする)。nowはワーカーがPoW完了時点で取った時刻(呼び出し側の関数の
 * 中でtime(NULL)を呼ばない、というCLAUDE.mdの方針に合わせてキュー側で取って渡す)。
 *
 * 受け付けたジョブがPoWされずに捨てられた場合(shutdownによる打ち切り・待ちジョブの破棄)は
 * object==NULL, object_len==0 で呼ばれる(ワーカー上とは限らず、shutdownを呼んだスレッドで
 * 呼ばれることもある)。user_dataの解放はいずれの場合もコールバックの責任。
 * 投入の時点で拒否した場合(bm_pow_queue_submitが0以外を返す)はdoneを呼ばない。
 */
typedef void (*bm_pow_done_fn)(void *user_data, unsigned char *object, size_t object_len, int64_t now);

struct bm_pow_job;

struct bm_pow_queue
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct bm_pow_job *head; /* 待ちジョブ(走行中のものは含まない) */
    struct bm_pow_job *tail;
    size_t pending;
    size_t max_pending;
    struct bm_pow_job *running; /* 走行中のジョブ(dedup判定用)。mutex下でのみ読み書きする */
    bool shutdown;
    atomic_bool cancel; /* 走行中のbm_pow_run_cancellableへ渡す */
    pthread_t thread;
    /* ワーカーが処理を終えたジョブ(cancelでの打ち切りを含む)の累計(テストの待ち合わせ用)。
     * submitでの拒否とshutdownでの待ちジョブ破棄は数えない。mutex下でのみ読み書きする */
    uint64_t completed;
};

/* 0で成功。max_pendingは「待ち」ジョブ数の上限(走行中の1本は数えない) */
int bm_pow_queue_init(struct bm_pow_queue *q, size_t max_pending);

/*
 * 走行中のPoWを打ち切り(cancel)、待ちジョブを全て破棄し(doneをobject==NULLで呼ぶ)、
 * ワーカースレッドをjoinする。以後のsubmitは-1を返す。bm_pow_queue_destroyの前に必ず呼ぶ。
 */
void bm_pow_queue_shutdown(struct bm_pow_queue *q);
void bm_pow_queue_destroy(struct bm_pow_queue *q);

/*
 * payload(nonce抜き、所有権はキューへ移る)のPoWジョブを投入する。
 *
 * key(NULL可、key_lenはBM_POW_QUEUE_KEY_MAX以下)を与えると、同じキーのジョブが待ち中または
 * 走行中ならPoWせずに破棄して1を返す。getpubkey自応答のように「同じ相手からの要求が
 * PoW完了前に重ねて届く」経路で、同じPoWを何本も積まないための仕組み(同期実装では
 * network_epoll_threadがPoW中に止まっていたので、後続の要求は応答キャッシュができてから
 * 処理されて自然に再利用されていた。非同期化でその暗黙の直列化が無くなるため明示的に要る)。
 * 例外として、doneの中(ワーカースレッド上)から投入した場合は走行中のジョブ(=今doneを
 * 呼ばれているジョブ自身)とのキー一致は見ない。多段のPoWで同じキーを次の段へ引き継げる
 * ようにするため(§11項目38 Tier 2、send_pipelineのack→msg)。待ち中のジョブとは比べる。
 *
 * 戻り値: 0=投入した(またはq==NULLで同期実行した)、1=dedupで破棄、-1=上限超過・
 * shutdown後・キーが長すぎるので破棄。0以外でもpayloadは解放されるが、doneは呼ばない
 * (user_dataは呼び出し側に残るので、呼び出し側が片付ける)。
 * §11 2026-11-03 Tier 2で変更: 以前は拒否のときもdoneをobject==NULLで同期的に呼んでいたが、
 * そうするとdoneの側では「投入時の拒否」(呼び出し元が戻り値を見て片付けたい)と
 * 「受け付けた後の破棄」(doneが片付けるべき)を見分けられない。スレッドで見分けようと
 * したら、shutdownの破棄もshutdownを呼んだスレッドで起きるため誤認し、破棄された送信の
 * 完了通知が失われてAPIの接続がsuspendされたまま残った(test_send_asyncで発覚)。
 *
 * q==NULLなら、その場(呼び出し元スレッド)でbm_pow_runを実行してdoneを呼ぶ
 * (テスト・CLI単体動作用。broadcast_queue==NULLならネットワークへ流さない、という
 * 既存の慣習と同じ考え方で、既存テストを同期完了の前提のまま動かせるようにする)。
 * その場合のnowは引数のnowを使う。
 */
int bm_pow_queue_submit(struct bm_pow_queue *q, unsigned char *payload, size_t payload_len, uint64_t target,
                        const unsigned char *key, size_t key_len, bm_pow_done_fn done, void *user_data,
                        int64_t now);

/* ワーカーが処理を終えたジョブの累計を返す(テストの待ち合わせ用、completedのdoc参照) */
uint64_t bm_pow_queue_completed_count(struct bm_pow_queue *q);

#endif /* BM_POW_QUEUE_H */
