/*
 * §11 2026-09-05: bm_peer_registry_evict_if_currentのテスト。
 *
 * 経緯: 本番daemonのログで「[peer_registry] failed to send inv to fd=N(write: Broken pipe)」
 * が数分おきに繰り返し出ていた調査から、ハンドシェイク未完了のinbound接続が何時間も
 * peer_registryに残り続けるリークが見つかった(read側のepoll検知に依存するidle_sweepの
 * ハンドシェイクタイムアウトが、何らかの理由で効かない接続が存在する)。read側検知に
 * 依存しない独立した安全網として、bm_peer_registry_broadcast_inv(object_sync_broadcast_
 * threadというnetwork_epoll_threadとは別スレッドから呼ばれる)がwrite失敗を検知した接続を
 * 能動的に除去するようにした(bm_peer_registry_evict_if_current)。
 *
 * このevict_if_currentは、conn(ポインタ)だけでなくconn->generation(bm_peer_registry_add時に
 * 払い出す単調増加値)も一致した場合のみ実際に除去(registryから外す・close・
 * bm_fd_data_free)する設計。理由: broadcast_inv側がconnポインタを捕まえた後、ロックを
 * 解放してからwriteするまでの間に、別スレッド(network_epoll_thread)がread側検知で先に
 * close_connection済み+free()し、同じアドレスへ別の新しいconnが割り当てられている
 * (ABA問題)可能性がある。ポインタ一致だけで除去すると、無関係な生きている新しい接続を
 * 誤って破壊してしまう。本テストはこの安全機構そのもの(ポインタ+generation一致時のみ
 * 除去、不一致/未登録なら一切dereferenceせず何もしない)を検証する。
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/infra/network.h"
#include "../src/infra/peer_registry.h"

static int failures = 0;

#define CHECK(cond, msg)                                                    \
    do                                                                      \
    {                                                                       \
        if (!(cond))                                                        \
        {                                                                   \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

static struct bm_fd_data *new_dummy_conn(void)
{
    /* bm_fd_data_free(recv_buffer/user_agent/pending_inv_hashesをfreeする)を安全に通すため、
     * bm_fd_data_newと同様callocでヒープ確保する(NULL初期化されるのでfree(NULL)は無害)。
     * fdは実ソケットを使わず-1のまま(close(-1)はEBADFで失敗するだけで安全、
     * このテストの関心はfd自体ではなくregistryのポインタ+generation照合ロジック)。 */
    struct bm_fd_data *conn = calloc(1, sizeof(*conn));
    conn->type = BM_FD_SERVER_SOCKET;
    conn->fd = -1;
    return conn;
}

int main(void)
{
    struct bm_peer_registry reg;
    bm_peer_registry_init(&reg);

    /* --- 1. generationはbm_peer_registry_addのたびに1から単調増加すること --- */
    struct bm_fd_data *conn1 = new_dummy_conn();
    bm_peer_registry_add(&reg, conn1);
    CHECK(conn1->generation == 1, "first registration should get generation 1");

    struct bm_fd_data *conn2 = new_dummy_conn();
    bm_peer_registry_add(&reg, conn2);
    CHECK(conn2->generation == 2, "second registration should get generation 2 (monotonic)");

    /* --- 2. generation不一致なら、ポインタが登録済みでも除去してはいけない(ABA問題対策の核心)。
     * conn1->generationを故意に書き換えて「本来のconn1とは別のgenerationを持つ新しい接続が
     * 同じアドレスに割り当てられた」状況を再現する(実際のmalloc再利用タイミングに依存させず
     * 決定的にテストするため)。 --- */
    conn1->generation = 999;
    int rc_mismatch = bm_peer_registry_evict_if_current(&reg, conn1, 1 /* 古いgeneration */);
    CHECK(rc_mismatch == 0, "generation mismatch must not evict (would destroy an unrelated live connection)");
    CHECK(bm_peer_registry_count(&reg) == 2, "registry must still contain both connections after a rejected evict");

    /* --- 3. ポインタ+generationが一致すれば除去・close・freeされ、1を返すこと。
     * conn1は正しいgeneration(999、上で書き換えた値)を渡せば除去される。 --- */
    int rc_ok = bm_peer_registry_evict_if_current(&reg, conn1, 999);
    CHECK(rc_ok == 1, "matching conn+generation must be evicted");
    CHECK(bm_peer_registry_count(&reg) == 1, "registry count must drop by one after a successful evict");
    /* conn1は内部でfree済みなので、以後は一切参照しない(ここでのCHECK群がまさにそれの検証)。 */

    /* --- 4. 既にregistryから外れている(=別経路で先に片付いた)connを渡すと、0を返し
     * dangling pointerには一切触れない(dereferenceしない)こと。conn2をbm_peer_registry_remove
     * (close/freeしない通常除去)で外した後、こちらで直接freeし、以後そのアドレスは
     * 「他人の何か」かもしれない前提でテストする。evict_if_currentがconn2を配列中に
     * 見つけられなければ、conn2->generationへは一切アクセスしないはずなので安全。 --- */
    uint64_t conn2_generation = conn2->generation;
    bm_peer_registry_remove(&reg, conn2);
    /* free()後にconn2そのものを引数へ渡すと-Wuse-after-freeで警告になる(ビルド時警告0件必須、
     * CLAUDE.md)。ここでは意図的に「free済みアドレスの値」だけを渡す(dereferenceは絶対に
     * 発生しないはず、というのがこのテストの検証対象そのもの)ため、uintptr_t経由で
     * コンパイラの use-after-free 変数追跡を切り離す。 */
    uintptr_t conn2_addr = (uintptr_t)conn2;
    free(conn2);
    CHECK(bm_peer_registry_count(&reg) == 0, "registry should be empty after removing the last connection");

    int rc_not_found = bm_peer_registry_evict_if_current(&reg, (struct bm_fd_data *)conn2_addr, conn2_generation);
    CHECK(rc_not_found == 0, "evicting an already-removed connection must return 0 without touching it");

    bm_peer_registry_destroy(&reg);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
