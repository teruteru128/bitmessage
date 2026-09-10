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
 * 払い出す単調増加値)も一致した場合のみ、conn->pending_eviction(network.hのdoc参照)を
 * 立てる設計。理由: broadcast_inv側がconnポインタを捕まえた後、ロックを解放してから
 * writeするまでの間に、別スレッド(network_epoll_thread)がread側検知で先にclose_connection
 * 済み+free()し、同じアドレスへ別の新しいconnが割り当てられている(ABA問題)可能性がある。
 * ポインタ一致だけで判定すると、無関係な生きている新しい接続を誤って破壊してしまう。
 *
 * §11 2026-09-09発覚のバグ修正: 以前はgeneration一致時にこの関数自身がその場でclose・
 * bm_fd_data_freeまで行っていたが、これはnetwork_epoll_thread側がまさに同じconnの
 * epollイベントを処理中の場合と競合し、二重close・二重freeを引き起こしうる欠陥だった
 * (本番daemonがdouble free or corruptionでSIGABRTした事故、DESIGN.md参照)。generation
 * 照合は「このconnがまだregistryに実在するか」は保証するが「他スレッドが今まさにこの
 * メモリへアクセスしていないか」は保証できないため、実際のfree()は必ずnetwork_epoll_
 * thread単一スレッド内(network.cのidle_sweep_one)に一元化した。この変更に伴い、
 * evict_if_current自体はもうconnをfree・closeせず、pending_evictionフラグを立てる
 * だけになった。本テストはこの安全機構(ポインタ+generation一致時のみフラグを立てる、
 * 不一致/未登録なら一切dereferenceせず何もしない、フラグを立てるだけでfree/closeは
 * しない)を検証する。
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

    /* --- 2. generation不一致なら、ポインタが登録済みでもフラグを立ててはいけない
     * (ABA問題対策の核心)。conn1->generationを故意に書き換えて「本来のconn1とは別の
     * generationを持つ新しい接続が同じアドレスに割り当てられた」状況を再現する
     * (実際のmalloc再利用タイミングに依存させず決定的にテストするため)。 --- */
    conn1->generation = 999;
    int rc_mismatch = bm_peer_registry_evict_if_current(&reg, conn1, 1 /* 古いgeneration */);
    CHECK(rc_mismatch == 0, "generation mismatch must not mark for eviction (would destroy an unrelated live connection)");
    CHECK(bm_peer_registry_count(&reg) == 2, "registry must still contain both connections after a rejected evict");
    CHECK(conn1->pending_eviction == 0, "generation mismatch must not set pending_eviction");

    /* --- 3. ポインタ+generationが一致すればpending_evictionが立ち、1を返すこと。
     * §11 2026-09-09発覚のバグ修正後: この関数自身はもうconnをfree/closeしない
     * (network.hのconn->pending_evictionのdoc、double free事故の経緯参照)。実際の
     * close_connectionはnetwork_epoll_thread側(network.cのidle_sweep_one)が担当するため、
     * ここではフラグが立つこと・registryにはまだ残ること・connがdereference可能な
     * ままであることを検証する。conn1は正しいgeneration(999、上で書き換えた値)を渡す。 --- */
    int rc_ok = bm_peer_registry_evict_if_current(&reg, conn1, 999);
    CHECK(rc_ok == 1, "matching conn+generation must set pending_eviction");
    CHECK(conn1->pending_eviction == 1, "pending_eviction must be set after a successful match");
    CHECK(bm_peer_registry_count(&reg) == 2, "registry must NOT shrink here (actual close/free is network_epoll_thread's job)");

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
    CHECK(bm_peer_registry_count(&reg) == 1, "registry should contain only conn1 after removing conn2");

    /* uintptr_t経由の変数追跡切り離しだけではRelease(-O2)最適化下でGCCが追跡を復元し
     * 再度-Wuse-after-freeを出すことがあるため、このテストの意図(絶対にdereferenceされない
     * ことの検証)を壊さない範囲でこの1行だけ警告を抑制する。-Wuse-after-freeはGCC固有の
     * 警告(clangには存在しない)なので、__clang__を明示的に除外する
     * (でないとclangで「未知の警告オプション」自体が新たな警告になる)。 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuse-after-free"
#endif
    int rc_not_found = bm_peer_registry_evict_if_current(&reg, (struct bm_fd_data *)conn2_addr, conn2_generation);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
    CHECK(rc_not_found == 0, "evicting an already-removed connection must return 0 without touching it");

    /* conn1はpending_evictionが立ったままだが、実際のclose/freeはこのテストの対象外
     * (network_epoll_thread側、tests/test_network_idle_sweep_pending_eviction.c等で検証)
     * なので、ここでは自前でfree()して後始末する(fd=-1なのでclose(-1)は無害)。 */
    bm_peer_registry_remove(&reg, conn1);
    free(conn1);

    bm_peer_registry_destroy(&reg);

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
