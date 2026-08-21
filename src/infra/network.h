#ifndef BM_INFRA_NETWORK_H
#define BM_INFRA_NETWORK_H

/*
 * epollベースの接続管理。DESIGN.md §1.1 network_epoll_thread に対応。
 * 移植元: study/libstudy/src/bm_network.c, study/src/bm.c(PoCクライアント)
 *
 * 既知バグ修正(DESIGN.md §0): 移植元 bm.c は parse_message が NULL を返すケースで
 * 「データ不足」と「checksum不一致」を混同していた。ここでは protocol.h の
 * bm_parse_result を使い分岐を明確化している(bm_network_handle_readable内)。
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "protocol.h"

struct bm_peer_registry; /* peer_registry.h、循環includeを避けるため前方宣言のみ */

enum bm_fd_type
{
    BM_FD_CLIENT_SOCKET, /* outbound: 自分からconnect()した接続 */
    BM_FD_SERVER_SOCKET, /* inbound: BM_FD_LISTEN_SOCKETがaccept()した、相手からの接続
                          * (§11 Tor hidden service対応) */
    BM_FD_LISTEN_SOCKET, /* inbound接続を受け付けるlisten中のソケット自体。epoll_waitで
                          * readable(=accept可能)になった際、bm_network_epoll_threadは
                          * bm_network_handle_readableではなくaccept()ループを呼ぶ */
};

struct bm_fd_data
{
    enum bm_fd_type type;
    int fd;
    size_t size;
    size_t length;
    unsigned char *recv_buffer;
    struct sockaddr_storage local_addr;
    socklen_t local_len;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
};

/* コマンド受信時のコールバック。DESIGN.md §1.2 command_queue へ積む処理は
 * このコールバックの実装(infra/object.c等)側で行う想定 */
typedef void (*bm_command_handler_fn)(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data);

struct bm_fd_data *bm_fd_data_new(enum bm_fd_type type, int fd);
void bm_fd_data_free(struct bm_fd_data *data);

/*
 * §11 inbound接続(Tor hidden service)対応。bind_address:portでTCP listenする(SO_REUSEADDR、
 * backlog 16、O_NONBLOCK)。bind_addressは通常"127.0.0.1"を渡す想定(公開IPへの直接listenは
 * 意味が無い。到達可能にするのはTor hidden serviceの役目、DESIGN.md §8-10参照)。
 * 成功時listen中のfd、失敗時-1。
 */
int bm_network_listen(const char *bind_address, int port);

/*
 * §11 部分書き込み対策。fdへdataをlenバイト書き切るまで送る。peer_connector.cが
 * 接続確立後もO_NONBLOCKのままepollへ渡す設計のため、この接続へのwrite()は常に短い
 * 書き込み・EAGAINで返る可能性がある(1回のwrite()で全部送れることを仮定してはいけない)。
 * EAGAIN/EWOULDBLOCK時はtimeout_secを上限にselect()で書き込み可能になるのを待つ。
 * 成功時0、失敗時(相手の切断・タイムアウト・その他エラー)-1。
 *
 * 呼び出し元は2種類あり、要求するタイムアウトの長さが異なる:
 *   - network_epoll_thread(単一の共有スレッド、全接続のディスパッチを直列に処理する)上で
 *     呼ばれるもの(verack/pong返信、infra/object_sync.cのgetdata要求・object応答・
 *     infra/peer_registry.cのinv broadcast)は、ここでブロックすると他の全接続の処理も
 *     止まってしまうため、BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDSを渡すこと(詰まったpeer
 *     1本あたり最大でもこの秒数しか他接続をブロックしない)
 *   - peer_connector_thread自身のスレッド上で呼ばれるもの(bm_post_version)は、他接続の
 *     処理を巻き込まないため、BM_NETWORK_WRITE_TIMEOUT_LONG_SECONDS(接続確立自体の
 *     タイムアウト、CONNECT_TIMEOUT_SEC@peer_connector.cと同程度)を渡してよい
 */
#define BM_NETWORK_WRITE_TIMEOUT_SHORT_SECONDS 2
#define BM_NETWORK_WRITE_TIMEOUT_LONG_SECONDS 5
int bm_network_write_all(int fd, const unsigned char *data, size_t len, int timeout_sec);

int bm_reply_verack(struct bm_fd_data *conn);
int bm_reply_pong(struct bm_fd_data *conn);
int bm_post_version(int sock, const char *user_agent_str, int version,
                     const struct sockaddr_storage *peer_addr,
                     const struct sockaddr_storage *local_addr);

/*
 * fdから読めるだけ読み、受信バッファに追記した上でパース可能なメッセージを
 * 全て取り出して handler を呼ぶ。接続が閉じられたら1、エラーなら-1、
 * 正常(EAGAIN到達)なら0を返す。
 */
int bm_network_handle_readable(struct bm_fd_data *conn, bm_command_handler_fn handler, void *user_data);

/* bm_network_epoll_threadへ渡す引数。handler=NULLならdefault_dispatch(version/verack/ping等の
 * 最小限のハンドリング)を使う。pthread_createのarg用にmallocして渡す(スレッド側でfreeする) */
struct bm_epoll_thread_args
{
    int epfd;
    bm_command_handler_fn handler;
    void *user_data;
    struct bm_peer_registry *registry; /* NULL可(未使用ならレジストリ更新をスキップ) */
};

/* epoll_wait ループ本体。DESIGN.md §1.1 network_epoll_thread のスレッド関数として使う。
 * argは struct bm_epoll_thread_args* (malloc済み、スレッド終了時にfreeされる) */
void *bm_network_epoll_thread(void *arg);

#endif /* BM_INFRA_NETWORK_H */
