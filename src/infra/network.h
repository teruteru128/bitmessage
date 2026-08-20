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

enum bm_fd_type
{
    BM_FD_CLIENT_SOCKET,
    BM_FD_SERVER_SOCKET,
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
};

/* epoll_wait ループ本体。DESIGN.md §1.1 network_epoll_thread のスレッド関数として使う。
 * argは struct bm_epoll_thread_args* (malloc済み、スレッド終了時にfreeされる) */
void *bm_network_epoll_thread(void *arg);

#endif /* BM_INFRA_NETWORK_H */
