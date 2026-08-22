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

#include <sqlite3.h>
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
    /* getpeername()で取得した、実際にOSレベルでTCP接続している相手。SOCKS5プロキシ
     * (Tor等)経由の接続では、これはプロキシ自身のアドレス(例: 127.0.0.1:9050)になる
     * ことに注意(§11 2026-08-22発覚のバグ: プロキシ越しの本来の宛先とは異なるため、
     * peer_manager.cのrating更新にこれを使うと常にDB上のどの行にも一致しない127.0.0.1:9050
     * 宛のUPDATEになり、0行ヒットのまま静かに失敗し続けていた)。 */
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    /* §11 2026-08-22発覚のバグ修正: SOCKS5プロキシ越しでも常に正しいのは、
     * peer_connector.cが接続先として選んだ本来のip:port(candidates[i].ip_address/port)
     * だけ。BM_FD_CLIENT_SOCKET(outbound)接続についてはpeer_connector.cが
     * bm_fd_data_new直後に明示的にここへ設定する(直接プロキシを使わない場合もpeer_addrと
     * 冗長ながら一致する値を入れる)。BM_FD_SERVER_SOCKET(inbound)やpeer_connector.c以外の
     * 経路で作られたBM_FD_CLIENT_SOCKET(テスト等)ではlogical_peer_ip[0]=='\0'のまま
     * (未設定)であり、この場合は呼び出し側がpeer_addr由来のip:portへフォールバックする
     * (network.c/object_sync.cのrating記録処理参照)。 */
    char logical_peer_ip[46]; /* INET6_ADDRSTRLEN相当。空文字列 = 未設定 */
    int logical_peer_port;
};

/* コマンド受信時のコールバック。DESIGN.md §1.2 command_queue へ積む処理は
 * このコールバックの実装(infra/object.c等)側で行う想定 */
typedef void (*bm_command_handler_fn)(struct bm_fd_data *conn, const struct bm_message *msg, void *user_data);

struct bm_fd_data *bm_fd_data_new(enum bm_fd_type type, int fd);
void bm_fd_data_free(struct bm_fd_data *data);

/* addr(sockaddr_storage)からip文字列とportを取り出す(DNS引きはせず数値表記のみ)。
 * bm_peer_manager_record_resultにip/portを別々の引数で渡す必要がある呼び出し元
 * (network.c自身のbm_network_epoll_thread、object_sync.cのverack/version受信時の
 * success記録)で共有するために公開している。out_ipはINET6_ADDRSTRLEN以上のバッファを渡すこと。
 * addr->ss_familyがAF_INET/AF_INET6のいずれでもなければout_ip[0]='\0'、*out_port=0のまま。 */
void bm_network_extract_ip_port(const struct sockaddr_storage *addr, char *out_ip, size_t out_ip_len,
                                 int *out_port);

/*
 * §11 2026-08-22発覚のバグ修正: peer_manager.cのrating更新(bm_peer_manager_record_result)に
 * 使うべき「本来の接続先」ip:portを解決する。conn->logical_peer_ip(peer_connector.cが
 * BM_FD_CLIENT_SOCKET作成時に設定する、SOCKS5プロキシの有無に関わらず正しい値)が
 * 設定済みならそれを優先し、未設定(空文字列、テストや将来の別経路でのBM_FD_CLIENT_SOCKET
 * 作成等)ならconn->peer_addr(getpeername)から素直に抽出したip:portへフォールバックする
 * (直接接続なら正しいが、SOCKS5経由だとプロキシのアドレスになってしまう点に注意。
 * フォールバックはあくまで「logical_peer_ipが無いよりはまし」という位置づけ)。
 * network.cのbm_network_epoll_thread(切断時のfailure記録)とobject_sync.cの
 * record_outbound_success(verack/version受信時のsuccess記録)の両方で共有する。
 */
void bm_network_resolve_peer_ip_port(const struct bm_fd_data *conn, char *out_ip, size_t out_ip_len,
                                      int *out_port);

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
    /* §11 outbound接続が切断された際にpeer_manager.cのratingへ失敗を反映するために使う
     * (2026-08-22発覚のバグ修正: connect()+version送信が成功した時点でpeer_connector.cが
     * 既にrating+0.1を記録するが、直後にECONNRESET等で切断されてもそれまでratingへ
     * フィードバックする経路が無く、"接続はできるが即座に切れる"peerのratingが下がらず
     * 際限なく再選出され続けていた)。NULL可(未使用ならrating更新をスキップ、テスト等)。 */
    sqlite3 *peers_db;
};

/* epoll_wait ループ本体。DESIGN.md §1.1 network_epoll_thread のスレッド関数として使う。
 * argは struct bm_epoll_thread_args* (malloc済み、スレッド終了時にfreeされる) */
void *bm_network_epoll_thread(void *arg);

#endif /* BM_INFRA_NETWORK_H */
