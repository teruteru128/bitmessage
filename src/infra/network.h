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

/* §11 2026-08-23発覚のバグ修正: IPv4/IPv6文字列(INET6_ADDRSTRLEN=46で足りる)だけでなく、
 * v3 onionアドレス(56文字base32+".onion"=62文字)も切り捨てずに保持できるサイズ。
 * peer_manager.hのbm_peer_entry.ip_address[64]と合わせている。logical_peer_ipや
 * bm_network_resolve_peer_ip_portの出力先バッファがこれより小さいと、onion peerの
 * アドレスが黙って途中で切り捨てられ、peers.dbの実際の行(フルの62文字)と一致しなくなり
 * rating/last_seen更新が0行ヒットのまま静かに失敗する(実際に発覚した不具合)。 */
#define BM_PEER_IP_STRLEN 64

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
    char logical_peer_ip[BM_PEER_IP_STRLEN]; /* 空文字列 = 未設定 */
    int logical_peer_port;
    /* §9 Dandelion++: 相手から受信したversion messageのservicesビットフィールド。
     * object_sync.cのversion受信処理が設定する(接続直後は0=未受信のまま)。
     * BM_SERVICE_NODE_DANDELION(protocol.h)のstem successor選定に使う。 */
    uint64_t services;
    /* §11 2026-08-23: inbound接続のアイドル/ハンドシェイクタイムアウト用。読み取り成功時
     * (bm_network_handle_readable)に更新される「最終活動時刻」。bm_fd_data_new時点の
     * 接続確立時刻で初期化する。keepalive ping送信時にも自己完結的に更新することで
     * (PyBitmessageのlastTxが読み書き両方で更新されるのと同じ効果を、pingという1箇所の
     * 書き込みだけで再現)、無応答の相手へping spamしてしまうのを防ぐ。 */
    int64_t last_activity;
    /* §11 2026-08-23: verack受信済み(=双方向のversion/verack交換が完了済み)かどうか。
     * object_sync.cのverack受信ブランチが立てる。inbound/outbound問わず、verack受信
     * 時点で相手も既にこちらのversionを受け取っている(既存のコメント参照)ため、
     * ここが正しい"fully established"判定点になる。0=未完了(既定)。 */
    int handshake_complete;
    /* §11 2026-08-23 backlog項目3: コマンドハンドラ(object_sync.c)が「このメッセージを
     * 処理した結果、この接続を切るべき」と判断した場合に立てるフラグ(例: 相手の
     * プロトコルバージョンがBM_MIN_PROTOCOL_VERSION未満)。ハンドラ自身はfdをcloseしたり
     * せず(registryからの除去・epoll登録解除・rating記録等の後始末はnetwork.c側に
     * 一元化されている、close_connection参照)、必要なerrorメッセージをconn->fdへ
     * 書き込んだ上でこのフラグだけ立てて返る。bm_network_handle_readableがハンドラ呼び出し
     * 直後にこのフラグを見て、切断が必要な通常の読み取りエラーと同じ経路(戻り値-1)へ
     * 合流させる。0=切断不要(既定)。 */
    int should_disconnect;
    /* §11 2026-08-23 backlog項目5: listConnections API(core/api_server.c)用。相手から
     * 受信したversion messageのuser agent文字列(malloc済み、NUL終端)。
     * object_sync.cのversion受信処理が設定する(接続直後・まだversion未受信の間はNULL)。
     * bm_fd_data_freeでfreeする。 */
    char *user_agent;
    /* §11 2026-08-23 backlog項目5(listConnections送受信バイト数)。この接続で実際に
     * 送信/受信したバイト数の累積(切断されるとこの接続ぶんは失われる、切断済み分も
     * 含めた累積はbm_network_get_statsの方を使う)。送信側はbm_network_write_allを
     * 直接呼ぶ箇所のうちconn(バイト数を積む先)を持っている呼び出し元だけが更新する
     * (peer_registry.cのbroadcast_invはdup()したfdへ書くだけでconnを持たないため対象外、
     * その分はbm_network_get_statsの全体累積にのみ計上される。ユーザーとの合意事項)。
     * 受信側はbm_network_handle_readableが読み取り成功のたびに一箇所で更新する。 */
    uint64_t bytes_sent;
    uint64_t bytes_received;
    /* §11 2026-08-26発覚: big inv(相手が知らない全objectのhash一覧)をverack受信直後に
     * 一括送信すると、相手(実測: PyBitmessage 0.6.3.2)の受信処理が追いつかずTCP受信
     * ウィンドウがゼロまで埋まり、最終的に相手からRSTで強制切断されることをtcpdumpで
     * 確認した(DESIGN-LOG.md参照)。object_sync.cのsend_big_invはbm_network_begin_big_inv
     * (このファイル参照)へ全hashの所有権を渡して最初の1chunkだけ即座に送り、残りは
     * ここへ保持したまま、bm_network_idle_sweepの巡回(既存の1秒間隔ポーリングに相乗り、
     * DandelionのreshuffleやPingのidle keepaliveと同じ方式)で少しずつ追加送信する。
     * pending_inv_hashes==NULLなら送信中の分割invなし。network_epoll_threadという
     * 単一スレッドの中でのみ触られるため排他制御はしない(peer_registry.cの既存コメントと
     * 同じ前提)。 */
    unsigned char (*pending_inv_hashes)[32]; /* malloc済み、全部送り終える/破棄時にfree */
    size_t pending_inv_total;
    size_t pending_inv_sent;
    int64_t pending_inv_last_chunk_time;
};

/*
 * §11 2026-08-23: inbound接続のレート制限(DoS対策、backlog項目2)。Tor hidden service経由の
 * inboundはaccept()で見える接続元IPが常にTorのローカル転送(127.0.0.1:<ephemeral>)になり、
 * 実際に相手ノードから「Too many connections from your IP」で拒否される場面を観測しているにも
 * 関わらずこちら側には対応する制限が無かった。生IPベースの制限はoriginally intended targetを
 * 区別できず機能しない(全接続が同一IPに見える)ため、IPに依存しない2種類の制限を設ける:
 * (1) 同時接続数の上限(BM_MAX_INBOUND_CONNECTIONS、bm_peer_registry_count_by_typeで判定)、
 * (2) 単位時間あたりのaccept数の上限(固定窓カウンタ、BM_INBOUND_ACCEPT_WINDOW_SECONDS秒
 * ごとにリセット)。どちらも超過時はaccept()自体は行った上で即座にcloseする
 * (listen backlogキューに溜め続けさせず次の接続試行にすぐ空きを渡すため。recv_buffer確保や
 * handshake処理は一切しない)。
 */
#define BM_MAX_INBOUND_CONNECTIONS 64
#define BM_INBOUND_ACCEPT_WINDOW_SECONDS 10
#define BM_INBOUND_ACCEPT_MAX_PER_WINDOW 20

struct bm_inbound_rate_limiter
{
    int64_t window_start;
    int count_in_window;
};

void bm_inbound_rate_limiter_init(struct bm_inbound_rate_limiter *rl);

/*
 * 呼ぶたびに今回のaccept 1件ぶんとして内部カウンタを進める。窓内の累積数が
 * BM_INBOUND_ACCEPT_MAX_PER_WINDOWを超えていなければ1(許可)、超えていれば0(拒否)を返す。
 * nowを明示引数に取ることで、テストが実際の壁時計待ちをせずに呼べる
 * (bm_network_idle_sweep等、このプロジェクト全体の慣習と同じ)。
 */
int bm_inbound_rate_limiter_allow(struct bm_inbound_rate_limiter *rl, int64_t now);

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
 * §11 2026-08-23発覚のバグ修正: ログ出力用に"host:port"文字列を組み立てる。hostに':'が
 * 含まれる場合(IPv6リテラル)はRFC 3986慣習に従い"[host]:port"の形にbracketで囲む
 * (囲わないとIPv6アドレス自体の':'区切りとホスト/ポート境界の':'が区別できない)。
 * ホスト名やIPv4、.onionアドレスには':'が含まれないため素通しで"host:port"になる。
 * out_lenはINET6_ADDRSTRLEN+3(bracket 2つ+終端)以上を推奨。
 */
void bm_network_format_host_port(const char *host, int port, char *out, size_t out_len);

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

/*
 * §11 2026-08-23 backlog項目5: プロセス起動時からの送受信バイト数の全体累積
 * (切断済みの接続ぶんも含む、mutex保護)。bm_network_write_all成功時/
 * bm_network_handle_readableの読み取り成功時に、呼び出し元(fdだけを持ちconnを
 * 持たない箇所も含めた"経路を問わない"全ての送受信)から更新される。
 * core/api_server.cのgetNetworkStats APIが読む。
 */
void bm_network_get_stats(uint64_t *out_bytes_sent, uint64_t *out_bytes_received);

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
    /* §11 2026-08-23: inbound accept数のレート制限用状態。main.cが起動時に
     * bm_inbound_rate_limiter_initで初期化してから渡すこと(mallocでは自動でゼロ初期化
     * されない)。listenソケットを使わない(=inbound無効)構成のargsでは未使用のまま無害。 */
    struct bm_inbound_rate_limiter inbound_rate_limiter;
};

/* epoll_wait ループ本体。DESIGN.md §1.1 network_epoll_thread のスレッド関数として使う。
 * argは struct bm_epoll_thread_args* (malloc済み、スレッド終了時にfreeされる) */
void *bm_network_epoll_thread(void *arg);

/* §11 2026-08-23: PyBitmessage本家(network/connectionpool.pyのメインループ)に
 * 合わせた値。ヘッダで公開しているのは、テストが「境界値の前後」を実際の値で検証
 * できるようにするため(bm_network_idle_sweepのdocも参照)。 */
#define BM_HANDSHAKE_TIMEOUT_SECONDS 20
#define BM_IDLE_PING_TIMEOUT_SECONDS 300
/* §11 2026-08-26: big invのペーシング用(struct bm_fd_dataのdoc参照)。1chunkあたり
 * BM_BIG_INV_CHUNK_SIZE件(32byte/件、1000件で約32KB)、chunk間はBM_BIG_INV_CHUNK_
 * INTERVAL_SECONDS秒空ける。tcpdumpの実測(DESIGN-LOG.md)では260KB超を無間隔で送ると
 * 相手のTCP受信ウィンドウが数秒でゼロまで埋まっていたため、それより十分小さい単位・
 * 間隔にしている。 */
#define BM_BIG_INV_CHUNK_SIZE 1000
#define BM_BIG_INV_CHUNK_INTERVAL_SECONDS 1

/*
 * §11 2026-08-23: inbound接続のアイドル/ハンドシェイクタイムアウト+keepalive ping送信
 * (PyBitmessage本家のnetwork/connectionpool.pyメインループを移植)。args->registryに
 * 登録済みの全接続を走査し、handshake_complete==0でBM_HANDSHAKE_TIMEOUT_SECONDS以上
 * 無活動なら切断(rating失敗記録込み、outboundのみ)、handshake_complete==1で
 * BM_IDLE_PING_TIMEOUT_SECONDS以上無活動ならpingを送信する。nowを明示引数に取ることで
 * テストが実際の壁時計待ちをせずに呼べる(bm_peer_manager_cleanup等と同じ慣習)。
 * bm_network_epoll_threadが自身のepoll_waitタイムアウトのたびに呼ぶ。
 */
void bm_network_idle_sweep(struct bm_epoll_thread_args *args, int64_t now);

/*
 * §11 2026-08-26: object_sync.cのsend_big_invから呼ぶ。hashes(malloc済み、count件)の
 * 所有権はこの関数へ渡り(呼び出し元は以後freeしない)、conn->pending_inv_*へ保存される。
 * 最初の1chunk(BM_BIG_INV_CHUNK_SIZE件まで)だけこの場でconn->fdへ即座に送り、count が
 * それ以下ならその場で送り切ってhashesもfreeする。残りがあればbm_network_idle_sweepが
 * 後続チャンクを1秒間隔で送る(struct bm_fd_dataのdoc参照)。書き込み失敗時は残りを諦めて
 * 破棄する(詰まった接続への再試行で単一スレッドの他接続処理を妨げないため)。
 */
void bm_network_begin_big_inv(struct bm_fd_data *conn, unsigned char (*hashes)[32], size_t count, int64_t now);

/*
 * §11 inbound接続(Tor hidden service)対応。listenソケットがreadable(=accept可能)になった際に
 * 呼ぶ。EAGAINになるまで(=溜まっている分を全部)accept()し、BM_MAX_INBOUND_CONNECTIONS
 * (同時接続数)/BM_INBOUND_ACCEPT_MAX_PER_WINDOW(単位時間あたりaccept数)のいずれかを
 * 超える分は即座にcloseする(2026-08-23 backlog項目2、上記の各定数のdoc参照)。
 * 上限内の接続はBM_FD_SERVER_SOCKETとしてepoll登録・registry登録する。inbound接続はこの
 * 時点ではまだ相手のversionを受け取っていないため、自分からは何も送らずに待つ(相手からの
 * versionを受けてobject_sync.cが自分のversionを送り返す、object_sync_dispatch参照)。
 * nowはbm_inbound_rate_limiter_allowへそのまま渡す(テスト容易性、他の同種APIと同じ慣習)。
 * ヘッダで公開しているのはtest_idle_sweep.cと同様、テストがepollスレッド自体
 * (無限ループ)を起動せず直接呼べるようにするため。
 */
void bm_network_handle_accept(struct bm_epoll_thread_args *args, struct bm_fd_data *listener, int64_t now);

#endif /* BM_INFRA_NETWORK_H */
