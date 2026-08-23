#ifndef BM_INFRA_PROTOCOL_H
#define BM_INFRA_PROTOCOL_H

/*
 * P2Pメッセージ(24byteヘッダ + payload)のパース/生成。DESIGN.md §5.0共通ヘッダとは別で、
 * こちらは message/version/verack/addr/inv/ping/pong など「ノード間の会話」レベルのメッセージ。
 * 移植元: study/libstudy/src/bm_protocol.c, bm_network.c
 *
 * 既知バグ修正(DESIGN.md §0): 移植元 bm.c は parse_message が NULL を返した際に
 * 「ヘッダ未着(データ不足)」と「checksum不一致(破損データ)」を区別できず、
 * 呼び出し側で msg 経由の未定義動作を招いていた。ここでは bm_parse_result で
 * 両者を明確に分離する。
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define BM_MESSAGE_HEADER_SIZE 24

/*
 * §11 DoS上限の見直し。ヘッダのlengthフィールドは32bit(理論上最大約4GiB)だが、そのまま
 * 信用すると悪意あるpeerが巨大な値を申告するだけで受信側に(実データが届く前から)無制限に
 * バッファを確保させられてしまう(bm_parse_messageがBM_PARSE_INCOMPLETEを返し続け、
 * infra/network.cの受信バッファがlengthに追いつくまでrealloc doublingし続けるため)。
 * この実装で正当に流通しうる最大のメッセージ(addr/inv、BM_MAX_INVENTORY_ITEMS=50000件、
 * object_sync.c参照)はaddrで約1.9MiBなので、十分な余裕を持たせて4MiBを上限とする。
 * これを超える申告はbm_parse_messageの時点でBM_PARSE_MESSAGE_TOO_LARGEとして拒否し、
 * 呼び出し側(infra/network.c)は該当接続を切断する(部分的に受信済みの巨大な偽データを
 * 1byteずつresyncしようとするのもコスト増になるため、resyncはせず即切断する)。
 */
#define BM_MAX_MESSAGE_LENGTH (4u * 1024u * 1024u)

/* 現在有効なmagic bytes(既定mainnet)。bm_protocol_set_testnetで切り替える。
 * mainnet=0xE9BEB4D9, testnet=0xFB110907(PyBitmessage protocol.py準拠)。 */
extern unsigned char bm_magicbytes[4];
extern const unsigned char bm_empty_payload_checksum[4];

/* testnetモードのon/off。bm_magicbytesを書き換える(プロセス全体で1つ、mainnet/testnet同時稼働は
 * 想定しない)。以後の送受信メッセージは新しいmagic bytesで扱われる。 */
void bm_protocol_set_testnet(int enabled);
int bm_protocol_is_testnet(void);

struct bm_message
{
    char command[12];
    uint32_t length;
    uint32_t checksum;
    unsigned char *payload; /* length byte、length==0ならNULL */
};

/* §9 Dandelion++。version messageのservicesビットフィールドで対応ピアを識別する
 * (PyBitmessageのprotocol.py準拠)。v1(Stage 1)時点では自分のversion messageの
 * servicesにこのビットを立てない(=stem対応ピアとして名乗らない、DESIGN.md §9.2)。 */
#define BM_SERVICE_NODE_DANDELION 8

/* §11 2026-08-23 backlog項目3: 互換性チェックできる最低プロトコルバージョン。
 * PyBitmessage(`network/bmproto.py`の`peerValidityChecks`)がremoteProtocolVersion<3の
 * 相手を強制切断しているのに合わせた(このプロジェクト自身も常にversion=3で送信している、
 * bm_post_version参照)。 */
#define BM_MIN_PROTOCOL_VERSION 3

/* §11 2026-08-23 backlog項目4: version messageのtimestampが自分の時計とどれだけ
 * ずれていれば拒否するか(秒)。PyBitmessage(`protocol.py`の`MAX_TIME_OFFSET`)に
 * 合わせた(1時間)。 */
#define BM_MAX_TIME_OFFSET_SECONDS 3600

struct bm_version_message
{
    uint32_t version;
    uint64_t services;
    uint64_t timestamp;
    unsigned char addr_recv[26];
    unsigned char addr_from[26];
    uint64_t nonce;
    char *user_agent;
    size_t stream_numbers_len;
    uint64_t *stream_numbers;
};

struct bm_address_info
{
    uint64_t time;
    uint32_t stream;
    uint64_t services;
    unsigned char ip[16];
    uint16_t port;
};

struct bm_addr_message
{
    uint64_t count;
    struct bm_address_info *addresses;
};

struct bm_inventory_message
{
    uint64_t count;
    unsigned char (*items)[32]; /* object hash 32byteの配列 */
};

enum bm_parse_result
{
    BM_PARSE_OK,
    BM_PARSE_INCOMPLETE,        /* データ不足。追加受信を待つ */
    BM_PARSE_BAD_CHECKSUM,      /* checksum不一致。このメッセージは破棄しresyncが必要 */
    BM_PARSE_BAD_MAGIC,         /* magic bytes不一致(mainnet/testnet取り違え等)。1byteスキップしてresync */
    BM_PARSE_MESSAGE_TOO_LARGE, /* §11 lengthがBM_MAX_MESSAGE_LENGTHを超える。resyncせず即切断 */
};

/*
 * data[0..data_len) の先頭からメッセージを1個パースする。
 * OK時: *out_msg にmalloc済みの構造体、*out_consumed に消費したバイト数(24+length)を設定
 * INCOMPLETE時: 何もしない(呼び出し側は追加受信を待つ)
 * BAD_CHECKSUM時: *out_consumed に 24+length(スキップすべきバイト数)を設定
 * MESSAGE_TOO_LARGE時: *out_consumedは設定しない(呼び出し側は接続を切断すること、§11)
 */
enum bm_parse_result bm_parse_message(const unsigned char *data, size_t data_len,
                                       struct bm_message **out_msg, size_t *out_consumed);
void bm_free_message(struct bm_message *msg);

void bm_encode_network_address(unsigned char addr[26], const struct sockaddr_storage *local_addr);
void bm_encode_time_and_stream(unsigned char *addr, uint64_t time, uint32_t stream);

void bm_parse_version_message(const unsigned char *payload, size_t payload_len,
                               struct bm_version_message *out_msg);
void bm_free_version_message(struct bm_version_message *msg);

size_t bm_version_message_size(const char *user_agent_str);
size_t bm_version_payload_size(const char *user_agent_str);
unsigned char *bm_create_version_payload(unsigned char *out, const char *user_agent_str, int version,
                                          const struct sockaddr_storage *peer_addr,
                                          const struct sockaddr_storage *local_addr);
/* malloc済みの完成した version メッセージ(ヘッダ込み)を返す。*out_len に全長を設定 */
unsigned char *bm_new_version_message(const char *user_agent_str, int version,
                                       const struct sockaddr_storage *peer_addr,
                                       const struct sockaddr_storage *local_addr,
                                       size_t *out_len);

int bm_parse_addr_message(const unsigned char *payload, size_t payload_len,
                           struct bm_addr_message *out_msg);
void bm_free_addr_message(struct bm_addr_message *msg);

/*
 * §11 2026-08-23: bm_parse_addr_messageと対称のエンコーダ(varint(count) || entry(38byte)*count)。
 * bm_create_inventory_messageと同じ流儀で、"addr"コマンドのヘッダまで含めた完成済みパケット
 * (malloc済み、呼び出し側でfree)を返す。*out_lenへ全長を設定する。countが0の場合はNULLを
 * 返す(空のaddrメッセージは送る意味が無いため、呼び出し側で判定)。
 */
unsigned char *bm_create_addr_message(const struct bm_address_info *addresses, size_t count, size_t *out_len);

int bm_parse_inventory_message(const unsigned char *payload, size_t payload_len,
                                struct bm_inventory_message *out_msg);
void bm_free_inventory_message(struct bm_inventory_message *msg);

/* 完成した24byteヘッダ+payloadのメッセージをmallocして返す(§6.1のCreatePacket相当) */
unsigned char *bm_create_packet(const char *command, const unsigned char *payload,
                                 size_t payload_len, size_t *out_len);

/* inv/getdata共通のペイロード(varint(count)||hash(32byte)*count)を持つメッセージを作る。
 * commandには"inv"または"getdata"を渡す。完成メッセージ(24byteヘッダ込み)をmallocして返す */
unsigned char *bm_create_inventory_message(const char *command, const unsigned char (*hashes)[32],
                                            size_t count, size_t *out_len);

/*
 * §11 2026-08-23 backlog項目3: object_sync.cの受信側パース処理(errorメッセージの
 * ワイヤーフォーマットに関するコメント参照)と対称のエンコーダ。
 * fatal(varint: 0=Warning, 1=Error, 2=Fatal/接続を切る) || banTime(varint) ||
 * vector(varstr、常に空文字列固定。相手のprotocol version不足のような接続全般への
 * 苦情ではobjectのhashを指す意味が無いため) || errorText(varstr)。
 * 完成メッセージ(24byteヘッダ込み)をmallocして返す(呼び出し側でfree)、*out_lenへ全長を設定。
 */
unsigned char *bm_create_error_message(uint64_t fatal, uint64_t ban_time, const char *error_text, size_t *out_len);

#endif /* BM_INFRA_PROTOCOL_H */
