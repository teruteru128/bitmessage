#ifndef BM_CORE_MESSAGES_STORE_H
#define BM_CORE_MESSAGES_STORE_H

/* messages.db(§2.4)の操作。 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

int bm_messages_store_init_schema(sqlite3 *db);

/* §11 再送(resend)ロジックの既定パラメータ。初回送信からBM_RESEND_INITIAL_INTERVAL_SECONDS
 * 後にackが届いていなければ再送し、以後は間隔を倍々にする(2^resend_count倍)。
 * BM_RESEND_MAX_ATTEMPTS回再送してもackが届かなければ諦める(以後resendの対象にしない、
 * PyBitmessageの終わりなき再送よりシンプルなv1簡略化)。 */
#define BM_RESEND_INITIAL_INTERVAL_SECONDS (4 * 60 * 60)
#define BM_RESEND_MAX_ATTEMPTS 5

/*
 * inboxへ1件挿入する(trial_decrypt.cから呼ばれる)。msg_idはobjectのinventory hash(32byte)。
 * 既に同じmsg_idがあれば何もしない(重複配送への耐性)。成功時0。
 */
int bm_messages_store_insert_inbox(sqlite3 *db, const unsigned char msg_id[32],
                                    const char *to_address, const char *from_address,
                                    const char *subject, const char *body,
                                    int64_t received_time);

/*
 * sentへ1件挿入/更新する(send_pipeline.cから呼ばれる)。msg_id(32byteランダムID、送信試行を
 * 安定して指す。inboxのmsg_id=inventory hashとは別概念)をキーにUPSERTする: 新規送信なら
 * INSERT(resend_count=0)、再送(既存msg_idを再利用した呼び出し)ならUPDATEしてresend_countを
 * 1増やす。ack_dataはbm_build_ack_objectで作ったackobjectの生バイト列(§5.5、再送のたびに
 * 新しい値で上書きされる)。next_resend_timeはこの時刻を過ぎてもack未着なら次に再送対象になる
 * (呼び出し側が§11の間隔倍々ルールに従って計算して渡す)。成功時0。
 */
int bm_messages_store_insert_sent(sqlite3 *db, const unsigned char msg_id[32],
                                   const unsigned char *ack_data, size_t ack_data_len,
                                   const char *to_address, const char *from_address,
                                   const char *subject, const char *body,
                                   const char *status, int ack_stealth_level,
                                   int64_t sent_time, int64_t ttl, int64_t next_resend_time);

/*
 * §5.5: 受信したobjectのinventory hash(bm_inventory_hash)がsentテーブルのいずれかの行の
 * ack_dataから計算したinventory hashと一致すれば、その行のstatusを'ackreceived'へ更新する
 * (object_sync_thread から呼ばれる)。ack_dataは既にPoW nonce込みの完全なobjectバイト列
 * (send_pipeline.cが格納する)なので、そのままhashを取り直して比較すればよい。
 * 一致して更新できたら0、該当なし/既にackreceived済みなら非0を返す。
 */
int bm_messages_store_try_mark_ack_received(sqlite3 *db, const unsigned char received_hash[32]);

struct bm_sent_resend_candidate
{
    unsigned char msg_id[32];
    char to_address[40];
    char from_address[40];
    char *subject; /* malloc */
    char *body;    /* malloc */
    int ack_stealth_level;
    int64_t ttl;
    int resend_count; /* 更新前(現在)の値。次回next_resend_time計算に+1して使う */
};

/*
 * status!='ackreceived' かつ status!='msgsentnoackexpected'(§11 2026-08-31 自分自身宛/chan宛は
 * ackが返ってこないため再送しても無駄、PyBitmessage本家class_singleCleaner.py準拠で除外)
 * かつ next_resend_time<=now かつ resend_count<max_attemptsな行を一覧する(object_sync_threadの
 * 再送チェックから呼ばれる)。成功時0、*out_countに件数を設定する(0件でも成功)。呼び出し側で
 * bm_sent_resend_candidate_list_freeすること。
 */
int bm_messages_store_list_resend_candidates(sqlite3 *db, int64_t now, int max_attempts,
                                              struct bm_sent_resend_candidate **out_list, size_t *out_count);
void bm_sent_resend_candidate_list_free(struct bm_sent_resend_candidate *list, size_t count);

#define BM_MESSAGES_ADDRESS_MAX 40
#define BM_MESSAGES_FOLDER_MAX 16

struct bm_inbox_message
{
    unsigned char msg_id[32];
    char to_address[BM_MESSAGES_ADDRESS_MAX];
    char from_address[BM_MESSAGES_ADDRESS_MAX];
    char *subject; /* malloc */
    char *body;    /* malloc */
    int64_t received_time;
    int read;
    char folder[BM_MESSAGES_FOLDER_MAX];
};

/*
 * inboxを一覧する(受信時刻降順)。folder_filterがNULLなら全件(inbox/trash問わず)、
 * 非NULLならその値のfolderのみ。成功時0、*out_listはmalloc済み配列(bm_inbox_message_list_freeで解放)。
 */
int bm_messages_store_list_inbox(sqlite3 *db, const char *folder_filter,
                                  struct bm_inbox_message **out_list, size_t *out_count);
void bm_inbox_message_list_free(struct bm_inbox_message *list, size_t count);

/*
 * §11 2026-08-30: trashMessage API用。msg_idでinboxの1行をfolder='trash'へ更新する(PyBitmessage
 * 本家api.pyのHandleTrashMessage/helper_inbox.trash準拠の論理削除)。inboxテーブルのfolder列
 * ('inbox'|'trash'、DESIGN.md §2.4)はこの用途のために既に設けられていたが、値を変更するAPIが
 * これまで無かった(getInboxMessagesのfolder引数は絞り込み専用で書き込み側が未実装だった)ため
 * 追加。該当行が無くてもエラーにしない(本家も「存在したと仮定して削除した」という応答仕様)。
 * trashMessage APIはinboxとsentの両方に対してこれと下のbm_messages_store_trash_sent_messageを
 * 無条件で両方呼ぶ(本家HandleTrashMessageと同じ構成)。成功時0。
 */
int bm_messages_store_trash_inbox_message(sqlite3 *db, const unsigned char msg_id[32]);

struct bm_sent_message
{
    unsigned char msg_id[32];
    char to_address[BM_MESSAGES_ADDRESS_MAX];
    char from_address[BM_MESSAGES_ADDRESS_MAX];
    char *subject; /* malloc */
    char *body;    /* malloc */
    char status[24]; /* 'sent'|'ackreceived'|'msgsentnoackexpected'(§11 2026-08-31、自分自身宛/chan宛) */
    int64_t sent_time;
    int64_t ttl;
    int resend_count;
};

/*
 * §11 2026-08-25: 送信済みボックス。sentテーブルはこれまでack追跡・再送判定
 * (bm_messages_store_list_resend_candidates)専用で、ユーザー向けの一覧手段が無かった
 * (get-inbox/getInboxMessagesに相当するものが未実装だった)ため追加。
 * 送信時刻降順で全件返す(inboxのfolder_filterに相当する絞り込みは、sentには
 * folder概念自体が無いため用意していない)。成功時0、*out_listはmalloc済み配列
 * (bm_sent_message_list_freeで解放)。
 */
int bm_messages_store_list_sent(sqlite3 *db, struct bm_sent_message **out_list, size_t *out_count);
void bm_sent_message_list_free(struct bm_sent_message *list, size_t count);

/* §11 2026-08-30: trashMessage API用。msg_idでsentの1行をfolder='trash'へ更新する
 * (bm_messages_store_trash_inbox_messageのsent版、詳細はそちらのコメント参照)。
 * bm_messages_store_list_sentはfolder='sent'の行のみ返すため、これでtrash化した行は
 * 一覧から消える。成功時0。 */
int bm_messages_store_trash_sent_message(sqlite3 *db, const unsigned char msg_id[32]);

/* --- §5.4 broadcast購読(subscriptions) --- */

/* 既存行があればlabelのみ更新(UPSERT)。成功時0 */
int bm_messages_store_add_subscription(sqlite3 *db, const char *address, const char *label);
/* 該当行が無くてもエラーにしない。成功時0 */
int bm_messages_store_remove_subscription(sqlite3 *db, const char *address);

struct bm_subscription
{
    char address[BM_MESSAGES_ADDRESS_MAX];
    char label[128];
};

/* enabled=1の購読を全件列挙する(malloc、呼び出し側でbm_subscription_list_freeすること)。
 * 成功時0、*out_countに件数を設定する(0件でも成功) */
int bm_messages_store_list_subscriptions(sqlite3 *db, struct bm_subscription **out_list, size_t *out_count);
void bm_subscription_list_free(struct bm_subscription *list);

/* --- アドレス帳(address_book) 2026-08-29実装。PyBitmessage本家api.pyの
 * addAddressBookEntry/deleteAddressBookEntry/listAddressBookEntries準拠 --- */

/* 既に同じaddressがあれば失敗させる(重複禁止、UPSERTしない。本家準拠)。成功時0 */
int bm_messages_store_add_address_book_entry(sqlite3 *db, const char *address, const char *label);
/* 該当行が無くてもエラーにしない。成功時0 */
int bm_messages_store_remove_address_book_entry(sqlite3 *db, const char *address);

struct bm_address_book_entry
{
    char address[BM_MESSAGES_ADDRESS_MAX];
    char label[128];
};

/* 全件列挙する(malloc、呼び出し側でbm_address_book_list_freeすること)。
 * 成功時0、*out_countに件数を設定する(0件でも成功) */
int bm_messages_store_list_address_book(sqlite3 *db, struct bm_address_book_entry **out_list, size_t *out_count);
void bm_address_book_list_free(struct bm_address_book_entry *list);

#endif /* BM_CORE_MESSAGES_STORE_H */
