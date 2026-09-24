/*
 * bitmessaged(core/api_server.c)向けの一発コマンド型CLIクライアント。
 * daemonが起動時に標準エラー出力へ表示するapiusername/apipasswordを、
 * 環境変数(BM_API_USER/BM_API_PASS)経由で渡す想定。スクリプトから叩きやすい設計
 * (会話の中で「TUIよりCLIを優先、テストにも使いやすい」と決めた方針に沿う)。
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/json.h"
#include "../common/message_limits.h"
#include "http_client.h"

struct bm_cli_env
{
    const char *host;
    int port;
    const char *user;
    const char *pass;
};

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "使い方: %s <command> [args...]\n"
            "\n"
            "環境変数: BM_API_HOST(既定127.0.0.1) BM_API_PORT(既定8442) BM_API_USER BM_API_PASS\n"
            "\n"
            "コマンド:\n"
            "  list-addresses\n"
            "  create-address <passphrase> <version:3|4> <stream> <ripeNullBytes> <label> <storePassphrase>\n"
            "  import-address <address> <signingWIF> <encryptionWIF> <label> <storePassphrase> "
            "[nonceTrialsPerByte] [payloadLengthExtraBytes]\n"
            "      keys.dat(PyBitmessage本家)由来のWIF鍵ペアからアドレスをインポートする。\n"
            "      addressから復元したripeとWIFの公開鍵ripeが一致しないと失敗する\n"
            "  import-keys-dat <keys.datのパス> <storePassphrase>\n"
            "      keys.dat(PyBitmessage本家、INI形式)を丸ごと一括インポートする。全アドレスへ\n"
            "      共通のstorePassphraseを使う(§7.4のvault方式による一括unlockを前提)。\n"
            "      importAddressesBulkでKEYS_DAT_BATCH_SIZE件ずつまとめて送信する\n"
            "  set-label <address> <label>\n"
            "      アドレスのラベルのみ変更する(秘密鍵には触れない、PyBitmessage本家のGUI相当の\n"
            "      機能を本実装独自にAPI経由で提供)\n"
            "  fix-labels-from-keys-dat <keys.datのパス>\n"
            "      keys.datを再パースし、既存アドレスのラベルだけを一括で正しい値に更新する。\n"
            "      import-keys-datで文字化けしたラベルを後から修正する用途を想定\n"
            "  join-chan <passphrase> <label> <storePassphrase>\n"
            "      chan(私設グループチャンネル)へ参加/作成する。同じpassphraseで呼んだ全員が\n"
            "      同じアドレス・鍵を共有する。投稿はsend-message <chanAddr> <chanAddr> ...\n"
            "      (自分自身宛の送信)で行い、他メンバーの投稿はunlock済みならget-inboxで読める\n"
            "  unlock <address> <passphrase>\n"
            "  export-address <address> <passphrase>\n"
            "      unlock中かどうかに関わらず、その場でpassphrase復号しWIF鍵ペアを返す\n"
            "      (keyringには触れない一回性操作、importAddressと対称)\n"
            "  unlock-all <passphrase>\n"
            "      identity.db全件に対し共通passphraseでunlockを試みる。行ごとのkdf_saltは\n"
            "      個別のままなので、一致しない行は黙ってスキップされる(エラーにしない)。\n"
            "      戻り値は[{address, unlocked}]の配列で、どの行が不一致だったか判別できる\n"
            "      identity.dbが10,000件を超える場合は何もunlockせずエラーになる(受信msgの\n"
            "      試行復号が件数に比例して重くなるため。必要なアドレスはunlockで個別に)\n"
            "  lock <address>\n"
            "  lock-all\n"
            "  delete <address>\n"
            "  convert-to-v4 <v3Address> <passphrase>\n"
            "      v3アドレスを同じ鍵のv4アドレスへ移す(v4が無ければ作り、inbox/sentのアドレスを\n"
            "      書き換え、v3を削除する)。v3とv4はripeが共通で受信msgの宛先を区別できないため\n"
            "  convert-all-v3-to-v4 <passphrase> [limit]\n"
            "      identity.dbのv3を古い順に最大limit件(既定1000、上限10000)まとめてconvert-to-v4する。\n"
            "      戻り値のremainingが0になるまで繰り返し実行する\n"
            "  cache-pubkey <address> <signingPubkeyHex> <encryptionPubkeyHex>\n"
            "      相手の公開鍵(いずれも130桁hex)を手動でpubkey_cacheへ登録する。\n"
            "      通常はsend-messageが未登録ならgetpubkey要求を自動送出し応答を自動キャッシュ\n"
            "      するため、本コマンドは事前に鍵を知っている場合や、その待ち時間を省きたい\n"
            "      場合の手動登録手段\n"
            "  send-message [--body-file <path>] <fromAddress> <toAddress> <subject> [<body>] "
            "[ttlSeconds] [ackStealthLevel]\n"
            "      宛先の公開暗号鍵は常にpubkey_cacheから解決する。未登録ならgetpubkey要求を\n"
            "      自動送出するので、応答を待ってから同じコマンドを再実行するか、先にcache-pubkeyで\n"
            "      鍵を登録しておく。\n"
            "      --body-file <path>を付けると<body>の位置引数の代わりにファイルから本文を読む\n"
            "      (pathが\"-\"なら標準入力)。長文・改行を含む本文はこちらを使うこと。位置引数で\n"
            "      渡すと本文がps(1)から見えシェル履歴にも残る。subject+本文の合計は\n"
            "      261644バイトまで(PyBitmessage本家と同じ2^18-500)\n"
            "  get-inbox [folder]\n"
            "  get-sent\n"
            "      送信済みボックス(sentテーブル)を一覧する。各要素はmsgId/toAddress/\n"
            "      fromAddress/subject/body/status(sent|ackreceived|msgsentnoackexpected)/\n"
            "      sentTime/ttl/resendCount\n"
            "  trash-message <msgId(hex)>\n"
            "      inbox/sent両方に対してfolder='trash'化を試みる(PyBitmessage本家trashMessage準拠)。\n"
            "      該当が無くてもエラーにしない\n"
            "  send-broadcast [--body-file <path>] <fromAddress> <subject> [<body>] [ttlSeconds]\n"
            "      --body-fileの意味はsend-messageと同じ(ファイル、\"-\"なら標準入力から本文を読む)\n"
            "  add-subscription <address> [label]\n"
            "      broadcast(§5.4)の購読先を登録する。以後そのアドレスからのbroadcastを\n"
            "      受信したらinboxへ保存する\n"
            "  remove-subscription <address>\n"
            "  list-subscriptions\n"
            "  add-address-book-entry <address> <label>\n"
            "      既に同じaddressが登録済みならエラーになる(重複禁止、PyBitmessage本家準拠)\n"
            "  delete-address-book-entry <address>\n"
            "  list-address-book-entries\n"
            "  get-socks-proxy-onion\n"
            "  set-socks-proxy-onion <enabled:0|1> <host> <port>\n"
            "      onion peer(.onion宛)専用のoutbound SOCKS5プロキシ(Tor等)設定。config.dbへ\n"
            "      永続化され、稼働中のbitmessagedにも次の再接続サイクル(既定30秒以内)で\n"
            "      反映される(再起動不要)\n"
            "  get-socks-proxy-clearnet\n"
            "  set-socks-proxy-clearnet <enabled:0|1> <host> <port>\n"
            "      クリアネットIP宛専用のoutbound SOCKS5プロキシ設定。既定disabled(直結)。\n"
            "      onion用と分離しているのは、有効にするとクリアネットIP宛の接続まで\n"
            "      Tor出口ノード経由になり、共有IPゆえのレート制限で外部ノードへの接続性が\n"
            "      悪化するため(DESIGN.md §11参照)\n"
            "  add-peer <ipAddress> <port> [stream]\n"
            "      個人的に存在を確認した(掲示板等の匿名リストではなく実際に運用者と面識のある\n"
            "      経路で)peerを手動でpeers.dbへ追加する。mainnetシード全滅時の最後の手段\n"
            "  list-connections\n"
            "      現在接続中のpeer一覧({inbound:[...], outbound:[...]}、各要素host/port/fd/\n"
            "      fullyEstablished/userAgent/sentBytes/receivedBytes)を返す。fdはregistry上の\n"
            "      実fd番号(デバッグ用。broadcast_inv失敗ログの\"fd=N\"はdup()した使い捨て番号\n"
            "      なのでこの値とは無関係)。sentBytesはbroadcast_inv経由の分だけ含まれない\n"
            "      場合がある(get-network-statsの全体累積には含まれる)\n"
            "  get-network-stats\n"
            "      プロセス起動時からの送受信バイト数の全体累積({sentBytes,\n"
            "      receivedBytes}、切断済みの接続ぶんも含む)\n",
            prog);
}

/*
 * §11 2026-08-29 import-keys-dat(5000件規模の一括インポート)向けに、call_rpcのHTTP送受信
 * ロジックを抽出した内部ヘルパー。成功時true、*out_responseにJSON-RPCレスポンス全体
 * (resultは呼び出し側がbm_json_object_get(*out_response, "result")で取り出す。使い終わったら
 * 呼び出し側でbm_json_freeすること、不要ならNULLを渡してよい)を設定する。失敗時はfalseを
 * 返し、*out_error_msgにエラーメッセージのコピー(malloc、呼び出し側でfree)を設定する。
 * paramsは呼び出し側が渡したものをこの関数が消費する(bm_json_freeする)。
 */
static int call_rpc_raw(const struct bm_cli_env *env, const char *method, bm_json_value_t *params,
                         bm_json_value_t **out_response, char **out_error_msg)
{
    bm_json_value_t *req = bm_json_new_object();
    bm_json_object_set(req, "jsonrpc", bm_json_new_string("2.0"));
    bm_json_object_set(req, "method", bm_json_new_string(method));
    bm_json_object_set(req, "params", params);
    bm_json_object_set(req, "id", bm_json_new_number(1));
    char *body = bm_json_serialize(req);
    bm_json_free(req);

    int status = 0;
    char *resp = bm_http_post_json(env->host, env->port, env->user, env->pass, body, &status);
    free(body);

    if (resp == NULL)
    {
        /* §11 IPv6アドレスはhostに':'を含むため、"host:port"のままだとportとの区切りが
         * 分からなくなる。RFC 3986慣習に合わせ"[host]:port"の形にする */
        int host_is_ipv6 = strchr(env->host, ':') != NULL;
        char buf[256];
        snprintf(buf, sizeof(buf), "接続に失敗しました(%s%s%s:%d、bitmessagedは起動していますか?)",
                 host_is_ipv6 ? "[" : "", env->host, host_is_ipv6 ? "]" : "", env->port);
        *out_error_msg = strdup(buf);
        return 0;
    }
    if (status == 401)
    {
        free(resp);
        *out_error_msg = strdup("認証に失敗しました(BM_API_USER/BM_API_PASSを確認してください)");
        return 0;
    }

    bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
    free(resp);
    if (v == NULL)
    {
        char buf[128];
        snprintf(buf, sizeof(buf), "サーバー応答をJSONとして解釈できませんでした(HTTP %d)", status);
        *out_error_msg = strdup(buf);
        return 0;
    }

    bm_json_value_t *error = bm_json_object_get(v, "error");
    if (error != NULL)
    {
        const char *msg = bm_json_as_string(bm_json_object_get(error, "message"));
        char buf[512];
        snprintf(buf, sizeof(buf), "エラー: %s", msg != NULL ? msg : "(不明なエラー)");
        *out_error_msg = strdup(buf);
        bm_json_free(v);
        return 0;
    }

    if (out_response != NULL)
    {
        *out_response = v;
    }
    else
    {
        bm_json_free(v);
    }
    return 1;
}

static int call_rpc(const struct bm_cli_env *env, const char *method, bm_json_value_t *params)
{
    char *error_msg = NULL;
    bm_json_value_t *response = NULL;
    if (!call_rpc_raw(env, method, params, &response, &error_msg))
    {
        fprintf(stderr, "%s\n", error_msg);
        free(error_msg);
        return EXIT_FAILURE;
    }
    bm_json_value_t *result = bm_json_object_get(response, "result");
    char *result_text = bm_json_serialize(result);
    printf("%s\n", result_text);
    free(result_text);
    bm_json_free(response);
    return EXIT_SUCCESS;
}

/* 前後の空白(スペース/タブ)を除去し、末尾にNULを詰め直して返す(文字列は破壊的に書き換える) */
static char *trim_inplace(char *s)
{
    while (*s == ' ' || *s == '\t')
    {
        s++;
    }
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r'))
    {
        s[--len] = '\0';
    }
    return s;
}

/*
 * §11 2026-08-29 keys.dat(PyBitmessage本家、INI/configparser形式)からの一括インポート。
 * DESIGN.md §11/§7.4参照: daemonのHTTPリクエストボディには1MiBのDoS対策上限があり、1.5MB
 * 規模のkeys.datをAPI越しに丸ごと送る方式は取れないため、CLI側でINIをパースする方式にした
 * (ユーザーと合意、2026-08-29)。
 *
 * 【重要】当初はimportAddressをアドレスごとに個別のHTTPリクエストで呼んでいたが、実測で
 * 5143件規模のkeys.iniを使って検証した結果、importAddressを個別に呼ぶとリクエストのたびに
 * vaultのmaster KEK導出(scrypt)が再実行されてしまい、vault方式(§7.4)にした高速化の効果が
 * 全く出ない(5000件で約15分)ことが判明した。そのため、entriesを`KEYS_DAT_BATCH_SIZE`件ずつ
 * まとめてimportAddressesBulk(1回の呼び出し内でmaster KEKを1回だけ計算する)に渡す方式へ
 * 変更した(ユーザーと合意、2026-08-29)。バッチサイズは、1エントリの平均JSONサイズ
 * (address+WIF2つ+label等で概算600byte)から、1MiB上限に安全マージンを持って収まる件数として
 * 決めた。
 *
 * [bitmessagesettings]等の特殊セクションは無視し、セクション名が"BM-"で始まるものだけを
 * アドレスとして扱う(PyBitmessage本家bmconfigparser.pyのaddresses()と同じ判定)。
 * privsigningkey/privencryptionkeyが両方揃っていない行(何らかの理由で欠落したセクション)は
 * スキップしてカウントするだけで処理は継続する。storePassphraseは全件で共通の1つを使う
 * (ユーザーの運用が元々「全アドレス同一passphrase」だったこと、および§7.4のvault方式が
 * 単一passphraseでの一括unlockを前提にしていることに合わせた)。
 */
#define KEYS_DAT_LINE_MAX 4096
#define KEYS_DAT_FIELD_MAX 256
#define KEYS_DAT_ADDRESS_MAX 64
#define KEYS_DAT_BATCH_SIZE 300

struct keys_dat_entry
{
    char address[KEYS_DAT_ADDRESS_MAX];
    char label[KEYS_DAT_FIELD_MAX];
    char signing_wif[KEYS_DAT_FIELD_MAX];
    char encryption_wif[KEYS_DAT_FIELD_MAX];
    long nonce_trials_per_byte;
    long payload_length_extra_bytes;
    int has_signing;
    int has_encryption;
    int is_chan; /* §11 2026-08-29 keys.datの"chan = true"キー(§11 chan仕様)を再現する */
};

/* batch[0..batch_count)をimportAddressesBulkで一括送信し、成否をimported/failedへ集計する */
static void flush_keys_dat_batch(const struct bm_cli_env *env, const struct keys_dat_entry *batch,
                                  size_t batch_count, const char *store_passphrase, int *imported, int *failed)
{
    if (batch_count == 0)
    {
        return;
    }

    bm_json_value_t *entries = bm_json_new_array();
    for (size_t i = 0; i < batch_count; i++)
    {
        const struct keys_dat_entry *e = &batch[i];
        bm_json_value_t *entry = bm_json_new_object();
        bm_json_object_set(entry, "address", bm_json_new_string(e->address));
        bm_json_object_set(entry, "signingWIF", bm_json_new_string(e->signing_wif));
        bm_json_object_set(entry, "encryptionWIF", bm_json_new_string(e->encryption_wif));
        bm_json_object_set(entry, "label", bm_json_new_string(e->label));
        bm_json_object_set(entry, "nonceTrialsPerByte",
                            bm_json_new_number((double)(e->nonce_trials_per_byte > 0 ? e->nonce_trials_per_byte : 1000)));
        bm_json_object_set(
            entry, "payloadLengthExtraBytes",
            bm_json_new_number((double)(e->payload_length_extra_bytes > 0 ? e->payload_length_extra_bytes : 1000)));
        if (e->is_chan)
        {
            bm_json_object_set(entry, "isChan", bm_json_new_bool(1));
        }
        bm_json_array_append(entries, entry);
    }

    bm_json_value_t *params = bm_json_new_array();
    bm_json_array_append(params, entries);
    bm_json_array_append(params, bm_json_new_string(store_passphrase));

    char *error_msg = NULL;
    bm_json_value_t *response = NULL;
    if (!call_rpc_raw(env, "importAddressesBulk", params, &response, &error_msg))
    {
        fprintf(stderr, "バッチ全体が失敗しました(%zu件): %s\n", batch_count, error_msg);
        free(error_msg);
        *failed += (int)batch_count;
        return;
    }

    bm_json_value_t *result = bm_json_object_get(response, "result");
    if (result == NULL || result->type != BM_JSON_ARRAY)
    {
        fprintf(stderr, "バッチ応答の形式が不正です(%zu件をスキップ扱いにします)\n", batch_count);
        *failed += (int)batch_count;
        bm_json_free(response);
        return;
    }

    for (size_t i = 0; i < result->item_count; i++)
    {
        bm_json_value_t *item = bm_json_array_get(result, i);
        bm_json_value_t *success_v = bm_json_object_get(item, "success");
        if (success_v != NULL && success_v->type == BM_JSON_BOOL && success_v->boolean)
        {
            (*imported)++;
        }
        else
        {
            const char *addr = bm_json_as_string(bm_json_object_get(item, "address"));
            const char *err = bm_json_as_string(bm_json_object_get(item, "error"));
            fprintf(stderr, "スキップ: %s (%s)\n", addr != NULL ? addr : "?",
                    err != NULL ? err : "不明なエラー");
            (*failed)++;
        }
    }
    bm_json_free(response);
}

static int import_keys_dat(const struct bm_cli_env *env, const char *path, const char *store_passphrase)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        fprintf(stderr, "エラー: %s を開けません\n", path);
        return EXIT_FAILURE;
    }

    struct keys_dat_entry cur;
    memset(&cur, 0, sizeof(cur));
    int in_address_section = 0;
    int imported = 0;
    int failed = 0;
    int skipped_no_keys = 0;
    char line[KEYS_DAT_LINE_MAX];

    struct keys_dat_entry *batch = malloc(sizeof(*batch) * KEYS_DAT_BATCH_SIZE);
    size_t batch_count = 0;

    while (fgets(line, sizeof(line), f) != NULL)
    {
        char *nl = strchr(line, '\n');
        if (nl != NULL)
        {
            *nl = '\0';
        }
        char *trimmed = trim_inplace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }

        if (trimmed[0] == '[')
        {
            if (in_address_section)
            {
                if (cur.has_signing && cur.has_encryption)
                {
                    batch[batch_count++] = cur;
                    if (batch_count >= KEYS_DAT_BATCH_SIZE)
                    {
                        flush_keys_dat_batch(env, batch, batch_count, store_passphrase, &imported, &failed);
                        batch_count = 0;
                    }
                }
                else
                {
                    skipped_no_keys++;
                }
            }
            memset(&cur, 0, sizeof(cur));
            in_address_section = 0;

            char *end = strchr(trimmed, ']');
            if (end != NULL)
            {
                *end = '\0';
                const char *section_name = trimmed + 1;
                if (strncmp(section_name, "BM-", 3) == 0)
                {
                    in_address_section = 1;
                    strncpy(cur.address, section_name, sizeof(cur.address) - 1);
                }
            }
            continue;
        }

        if (!in_address_section)
        {
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (eq == NULL)
        {
            continue;
        }
        *eq = '\0';
        char *key = trim_inplace(trimmed);
        char *value = trim_inplace(eq + 1);

        if (strcasecmp(key, "label") == 0)
        {
            strncpy(cur.label, value, sizeof(cur.label) - 1);
        }
        else if (strcasecmp(key, "privsigningkey") == 0)
        {
            strncpy(cur.signing_wif, value, sizeof(cur.signing_wif) - 1);
            cur.has_signing = 1;
        }
        else if (strcasecmp(key, "privencryptionkey") == 0)
        {
            strncpy(cur.encryption_wif, value, sizeof(cur.encryption_wif) - 1);
            cur.has_encryption = 1;
        }
        else if (strcasecmp(key, "noncetrialsperbyte") == 0)
        {
            cur.nonce_trials_per_byte = atol(value);
        }
        else if (strcasecmp(key, "payloadlengthextrabytes") == 0)
        {
            cur.payload_length_extra_bytes = atol(value);
        }
        else if (strcasecmp(key, "chan") == 0)
        {
            cur.is_chan = (strcasecmp(value, "true") == 0);
        }
    }

    /* ファイル末尾が別セクションの見出しで終わらない場合、最後のセクションはループ内の
     * "["処理を通らないのでここで拾う */
    if (in_address_section)
    {
        if (cur.has_signing && cur.has_encryption)
        {
            batch[batch_count++] = cur;
        }
        else
        {
            skipped_no_keys++;
        }
    }
    flush_keys_dat_batch(env, batch, batch_count, store_passphrase, &imported, &failed);
    free(batch);

    fclose(f);

    printf("インポート完了: 成功%d件, 失敗%d件, 鍵欠落でスキップ%d件\n", imported, failed, skipped_no_keys);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void set_address_label(const struct bm_cli_env *env, const char *address, const char *label,
                               int *fixed, int *failed)
{
    bm_json_value_t *params = bm_json_new_array();
    bm_json_array_append(params, bm_json_new_string(address));
    bm_json_array_append(params, bm_json_new_string(label));

    char *error_msg = NULL;
    bm_json_value_t *response = NULL;
    if (!call_rpc_raw(env, "setAddressLabel", params, &response, &error_msg))
    {
        fprintf(stderr, "スキップ: %s (%s)\n", address, error_msg);
        free(error_msg);
        (*failed)++;
        return;
    }
    bm_json_free(response);
    (*fixed)++;
}

/*
 * §11 2026-08-29 keys.datインポート時のUTF-8文字化けバグ(§11参照)修正後、既にインポート
 * 済みのラベルを正しい値へ再設定するための専用コマンド。import-keys-datと同じINIパース
 * ロジックだが、WIF/nonce等は扱わずlabelキーだけを読み、setAddressLabelで1件ずつ更新する
 * (秘密鍵に触れないラベル更新はscryptを伴わない軽量な処理のため、importAddressesBulkの
 * ようなバッチAPIは不要)。
 */
static int fix_labels_from_keys_dat(const struct bm_cli_env *env, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        fprintf(stderr, "エラー: %s を開けません\n", path);
        return EXIT_FAILURE;
    }

    char address[KEYS_DAT_ADDRESS_MAX] = {0};
    char label[KEYS_DAT_FIELD_MAX] = {0};
    int in_address_section = 0;
    int fixed = 0;
    int failed = 0;
    char line[KEYS_DAT_LINE_MAX];

    while (fgets(line, sizeof(line), f) != NULL)
    {
        char *nl = strchr(line, '\n');
        if (nl != NULL)
        {
            *nl = '\0';
        }
        char *trimmed = trim_inplace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }

        if (trimmed[0] == '[')
        {
            if (in_address_section && label[0] != '\0')
            {
                set_address_label(env, address, label, &fixed, &failed);
            }
            address[0] = '\0';
            label[0] = '\0';
            in_address_section = 0;

            char *end = strchr(trimmed, ']');
            if (end != NULL)
            {
                *end = '\0';
                const char *section_name = trimmed + 1;
                if (strncmp(section_name, "BM-", 3) == 0)
                {
                    in_address_section = 1;
                    strncpy(address, section_name, sizeof(address) - 1);
                }
            }
            continue;
        }

        if (!in_address_section)
        {
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (eq == NULL)
        {
            continue;
        }
        *eq = '\0';
        char *key = trim_inplace(trimmed);
        char *value = trim_inplace(eq + 1);
        if (strcasecmp(key, "label") == 0)
        {
            strncpy(label, value, sizeof(label) - 1);
        }
    }

    if (in_address_section && label[0] != '\0')
    {
        set_address_label(env, address, label, &fixed, &failed);
    }

    fclose(f);

    printf("ラベル修正完了: 成功%d件, 失敗%d件\n", fixed, failed);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * §11 2026-09-16 --body-file: send-message/send-broadcastの本文をファイル(または標準入力)
 * から読む。
 *
 * 動機は「長文をコマンドライン引数で渡せない」ことそのものより、渡せてしまった場合の実害:
 *  (1) 本文が`ps aux`で他ユーザーから丸見えになる。メッセージ本文としてこれが一番まずい
 *  (2) シェル履歴に本文が残る
 *  (3) 改行を含む本文のクォートが現実的でなく、ARG_MAXの制約も残る
 * 標準入力(`--body-file -`)に対応しているのは、(1)(2)を完全に回避できる経路を用意する
 * ため(ファイル自体を置きたくない場合に`... --body-file - <<'EOF'`で渡せる)。
 *
 * curl流の「本文が@で始まったらファイル名とみなす」方式は採らなかった。`@teruteruさん、`の
 * ように@で始まる本文はメッセージとして普通にあり得るので、既存の呼び出しの意味を黙って
 * 変えてしまうため(ユーザーとの相談で明示オプション方式に決めた)。
 */

/* 一度のfreadで読む単位。本文の上限(BM_MAX_SUBJECT_PLUS_BODY_LEN)が256KiB弱なので、
 * これで数回のループに収まる */
#define BM_BODY_READ_CHUNK 65536

/*
 * ストリームを最後まで読み切り、NUL終端した新しいバッファ(呼び出し側でfree)を返す。
 * 失敗時はNULLを返し、理由は既にstderrへ出力済み。pathはエラーメッセージ用の表示名。
 */
static char *read_stream_all(FILE *f, const char *path, size_t *out_len)
{
    size_t cap = BM_BODY_READ_CHUNK + 1;
    size_t len = 0;
    char *buf = malloc(cap);
    if (buf == NULL)
    {
        fprintf(stderr, "エラー: メモリ確保に失敗しました\n");
        return NULL;
    }

    for (;;)
    {
        if (len + BM_BODY_READ_CHUNK + 1 > cap)
        {
            size_t new_cap = cap * 2;
            char *grown = realloc(buf, new_cap);
            if (grown == NULL)
            {
                fprintf(stderr, "エラー: メモリ確保に失敗しました\n");
                free(buf);
                return NULL;
            }
            buf = grown;
            cap = new_cap;
        }
        size_t n = fread(buf + len, 1, BM_BODY_READ_CHUNK, f);
        len += n;
        if (n < BM_BODY_READ_CHUNK)
        {
            if (ferror(f))
            {
                fprintf(stderr, "エラー: %s の読み込みに失敗しました\n", path);
                free(buf);
                return NULL;
            }
            break; /* EOF */
        }
        /* 上限を超えた時点で打ち切る。ここで止めないと、巨大なファイルや終わらない
         * 標準入力を指定された場合に、エラーを出す前にメモリを食い尽くしてしまう
         * (呼び出し側が長さを見て弾くので、1バイトでも超えていれば足りる) */
        if (len > BM_MAX_SUBJECT_PLUS_BODY_LEN)
        {
            break;
        }
    }
    buf[len] = '\0';

    /* NULバイトを含むファイルはJSON文字列にもC文字列にも載らない。黙って切り詰めると
     * 本文の一部だけが送信されてしまうので、ここで明示的に弾く */
    if (strlen(buf) != len)
    {
        fprintf(stderr, "エラー: %s にNULバイトが含まれています(テキストファイルを指定してください)\n",
                path);
        free(buf);
        return NULL;
    }

    *out_len = len;
    return buf;
}

/* --body-fileの引数を読み込む。"-"なら標準入力。失敗時NULL(理由はstderrへ出力済み) */
static char *load_body_file(const char *path, size_t *out_len)
{
    if (strcmp(path, "-") == 0)
    {
        return read_stream_all(stdin, "標準入力", out_len);
    }
    /* テキスト前提だが"rb"で開く。改行変換を挟まず、ファイルの内容をそのまま本文にする
     * (末尾の改行も勝手に落とさない) */
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "エラー: %s を開けません\n", path);
        return NULL;
    }
    char *buf = read_stream_all(f, path, out_len);
    fclose(f);
    return buf;
}

/*
 * argvから "--body-file <path>" を取り除き、読み込んだ本文をbody_indexの位置へ挿入した
 * 新しいargvを *out_argc と *out_argv へ組み立てる。こうしておけば各コマンドのハンドラは
 * 従来通りの位置引数だけを見ればよく、引数の数え方を二重に持たずに済む。
 *
 * 戻り値: 0=--body-fileが無いので何もしなかった(*out_argc と *out_argv は未変更)、
 *         1=組み立てた、-1=エラー(理由はstderrへ出力済み)。
 *
 * 確保したargv配列と本文バッファはfreeしない。このCLIは1コマンド実行して即exitするので、
 * プロセス終了時のOSによる回収に任せている(引数として使う以上、コマンドの処理が終わるまで
 * 生かしておく必要があり、途中でfreeできる箇所も無い)。
 */
static int apply_body_file_option(int argc, char **argv, int subject_index, int body_index,
                                   int *out_argc, char ***out_argv)
{
    int opt_index = -1;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--body-file") == 0)
        {
            opt_index = i;
            break;
        }
    }
    if (opt_index < 0)
    {
        return 0;
    }
    if (opt_index + 1 >= argc)
    {
        fprintf(stderr, "エラー: --body-file にファイルパスが指定されていません\n");
        return -1;
    }
    const char *path = argv[opt_index + 1];

    /* --body-fileとそのパスを除いた位置引数の並びを作る */
    char **rest = malloc(sizeof(char *) * (size_t)(argc + 1));
    if (rest == NULL)
    {
        fprintf(stderr, "エラー: メモリ確保に失敗しました\n");
        return -1;
    }
    int rest_argc = 0;
    for (int i = 0; i < argc; i++)
    {
        if (i == opt_index || i == opt_index + 1)
        {
            continue;
        }
        rest[rest_argc++] = argv[i];
    }

    if (rest_argc < body_index)
    {
        fprintf(stderr, "エラー: --body-file を使う場合でも、本文より前の位置引数は全て指定してください\n");
        free(rest);
        return -1;
    }

    size_t body_len = 0;
    char *body = load_body_file(path, &body_len);
    if (body == NULL)
    {
        free(rest);
        return -1;
    }

    /* subject+bodyの合計をサーバー側(core/api_server.cのcheck_subject_body_length)と同じ
     * 基準で先に弾く。HTTPへ載せる前・PoWを回す前に落とせるので、大きすぎるファイルを
     * 指定した際に待たされずに済む(上限の根拠はcommon/message_limits.h参照) */
    size_t subject_len = strlen(rest[subject_index]);
    if (subject_len + body_len > BM_MAX_SUBJECT_PLUS_BODY_LEN)
    {
        /* read_stream_allは上限を超えた時点で読むのをやめるので、body_lenが上限を超えている
         * 場合の値はファイル全体の大きさとは限らない。「以上」を付けて実サイズだと
         * 誤解させないようにする */
        fprintf(stderr,
                "エラー: 本文が長すぎます(subject %zuバイト + 本文 %zuバイト%s、上限は合計%zuバイト)\n",
                subject_len, body_len,
                body_len > BM_MAX_SUBJECT_PLUS_BODY_LEN ? "以上" : "",
                BM_MAX_SUBJECT_PLUS_BODY_LEN);
        free(body);
        free(rest);
        return -1;
    }

    char **result = malloc(sizeof(char *) * (size_t)(rest_argc + 2));
    if (result == NULL)
    {
        fprintf(stderr, "エラー: メモリ確保に失敗しました\n");
        free(body);
        free(rest);
        return -1;
    }
    for (int i = 0; i < body_index; i++)
    {
        result[i] = rest[i];
    }
    result[body_index] = body;
    for (int i = body_index; i < rest_argc; i++)
    {
        result[i + 1] = rest[i];
    }
    result[rest_argc + 1] = NULL;
    free(rest);

    *out_argc = rest_argc + 1;
    *out_argv = result;
    return 1;
}

/*
 * §11 2026-09-16 ttlSeconds等の数値引数のパース。従来はatof()をそのまま使っており、
 * 数値でない文字列は黙って0になっていた。--body-fileの導入で「--body-fileを指定しつつ
 * 位置引数の<body>も書いてしまった」場合に本文がttlSecondsの位置へずれ込むため、
 * そのまま0として送ってしまわないよう明示的に弾く(この誤りは--body-file以前から
 * 起こり得たので、結果としてtypo時の挙動も改善している)。
 */
static int parse_number_arg(const char *s, const char *name, double *out)
{
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (end == s || *end != '\0' || errno == ERANGE)
    {
        fprintf(stderr, "エラー: %s には数値を指定してください(指定値: %s)\n", name, s);
        return -1;
    }
    *out = v;
    return 0;
}

int main(int argc, char **argv)
{
    struct bm_cli_env env;
    env.host = getenv("BM_API_HOST");
    if (env.host == NULL)
    {
        env.host = "127.0.0.1";
    }
    const char *port_str = getenv("BM_API_PORT");
    env.port = port_str != NULL ? atoi(port_str) : 8442;
    env.user = getenv("BM_API_USER");
    env.pass = getenv("BM_API_PASS");

    if (argc < 2)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* §11 2026-08-27: bitmessaged側への--version/--help追加(DESIGN-LOG.md参照)とセットで
     * こちらにも追加した。他のRPCコマンドと違いdaemonへの接続を必要としないため、
     * BM_API_USER/PASS未設定でも使える(call_rpc呼び出しより前でreturnする)。 */
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)
    {
        printf("bitmessage-cli %s\n", BM_PROJECT_VERSION);
        return EXIT_SUCCESS;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    const char *cmd = argv[1];
    bm_json_value_t *params = bm_json_new_array();

    /* §11 2026-09-16 --body-fileを受け付けるのはこの2コマンドだけ。argvから取り除いて
     * 本文を位置引数の位置へ挿し込むので、以降のハンドラは従来の位置引数だけを見ればよい
     * (詳細はapply_body_file_optionのコメント参照) */
    if (strcmp(cmd, "send-message") == 0 || strcmp(cmd, "send-broadcast") == 0)
    {
        int is_send_message = strcmp(cmd, "send-message") == 0;
        /* send-message:   argv[2]=from argv[3]=to      argv[4]=subject argv[5]=body
         * send-broadcast: argv[2]=from argv[3]=subject argv[4]=body */
        int subject_index = is_send_message ? 4 : 3;
        int body_index = is_send_message ? 5 : 4;
        int new_argc = 0;
        char **new_argv = NULL;
        int rc = apply_body_file_option(argc, argv, subject_index, body_index, &new_argc, &new_argv);
        if (rc < 0)
        {
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        if (rc > 0)
        {
            argc = new_argc;
            argv = new_argv;
        }
    }

    if (strcmp(cmd, "list-addresses") == 0)
    {
        return call_rpc(&env, "listAddresses", params);
    }

    if (strcmp(cmd, "create-address") == 0)
    {
        if (argc != 8)
        {
            fprintf(stderr,
                    "使い方: %s create-address <passphrase> <version> <stream> <ripeNullBytes> "
                    "<label> <storePassphrase>\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_number(atof(argv[3])));
        bm_json_array_append(params, bm_json_new_number(atof(argv[4])));
        bm_json_array_append(params, bm_json_new_number(atof(argv[5])));
        bm_json_array_append(params, bm_json_new_string(argv[6]));
        bm_json_array_append(params, bm_json_new_string(argv[7]));
        return call_rpc(&env, "createDeterministicAddress", params);
    }

    if (strcmp(cmd, "import-address") == 0)
    {
        if (argc < 7 || argc > 9)
        {
            fprintf(stderr,
                    "使い方: %s import-address <address> <signingWIF> <encryptionWIF> <label> "
                    "<storePassphrase> [nonceTrialsPerByte] [payloadLengthExtraBytes]\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        bm_json_array_append(params, bm_json_new_string(argv[5]));
        bm_json_array_append(params, bm_json_new_string(argv[6]));
        if (argc >= 8)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[7])));
        }
        if (argc == 9)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[8])));
        }
        return call_rpc(&env, "importAddress", params);
    }

    if (strcmp(cmd, "import-keys-dat") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s import-keys-dat <keys.datのパス> <storePassphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_free(params);
        return import_keys_dat(&env, argv[2], argv[3]);
    }

    if (strcmp(cmd, "set-label") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s set-label <address> <label>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        return call_rpc(&env, "setAddressLabel", params);
    }

    if (strcmp(cmd, "fix-labels-from-keys-dat") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s fix-labels-from-keys-dat <keys.datのパス>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_free(params);
        return fix_labels_from_keys_dat(&env, argv[2]);
    }

    if (strcmp(cmd, "join-chan") == 0)
    {
        if (argc != 5)
        {
            fprintf(stderr, "使い方: %s join-chan <passphrase> <label> <storePassphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        return call_rpc(&env, "joinChan", params);
    }

    if (strcmp(cmd, "unlock") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s unlock <address> <passphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        return call_rpc(&env, "unlockAddress", params);
    }

    if (strcmp(cmd, "export-address") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s export-address <address> <passphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        return call_rpc(&env, "exportAddress", params);
    }

    if (strcmp(cmd, "unlock-all") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s unlock-all <passphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "unlockAllAddresses", params);
    }

    if (strcmp(cmd, "lock") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s lock <address>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "lockAddress", params);
    }

    if (strcmp(cmd, "lock-all") == 0)
    {
        return call_rpc(&env, "lockAllAddresses", params);
    }

    if (strcmp(cmd, "delete") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s delete <address>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "deleteAddress", params);
    }

    if (strcmp(cmd, "convert-to-v4") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s convert-to-v4 <v3Address> <passphrase>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        return call_rpc(&env, "convertAddressToV4", params);
    }

    if (strcmp(cmd, "convert-all-v3-to-v4") == 0)
    {
        if (argc != 3 && argc != 4)
        {
            fprintf(stderr, "使い方: %s convert-all-v3-to-v4 <passphrase> [limit]\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        if (argc == 4)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[3])));
        }
        return call_rpc(&env, "convertV3AddressesToV4", params);
    }

    if (strcmp(cmd, "cache-pubkey") == 0)
    {
        if (argc != 5)
        {
            fprintf(stderr, "使い方: %s cache-pubkey <address> <signingPubkeyHex> <encryptionPubkeyHex>\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        return call_rpc(&env, "cachePubkey", params);
    }

    if (strcmp(cmd, "send-message") == 0)
    {
        if (argc < 6 || argc > 8)
        {
            fprintf(stderr,
                    "使い方: %s send-message [--body-file <path>] <fromAddress> <toAddress> "
                    "<subject> [<body>] [ttlSeconds] [ackStealthLevel]\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        bm_json_array_append(params, bm_json_new_string(argv[5]));
        if (argc >= 7)
        {
            double ttl = 0;
            if (parse_number_arg(argv[6], "ttlSeconds", &ttl) != 0)
            {
                bm_json_free(params);
                return EXIT_FAILURE;
            }
            bm_json_array_append(params, bm_json_new_number(ttl));
        }
        if (argc >= 8)
        {
            double stealth = 0;
            if (parse_number_arg(argv[7], "ackStealthLevel", &stealth) != 0)
            {
                bm_json_free(params);
                return EXIT_FAILURE;
            }
            bm_json_array_append(params, bm_json_new_number(stealth));
        }
        return call_rpc(&env, "sendMessage", params);
    }

    if (strcmp(cmd, "get-inbox") == 0)
    {
        if (argc > 3)
        {
            fprintf(stderr, "使い方: %s get-inbox [folder]\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        if (argc == 3)
        {
            bm_json_array_append(params, bm_json_new_string(argv[2]));
        }
        return call_rpc(&env, "getInboxMessages", params);
    }

    if (strcmp(cmd, "get-sent") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "使い方: %s get-sent\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        return call_rpc(&env, "getSentMessages", params);
    }

    if (strcmp(cmd, "trash-message") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s trash-message <msgId(hex)>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "trashMessage", params);
    }

    if (strcmp(cmd, "send-broadcast") == 0)
    {
        if (argc < 5 || argc > 6)
        {
            fprintf(stderr,
                    "使い方: %s send-broadcast [--body-file <path>] <fromAddress> <subject> "
                    "[<body>] [ttlSeconds]\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        if (argc == 6)
        {
            double ttl = 0;
            if (parse_number_arg(argv[5], "ttlSeconds", &ttl) != 0)
            {
                bm_json_free(params);
                return EXIT_FAILURE;
            }
            bm_json_array_append(params, bm_json_new_number(ttl));
        }
        return call_rpc(&env, "sendBroadcast", params);
    }

    if (strcmp(cmd, "add-subscription") == 0)
    {
        if (argc < 3 || argc > 4)
        {
            fprintf(stderr, "使い方: %s add-subscription <address> [label]\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argc == 4 ? argv[3] : ""));
        return call_rpc(&env, "addSubscription", params);
    }

    if (strcmp(cmd, "remove-subscription") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s remove-subscription <address>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "removeSubscription", params);
    }

    if (strcmp(cmd, "list-subscriptions") == 0)
    {
        return call_rpc(&env, "listSubscriptions", params);
    }

    if (strcmp(cmd, "add-address-book-entry") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "使い方: %s add-address-book-entry <address> <label>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        return call_rpc(&env, "addAddressBookEntry", params);
    }

    if (strcmp(cmd, "delete-address-book-entry") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "使い方: %s delete-address-book-entry <address>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "deleteAddressBookEntry", params);
    }

    if (strcmp(cmd, "list-address-book-entries") == 0)
    {
        return call_rpc(&env, "listAddressBookEntries", params);
    }

    if (strcmp(cmd, "get-socks-proxy-onion") == 0)
    {
        return call_rpc(&env, "getSocksProxyOnion", params);
    }

    if (strcmp(cmd, "set-socks-proxy-onion") == 0)
    {
        if (argc != 5)
        {
            fprintf(stderr, "使い方: %s set-socks-proxy-onion <enabled:0|1> <host> <port>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_number(atof(argv[2])));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_number(atof(argv[4])));
        return call_rpc(&env, "setSocksProxyOnion", params);
    }

    if (strcmp(cmd, "get-socks-proxy-clearnet") == 0)
    {
        return call_rpc(&env, "getSocksProxyClearnet", params);
    }

    if (strcmp(cmd, "set-socks-proxy-clearnet") == 0)
    {
        if (argc != 5)
        {
            fprintf(stderr, "使い方: %s set-socks-proxy-clearnet <enabled:0|1> <host> <port>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_number(atof(argv[2])));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_number(atof(argv[4])));
        return call_rpc(&env, "setSocksProxyClearnet", params);
    }

    if (strcmp(cmd, "add-peer") == 0)
    {
        if (argc < 4 || argc > 5)
        {
            fprintf(stderr, "使い方: %s add-peer <ipAddress> <port> [stream]\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_number(atof(argv[3])));
        if (argc == 5)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[4])));
        }
        return call_rpc(&env, "addPeer", params);
    }

    if (strcmp(cmd, "list-connections") == 0)
    {
        return call_rpc(&env, "listConnections", params);
    }

    if (strcmp(cmd, "get-network-stats") == 0)
    {
        return call_rpc(&env, "getNetworkStats", params);
    }

    fprintf(stderr, "不明なコマンド: %s\n\n", cmd);
    print_usage(argv[0]);
    bm_json_free(params);
    return EXIT_FAILURE;
}
