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
#include "i18n.h"

struct bm_cli_env
{
    const char *host;
    int port;
    const char *user;
    const char *pass;
};

/*
 * §11 2026-11-03 項目54(国際化): コマンド一覧の表。従来はprint_usageの1つの巨大な日本語
 * 文字列と、各コマンドの引数エラー時の個別の"使い方: ..."文字列に、同じ書式を二重に
 * 書いていた。翻訳のために文字列を英語のmsgidへ書き直すついでに、書式(synopsis)は
 * ここ1か所にまとめ、print_usageと引数エラー時のprint_command_usageの両方がこの表を引く
 * ようにした。
 *
 * synopsisは翻訳しない(コマンド名・引数名はそのまま打ち込むものなので)。helpは
 * 翻訳対象で、N_()で印を付けておき表示時に_()を通す。helpは改行区切りの複数行で、
 * 各行の字下げはprint_usage側で付ける(msgidに字下げの空白を含めないため)。
 */
struct cli_command_help
{
    const char *synopsis;
    const char *help; /* NULLなら説明なし */
};

static const struct cli_command_help CLI_COMMANDS[] = {
    {"list-addresses", NULL},
    {"create-address <passphrase> <version:3|4> <stream> <ripeNullBytes> <label> <storePassphrase>", NULL},
    {"import-address <address> <signingWIF> <encryptionWIF> <label> <storePassphrase> "
     "[nonceTrialsPerByte] [payloadLengthExtraBytes]",
     N_("Import an address from a WIF key pair taken from keys.dat (PyBitmessage).\n"
        "Fails if the ripe derived from the address does not match the ripe of the\n"
        "WIF public keys")},
    {"import-keys-dat <keys.dat path> <storePassphrase>",
     N_("Bulk-import an entire keys.dat (PyBitmessage, INI format). The same\n"
        "storePassphrase is used for every address (assumes bulk unlock with the\n"
        "vault scheme in DESIGN.md section 7.4). Addresses are sent in batches with\n"
        "importAddressesBulk")},
    {"set-label <address> <label>",
     N_("Change only the label of an address (private keys are not touched; offers\n"
        "through the API what PyBitmessage offers in its GUI)")},
    {"fix-labels-from-keys-dat <keys.dat path>",
     N_("Re-parse keys.dat and update only the labels of existing addresses to the\n"
        "correct values. Meant for repairing labels garbled by import-keys-dat")},
    {"join-chan <passphrase> <label> <storePassphrase>",
     N_("Join or create a chan (private group channel). Everyone who uses the same\n"
        "passphrase shares the same address and keys. Post with\n"
        "send-message <chanAddr> <chanAddr> ... (sending to itself); once unlocked,\n"
        "other members' posts can be read with get-inbox")},
    {"unlock <address> <passphrase>", NULL},
    {"export-address <address> <passphrase>",
     N_("Decrypt with the passphrase on the spot and return the WIF key pair, whether\n"
        "or not the address is unlocked (a one-shot operation that does not touch\n"
        "the keyring; the counterpart of importAddress)")},
    {"unlock-all <passphrase>",
     N_("Try to unlock every row of identity.db with a common passphrase. Each row\n"
        "keeps its own kdf_salt, so rows that do not match are silently skipped (not\n"
        "an error). Returns an array of [{address, unlocked}], so you can tell which\n"
        "rows did not match.\n"
        "If identity.db has more than 10,000 entries, nothing is unlocked and an\n"
        "error is returned (trial decryption of received msgs gets heavier in\n"
        "proportion to the count; unlock the addresses you need with\n"
        "unlock-addresses)")},
    {"unlock-addresses [--backfill] <address-list path|-> <passphrase>",
     N_("Unlock the addresses listed one per line in a file (\"-\" for stdin) with a\n"
        "common passphrase (blank lines and lines starting with # are ignored).\n"
        "Calling unlock repeatedly runs scrypt every time; this runs it once per\n"
        "1,000 addresses. Failed addresses and the reason (address not found /\n"
        "passphrase mismatch) are printed to stderr, and the exit status is non-zero\n"
        "if any address failed. With --backfill, past msgs addressed to the unlocked\n"
        "addresses are looked up in object_pool.db and put into the inbox (unlike\n"
        "unlock, this is off by default because it takes time proportional to\n"
        "msgs x addresses)")},
    {"lock <address>", NULL},
    {"lock-all", NULL},
    {"delete <address>", NULL},
    {"convert-to-v4 <v3Address> <passphrase>",
     N_("Move a v3 address to the v4 address with the same keys (creating the v4 if\n"
        "missing, rewriting the addresses in inbox/sent, and deleting the v3).\n"
        "Needed because v3 and v4 share the ripe, so received msgs cannot be told\n"
        "apart by their destination")},
    {"convert-all-v3-to-v4 <passphrase> [limit]",
     N_("Run convert-to-v4 on up to limit v3 addresses in identity.db, oldest first\n"
        "(default 1000, at most 10000). Repeat until remaining in the result is 0")},
    {"cache-pubkey <address> <signingPubkeyHex> <encryptionPubkeyHex>",
     N_("Manually register a peer's public keys (130 hex digits each) in\n"
        "pubkey_cache. Normally send-message sends a getpubkey request automatically\n"
        "when the key is unknown and caches the reply, so this command is for when\n"
        "you already know the keys or want to skip that wait")},
    {"send-message [--body-file <path>] <fromAddress> <toAddress> <subject> [<body>] "
     "[ttlSeconds] [ackStealthLevel]",
     N_("The recipient's public encryption key is always resolved from\n"
        "pubkey_cache. If it is not there, a getpubkey request is sent\n"
        "automatically; wait for the reply and run the same command again, or\n"
        "register the key first with cache-pubkey.\n"
        "With --body-file <path>, the body is read from the file instead of the\n"
        "<body> argument (\"-\" for stdin). Use it for long or multi-line bodies: a\n"
        "body passed as an argument is visible in ps(1) and stays in the shell\n"
        "history. subject + body may be up to 261644 bytes in total (2^18-500, the\n"
        "same as PyBitmessage)")},
    {"get-inbox [folder]", NULL},
    {"get-sent",
     N_("List the sent box (sent table). Each element has msgId/toAddress/\n"
        "fromAddress/subject/body/status (sent|ackreceived|msgsentnoackexpected)/\n"
        "sentTime/ttl/resendCount")},
    {"trash-message <msgId(hex)>",
     N_("Move the message to folder='trash' in both inbox and sent (as\n"
        "PyBitmessage's trashMessage does). Not an error if nothing matches")},
    {"send-broadcast [--body-file <path>] <fromAddress> <subject> [<body>] [ttlSeconds]",
     N_("--body-file works as in send-message (the body is read from the file, or\n"
        "from stdin for \"-\")")},
    {"add-subscription <address> [label]",
     N_("Subscribe to broadcasts (DESIGN.md section 5.4) from the address. Broadcasts\n"
        "received from it are saved to the inbox from then on")},
    {"remove-subscription <address>", NULL},
    {"list-subscriptions", NULL},
    {"add-address-book-entry <address> <label>",
     N_("Fails if the same address is already registered (no duplicates, as in\n"
        "PyBitmessage)")},
    {"delete-address-book-entry <address>", NULL},
    {"list-address-book-entries", NULL},
    {"get-socks-proxy-onion", NULL},
    {"set-socks-proxy-onion <enabled:0|1> <host> <port>",
     N_("Outbound SOCKS5 proxy (Tor etc.) used only for onion peers (.onion).\n"
        "Stored in config.db and picked up by a running bitmessaged at its next\n"
        "reconnect cycle (within 30 seconds by default; no restart needed)")},
    {"get-socks-proxy-clearnet", NULL},
    {"set-socks-proxy-clearnet <enabled:0|1> <host> <port>",
     N_("Outbound SOCKS5 proxy used only for clearnet IPs. Disabled (direct) by\n"
        "default. It is separate from the onion one because enabling it sends even\n"
        "clearnet connections through Tor exit nodes, where rate limits on the\n"
        "shared IPs hurt connectivity to other nodes (see DESIGN.md section 11)")},
    {"add-peer <ipAddress> <port> [stream]",
     N_("Manually add to peers.db a peer you have personally confirmed to exist\n"
        "(through a channel where you actually know the operator, not an anonymous\n"
        "list on a message board). A last resort when all mainnet seeds are down")},
    {"list-connections",
     N_("Return the currently connected peers ({inbound:[...], outbound:[...]},\n"
        "each element host/port/fd/fullyEstablished/userAgent/sentBytes/\n"
        "receivedBytes). fd is the real fd number in the registry (for debugging;\n"
        "the \"fd=N\" in broadcast_inv failure logs is a throwaway dup() number\n"
        "unrelated to it). sentBytes may not include what was sent via\n"
        "broadcast_inv (the overall total in get-network-stats does)")},
    {"get-network-stats",
     N_("Total bytes sent/received since the process started ({sentBytes,\n"
        "receivedBytes}, including connections already closed)")},
};

#define CLI_COMMAND_COUNT (sizeof(CLI_COMMANDS) / sizeof(CLI_COMMANDS[0]))

static void print_usage(const char *prog)
{
    fprintf(stderr, _("Usage: %s <command> [args...]\n"), prog);
    fputs("\n", stderr);
    fputs(_("Environment variables: BM_API_HOST (default 127.0.0.1) BM_API_PORT (default 8442) "
            "BM_API_USER BM_API_PASS\n"),
          stderr);
    fputs("\n", stderr);
    fputs(_("Commands:\n"), stderr);
    for (size_t i = 0; i < CLI_COMMAND_COUNT; i++)
    {
        fprintf(stderr, "  %s\n", CLI_COMMANDS[i].synopsis);
        if (CLI_COMMANDS[i].help == NULL)
        {
            continue;
        }
        /* 訳文の各行に字下げを付けて出す */
        const char *line = _(CLI_COMMANDS[i].help);
        while (*line != '\0')
        {
            const char *nl = strchr(line, '\n');
            int len = nl != NULL ? (int)(nl - line) : (int)strlen(line);
            fprintf(stderr, "      %.*s\n", len, line);
            line += len;
            if (*line == '\n')
            {
                line++;
            }
        }
    }
}

/* 引数の数が合わないときに、そのコマンドの書式だけを表示する。nameはCLI_COMMANDSに
 * 必ず載っているコマンド名(載っていなければ一覧全体を出す) */
static void print_command_usage(const char *prog, const char *name)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < CLI_COMMAND_COUNT; i++)
    {
        const char *synopsis = CLI_COMMANDS[i].synopsis;
        if (strncmp(synopsis, name, name_len) == 0 && (synopsis[name_len] == ' ' || synopsis[name_len] == '\0'))
        {
            fprintf(stderr, _("Usage: %s %s\n"), prog, synopsis);
            return;
        }
    }
    print_usage(prog);
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
        snprintf(buf, sizeof(buf), _("Could not connect to %s%s%s:%d (is bitmessaged running?)"),
                 host_is_ipv6 ? "[" : "", env->host, host_is_ipv6 ? "]" : "", env->port);
        *out_error_msg = strdup(buf);
        return 0;
    }
    if (status == 401)
    {
        free(resp);
        *out_error_msg = strdup(_("Authentication failed (check BM_API_USER/BM_API_PASS)"));
        return 0;
    }

    bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
    free(resp);
    if (v == NULL)
    {
        char buf[128];
        snprintf(buf, sizeof(buf), _("Could not parse the server response as JSON (HTTP %d)"), status);
        *out_error_msg = strdup(buf);
        return 0;
    }

    bm_json_value_t *error = bm_json_object_get(v, "error");
    if (error != NULL)
    {
        const char *msg = bm_json_as_string(bm_json_object_get(error, "message"));
        char buf[512];
        snprintf(buf, sizeof(buf), _("Error: %s"), msg != NULL ? msg : _("(unknown error)"));
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
        fprintf(stderr, _("Entire batch failed (%zu entries): %s\n"), batch_count, error_msg);
        free(error_msg);
        *failed += (int)batch_count;
        return;
    }

    bm_json_value_t *result = bm_json_object_get(response, "result");
    if (result == NULL || result->type != BM_JSON_ARRAY)
    {
        fprintf(stderr, _("Malformed batch response (counting %zu entries as skipped)\n"), batch_count);
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
            fprintf(stderr, _("Skipped: %s (%s)\n"), addr != NULL ? addr : "?",
                    err != NULL ? err : _("unknown error"));
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
        fprintf(stderr, _("Error: cannot open %s\n"), path);
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

    printf(_("Import finished: %d succeeded, %d failed, %d skipped (missing keys)\n"), imported, failed, skipped_no_keys);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * §11 2026-09-28 項目48 unlock-addresses: ファイル(1行1アドレス)に並べたアドレスを
 * unlockAddressesでまとめてunlockする。identity.dbが項目44の上限を超えてunlock-allが使えない
 * 運用で、unlockを1件ずつ数千回呼ぶと毎回vaultのmaster KEK導出(scrypt)とbackfillが走って
 * 遅い、というユーザー要望への対応。
 *
 * UNLOCK_ADDRESSES_BATCH_SIZE件ずつ送る。master KEKの導出はバッチごとに1回だけなので、
 * バッチを小さくしてもコストはほとんど増えない。一方でRPCのハンドラは直列実行なので、
 * 旧方式(個別scrypt、1件約161ms)の行が混じっていても1回の呼び出しが他のAPI呼び出しを
 * 数分単位で待たせない大きさにした(1,000件すべてが旧方式でも約3分)。
 *
 * 空行と'#'で始まる行は読み飛ばす(前後の空白・CRは除く)。backfillは既定では行わず、
 * --backfillを付けたときだけ行う(API側のコメント参照)。
 */
#define UNLOCK_ADDRESSES_BATCH_SIZE 1000

/* batch[0..batch_count)をunlockAddressesで送信し、成否をunlocked/failed/backfilledへ集計する */
static void flush_unlock_addresses_batch(const struct bm_cli_env *env, char **batch, size_t batch_count,
                                          const char *passphrase, int backfill, int *unlocked, int *failed,
                                          int *backfilled)
{
    if (batch_count == 0)
    {
        return;
    }

    bm_json_value_t *addresses = bm_json_new_array();
    for (size_t i = 0; i < batch_count; i++)
    {
        bm_json_array_append(addresses, bm_json_new_string(batch[i]));
    }
    bm_json_value_t *params = bm_json_new_array();
    bm_json_array_append(params, addresses);
    bm_json_array_append(params, bm_json_new_string(passphrase));
    bm_json_array_append(params, bm_json_new_bool(backfill));

    char *error_msg = NULL;
    bm_json_value_t *response = NULL;
    if (!call_rpc_raw(env, "unlockAddresses", params, &response, &error_msg))
    {
        fprintf(stderr, _("Entire batch failed (%zu entries): %s\n"), batch_count, error_msg);
        free(error_msg);
        *failed += (int)batch_count;
        return;
    }

    bm_json_value_t *result = bm_json_object_get(response, "result");
    bm_json_value_t *results = bm_json_object_get(result, "results");
    if (results == NULL || results->type != BM_JSON_ARRAY)
    {
        fprintf(stderr, _("Malformed batch response (counting %zu entries as failed)\n"), batch_count);
        *failed += (int)batch_count;
        bm_json_free(response);
        return;
    }

    for (size_t i = 0; i < results->item_count; i++)
    {
        bm_json_value_t *item = bm_json_array_get(results, i);
        bm_json_value_t *unlocked_v = bm_json_object_get(item, "unlocked");
        if (unlocked_v != NULL && unlocked_v->type == BM_JSON_BOOL && unlocked_v->boolean)
        {
            (*unlocked)++;
        }
        else
        {
            const char *addr = bm_json_as_string(bm_json_object_get(item, "address"));
            const char *err = bm_json_as_string(bm_json_object_get(item, "error"));
            fprintf(stderr, _("Failed: %s (%s)\n"), addr != NULL ? addr : "?", err != NULL ? err : _("unknown error"));
            (*failed)++;
        }
    }
    bm_json_value_t *backfilled_v = bm_json_object_get(result, "backfilledMessages");
    if (backfilled_v != NULL && backfilled_v->type == BM_JSON_NUMBER)
    {
        *backfilled += (int)bm_json_as_number(backfilled_v);
    }
    bm_json_free(response);
}

static int unlock_addresses_from_file(const struct bm_cli_env *env, const char *path, const char *passphrase,
                                      int backfill)
{
    FILE *f = (strcmp(path, "-") == 0) ? stdin : fopen(path, "r");
    if (f == NULL)
    {
        fprintf(stderr, _("Error: cannot open %s\n"), path);
        return EXIT_FAILURE;
    }

    char **batch = malloc(sizeof(*batch) * UNLOCK_ADDRESSES_BATCH_SIZE);
    if (batch == NULL)
    {
        if (f != stdin)
        {
            fclose(f);
        }
        fprintf(stderr, _("Error: out of memory\n"));
        return EXIT_FAILURE;
    }
    size_t batch_count = 0;
    int unlocked = 0;
    int failed = 0;
    int backfilled = 0;
    char line[KEYS_DAT_LINE_MAX];

    while (fgets(line, sizeof(line), f) != NULL)
    {
        char *nl = strchr(line, '\n');
        if (nl != NULL)
        {
            *nl = '\0';
        }
        char *trimmed = trim_inplace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#')
        {
            continue;
        }
        batch[batch_count] = strdup(trimmed);
        if (batch[batch_count] == NULL)
        {
            fprintf(stderr, _("Error: out of memory\n"));
            break;
        }
        batch_count++;
        if (batch_count == UNLOCK_ADDRESSES_BATCH_SIZE)
        {
            flush_unlock_addresses_batch(env, batch, batch_count, passphrase, backfill, &unlocked, &failed,
                                          &backfilled);
            for (size_t i = 0; i < batch_count; i++)
            {
                free(batch[i]);
            }
            batch_count = 0;
        }
    }
    flush_unlock_addresses_batch(env, batch, batch_count, passphrase, backfill, &unlocked, &failed, &backfilled);
    for (size_t i = 0; i < batch_count; i++)
    {
        free(batch[i]);
    }
    free(batch);
    if (f != stdin)
    {
        fclose(f);
    }

    if (backfill)
    {
        printf(_("Unlock finished: %d succeeded, %d failed, %d msg(s) newly added to the inbox by backfill\n"), unlocked, failed,
               backfilled);
    }
    else
    {
        printf(_("Unlock finished: %d succeeded, %d failed\n"), unlocked, failed);
    }
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
        fprintf(stderr, _("Skipped: %s (%s)\n"), address, error_msg);
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
        fprintf(stderr, _("Error: cannot open %s\n"), path);
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

    printf(_("Label fix finished: %d succeeded, %d failed\n"), fixed, failed);
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
        fprintf(stderr, _("Error: out of memory\n"));
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
                fprintf(stderr, _("Error: out of memory\n"));
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
                fprintf(stderr, _("Error: failed to read %s\n"), path);
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
        fprintf(stderr, _("Error: %s contains a NUL byte (specify a text file)\n"),
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
        return read_stream_all(stdin, _("standard input"), out_len);
    }
    /* テキスト前提だが"rb"で開く。改行変換を挟まず、ファイルの内容をそのまま本文にする
     * (末尾の改行も勝手に落とさない) */
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, _("Error: cannot open %s\n"), path);
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
 *
 * §11 2026-11-03 項目54: ただし組み立てたargv配列はg_body_file_argvにも保持する。保持して
 * いないと、main()が返った後のLeakSanitizer(CIのsanitizeジョブ)から見たときに到達可能か
 * どうかが、ポインタがたまたまスタックやレジスタに残っているかどうかで決まってしまう。実際、
 * main()の先頭にbm_cli_i18n_init()を足しただけでコードの配置が変わってリーク扱いになり、
 * --body-fileでの送信が(成功したのに)終了コード非0になってcli_integrationが落ちた。
 * ファイルスコープの変数はLSanの探索の起点になるので、配列とそこから指す本文バッファが
 * 常に到達可能になる。
 */
static char **g_body_file_argv;

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
        fprintf(stderr, _("Error: no file path given for --body-file\n"));
        return -1;
    }
    const char *path = argv[opt_index + 1];

    /* --body-fileとそのパスを除いた位置引数の並びを作る */
    char **rest = malloc(sizeof(char *) * (size_t)(argc + 1));
    if (rest == NULL)
    {
        fprintf(stderr, _("Error: out of memory\n"));
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
        fprintf(stderr, _("Error: even with --body-file, all positional arguments before the body are required\n"));
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
         * 誤解させないようにする。
         * §11 2026-11-03 項目54: 従来は「以上」の有無を%sで差し込んでいたが、語順が言語ごとに
         * 違うため断片の差し込みは翻訳できない。文ごと2通りに分けた */
        if (body_len > BM_MAX_SUBJECT_PLUS_BODY_LEN)
        {
            fprintf(stderr,
                    _("Error: body too long (subject %zu bytes + body %zu bytes or more; the limit is %zu "
                      "bytes in total)\n"),
                    subject_len, body_len, BM_MAX_SUBJECT_PLUS_BODY_LEN);
        }
        else
        {
            fprintf(stderr,
                    _("Error: body too long (subject %zu bytes + body %zu bytes; the limit is %zu bytes in "
                      "total)\n"),
                    subject_len, body_len, BM_MAX_SUBJECT_PLUS_BODY_LEN);
        }
        free(body);
        free(rest);
        return -1;
    }

    char **result = malloc(sizeof(char *) * (size_t)(rest_argc + 2));
    if (result == NULL)
    {
        fprintf(stderr, _("Error: out of memory\n"));
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
    g_body_file_argv = result;
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
        fprintf(stderr, _("Error: %s must be a number (got: %s)\n"), name, s);
        return -1;
    }
    *out = v;
    return 0;
}

int main(int argc, char **argv)
{
    /* §11 2026-11-03 項目54: どのメッセージを出すよりも前にロケールと訳の置き場所を決める */
    bm_cli_i18n_init();

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
            print_command_usage(argv[0], "create-address");
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
            print_command_usage(argv[0], "import-address");
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
            print_command_usage(argv[0], "import-keys-dat");
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
            print_command_usage(argv[0], "set-label");
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
            print_command_usage(argv[0], "fix-labels-from-keys-dat");
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
            print_command_usage(argv[0], "join-chan");
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
            print_command_usage(argv[0], "unlock");
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
            print_command_usage(argv[0], "export-address");
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
            print_command_usage(argv[0], "unlock-all");
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        return call_rpc(&env, "unlockAllAddresses", params);
    }

    if (strcmp(cmd, "unlock-addresses") == 0)
    {
        /* --backfillは位置引数の前にだけ置ける(引数が少ないので並べ替えは受け付けない) */
        int backfill = (argc >= 3 && strcmp(argv[2], "--backfill") == 0);
        int first = backfill ? 3 : 2;
        bm_json_free(params);
        if (argc != first + 2)
        {
            print_command_usage(argv[0], "unlock-addresses");
            return EXIT_FAILURE;
        }
        return unlock_addresses_from_file(&env, argv[first], argv[first + 1], backfill);
    }

    if (strcmp(cmd, "lock") == 0)
    {
        if (argc != 3)
        {
            print_command_usage(argv[0], "lock");
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
            print_command_usage(argv[0], "delete");
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
            print_command_usage(argv[0], "convert-to-v4");
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
            print_command_usage(argv[0], "convert-all-v3-to-v4");
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
            print_command_usage(argv[0], "cache-pubkey");
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
            print_command_usage(argv[0], "send-message");
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
            print_command_usage(argv[0], "get-inbox");
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
            print_command_usage(argv[0], "get-sent");
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        return call_rpc(&env, "getSentMessages", params);
    }

    if (strcmp(cmd, "trash-message") == 0)
    {
        if (argc != 3)
        {
            print_command_usage(argv[0], "trash-message");
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
            print_command_usage(argv[0], "send-broadcast");
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
            print_command_usage(argv[0], "add-subscription");
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
            print_command_usage(argv[0], "remove-subscription");
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
            print_command_usage(argv[0], "add-address-book-entry");
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
            print_command_usage(argv[0], "delete-address-book-entry");
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
            print_command_usage(argv[0], "set-socks-proxy-onion");
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
            print_command_usage(argv[0], "set-socks-proxy-clearnet");
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
            print_command_usage(argv[0], "add-peer");
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

    fprintf(stderr, _("Unknown command: %s\n\n"), cmd);
    print_usage(argv[0]);
    bm_json_free(params);
    return EXIT_FAILURE;
}
