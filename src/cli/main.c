/*
 * bitmessaged(core/api_server.c)向けの一発コマンド型CLIクライアント。
 * daemonが起動時に標準エラー出力へ表示するapiusername/apipasswordを、
 * 環境変数(BM_API_USER/BM_API_PASS)経由で渡す想定。スクリプトから叩きやすい設計
 * (会話の中で「TUIよりCLIを優先、テストにも使いやすい」と決めた方針に沿う)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/json.h"
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
            "  unlock <address> <passphrase>\n"
            "  lock <address>\n"
            "  lock-all\n"
            "  delete <address>\n"
            "  cache-pubkey <address> <signingPubkeyHex> <encryptionPubkeyHex>\n"
            "      相手の公開鍵(いずれも130桁hex)を手動でpubkey_cacheへ登録する\n"
            "      (実ネットワークからの自動取得は未実装のため)\n"
            "  send-message <fromAddress> <toAddress> <toPubEncryptionHex|-> <subject> <body> "
            "[ttlSeconds] [ackStealthLevel]\n"
            "      toPubEncryptionHexは宛先の公開暗号鍵(130桁hex)。\"-\"を指定するとcache-pubkeyで\n"
            "      登録済みの鍵を使う\n"
            "  get-inbox [folder]\n"
            "  send-broadcast <fromAddress> <subject> <body> [ttlSeconds]\n"
            "  add-subscription <address> [label]\n"
            "      broadcast(§5.4)の購読先を登録する。以後そのアドレスからのbroadcastを\n"
            "      受信したらinboxへ保存する\n"
            "  remove-subscription <address>\n"
            "  list-subscriptions\n"
            "  get-socks-proxy\n"
            "  set-socks-proxy <enabled:0|1> <host> <port>\n"
            "      outbound接続用SOCKS5プロキシ(Tor等)の設定。config.dbへ永続化されるが、\n"
            "      稼働中のbitmessagedには反映されない(再起動が必要)\n",
            prog);
}

static int call_rpc(const struct bm_cli_env *env, const char *method, bm_json_value_t *params)
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
        fprintf(stderr, "接続に失敗しました(%s:%d、bitmessagedは起動していますか?)\n", env->host, env->port);
        return EXIT_FAILURE;
    }
    if (status == 401)
    {
        fprintf(stderr, "認証に失敗しました(BM_API_USER/BM_API_PASSを確認してください)\n");
        free(resp);
        return EXIT_FAILURE;
    }

    bm_json_value_t *v = bm_json_parse(resp, strlen(resp));
    free(resp);
    if (v == NULL)
    {
        fprintf(stderr, "サーバー応答をJSONとして解釈できませんでした(HTTP %d)\n", status);
        return EXIT_FAILURE;
    }

    bm_json_value_t *error = bm_json_object_get(v, "error");
    if (error != NULL)
    {
        const char *msg = bm_json_as_string(bm_json_object_get(error, "message"));
        fprintf(stderr, "エラー: %s\n", msg != NULL ? msg : "(不明なエラー)");
        bm_json_free(v);
        return EXIT_FAILURE;
    }

    bm_json_value_t *result = bm_json_object_get(v, "result");
    char *result_text = bm_json_serialize(result);
    printf("%s\n", result_text);
    free(result_text);
    bm_json_free(v);
    return EXIT_SUCCESS;
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

    const char *cmd = argv[1];
    bm_json_value_t *params = bm_json_new_array();

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
        if (argc < 7 || argc > 9)
        {
            fprintf(stderr,
                    "使い方: %s send-message <fromAddress> <toAddress> <toPubEncryptionHex|-> "
                    "<subject> <body> [ttlSeconds] [ackStealthLevel]\n",
                    argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        /* "-" はpubkey_cacheを使う合図(JSON上はnullを送る) */
        if (strcmp(argv[4], "-") == 0)
        {
            bm_json_array_append(params, bm_json_new_null());
        }
        else
        {
            bm_json_array_append(params, bm_json_new_string(argv[4]));
        }
        bm_json_array_append(params, bm_json_new_string(argv[5]));
        bm_json_array_append(params, bm_json_new_string(argv[6]));
        if (argc >= 8)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[7])));
        }
        if (argc >= 9)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[8])));
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

    if (strcmp(cmd, "send-broadcast") == 0)
    {
        if (argc < 5 || argc > 6)
        {
            fprintf(stderr, "使い方: %s send-broadcast <fromAddress> <subject> <body> [ttlSeconds]\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_string(argv[2]));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_string(argv[4]));
        if (argc == 6)
        {
            bm_json_array_append(params, bm_json_new_number(atof(argv[5])));
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

    if (strcmp(cmd, "get-socks-proxy") == 0)
    {
        return call_rpc(&env, "getSocksProxy", params);
    }

    if (strcmp(cmd, "set-socks-proxy") == 0)
    {
        if (argc != 5)
        {
            fprintf(stderr, "使い方: %s set-socks-proxy <enabled:0|1> <host> <port>\n", argv[0]);
            bm_json_free(params);
            return EXIT_FAILURE;
        }
        bm_json_array_append(params, bm_json_new_number(atof(argv[2])));
        bm_json_array_append(params, bm_json_new_string(argv[3]));
        bm_json_array_append(params, bm_json_new_number(atof(argv[4])));
        return call_rpc(&env, "setSocksProxy", params);
    }

    fprintf(stderr, "不明なコマンド: %s\n\n", cmd);
    print_usage(argv[0]);
    bm_json_free(params);
    return EXIT_FAILURE;
}
