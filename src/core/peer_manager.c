#include "peer_manager.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../common/db_common.h"
#include "../common/logging.h"

/* §11 peers.dbクリーンアップ。PyBitmessage network/knownnodes.pyのcleanupKnownNodes
 * (28日/3時間/-0.5)準拠 */
#define BM_PEER_CLEANUP_MAX_AGE_SECONDS (28 * 24 * 60 * 60)
#define BM_PEER_CLEANUP_MIN_AGE_SECONDS (3 * 60 * 60)
#define BM_PEER_CLEANUP_FORGET_RATING (-0.5)

/* §11 2026-08-23: outbound addr送信の候補フィルタ。PyBitmessage network/tcp.pyの
 * maximumAgeOfNodesThatIAdvertiseToOthers(=10800秒、3時間)準拠 */
#define BM_PEER_SHARE_MAX_AGE_SECONDS (3 * 60 * 60)

struct bootstrap_node
{
    const char *ip;
    int port;
};

/* PyBitmessage src/network/knownnodes.py の DEFAULT_NODES(2026-08-21確認) */
static const struct bootstrap_node MAINNET_SEEDS[] = {
    {"5.45.99.75", 8444},
    {"75.167.159.54", 8444},
    {"95.165.168.168", 8444},
    {"85.180.139.241", 8444},
    {"158.222.217.190", 8080},
    {"178.62.12.187", 8448},
    {"24.188.198.204", 8111},
    {"109.147.204.113", 1195},
    {"178.11.46.221", 8444},
};

/* 同ファイルの TESTNET_NODES */
static const struct bootstrap_node TESTNET_SEEDS[] = {
    {"46.62.252.34", 8444},
    {"5.78.198.100", 8444},
};

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS hosts ("
    "ip_address TEXT NOT NULL, "
    "port INTEGER NOT NULL, "
    "stream INTEGER NOT NULL DEFAULT 1, "
    "services INTEGER NOT NULL DEFAULT 1, "
    "last_seen INTEGER NOT NULL, "
    "rating REAL NOT NULL DEFAULT 0.0, "
    "source TEXT NOT NULL DEFAULT 'unknown', "
    /* §11 2026-08-22発覚: version messageのnonceによる自己接続検知は、Torでは
     * プロセス全体で同じnonceを使い回すこと自体が「同一ノードが複数circuitから接続して
     * いる」という相関情報を漏らしTorの匿名性を損なうため採用しなかった(ユーザーとの
     * 議論の結論)。代わりにPyBitmessageのknownnodes myselfフィールドと同じ発想で、
     * 自分自身のonionアドレス(Stage 2のADD_ONION、またはBM_ONION_ADDRESS判明時)を
     * bm_peer_manager_mark_selfでこの列に立て、bm_peer_manager_list_top(接続候補選定)
     * から除外することで、そもそも自分自身へ接続を試みないようにする。 */
    "is_self INTEGER NOT NULL DEFAULT 0, "
    "last_attempt INTEGER NOT NULL DEFAULT 0, "
    "PRIMARY KEY (ip_address, port, stream)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_hosts_stream_rating ON hosts(stream, rating DESC);";

int bm_peer_manager_init_schema(sqlite3 *db)
{
    if (bm_db_init_schema(db, SCHEMA_SQL) != 0)
    {
        return -1;
    }
    /* §11 2026-08-22: is_self列は追加時点で既に稼働中のpeers.dbには存在しない。
     * "CREATE TABLE IF NOT EXISTS"はテーブルが既に存在する場合まるごとno-opのため、
     * SCHEMA_SQLを変更しただけでは既存DBに列が増えない。ALTER TABLEで個別に追加を試み、
     * 新規DB(SCHEMA_SQLのCREATE TABLE時点で既にis_self列を含む)では必ず発生する
     * "duplicate column name"エラーは無視する(戻り値を見ないのはこのため)。 */
    sqlite3_exec(db, "ALTER TABLE hosts ADD COLUMN is_self INTEGER NOT NULL DEFAULT 0;", NULL, NULL, NULL);
    /* §11 2026-08-24: last_attempt列も同様に既存DBへ後付けする(is_self追加時と同じ理由)。 */
    sqlite3_exec(db, "ALTER TABLE hosts ADD COLUMN last_attempt INTEGER NOT NULL DEFAULT 0;", NULL, NULL, NULL);
    return 0;
}

int bm_peer_manager_upsert(sqlite3 *db, const struct bm_peer_entry *entry)
{
    static const char *SQL =
        "INSERT INTO hosts (ip_address, port, stream, services, last_seen, rating, source) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
        "ON CONFLICT(ip_address, port, stream) DO UPDATE SET "
        "services=excluded.services, last_seen=excluded.last_seen, "
        "rating=excluded.rating, source=excluded.source;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, entry->ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, entry->port);
    sqlite3_bind_int(stmt, 3, entry->stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)entry->services);
    sqlite3_bind_int64(stmt, 5, entry->last_seen);
    sqlite3_bind_double(stmt, 6, entry->rating);
    sqlite3_bind_text(stmt, 7, entry->source, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_list_top(sqlite3 *db, int stream, struct bm_peer_entry *results,
                              int max_results, int *out_count)
{
    /* §11 2026-08-22: is_self=1(自分自身、bm_peer_manager_mark_self参照)の行は
     * 接続候補から常に除外する。自分自身へ接続しようとする(自分のonionpeer自己announceが
     * gossip経由で自分のpeers.dbへ戻ってくるケース等)のを未然に防ぐ。 */
    static const char *SQL =
        "SELECT ip_address, port, stream, services, last_seen, rating, source, last_attempt "
        "FROM hosts WHERE stream = ?1 AND is_self = 0 ORDER BY rating DESC LIMIT ?2;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, stream);
    sqlite3_bind_int(stmt, 2, max_results);

    int count = 0;
    while (count < max_results && sqlite3_step(stmt) == SQLITE_ROW)
    {
        struct bm_peer_entry *e = &results[count];
        memset(e, 0, sizeof(*e));
        const unsigned char *ip = sqlite3_column_text(stmt, 0);
        strncpy(e->ip_address, (const char *)ip, sizeof(e->ip_address) - 1);
        e->port = sqlite3_column_int(stmt, 1);
        e->stream = sqlite3_column_int(stmt, 2);
        e->services = (uint64_t)sqlite3_column_int64(stmt, 3);
        e->last_seen = sqlite3_column_int64(stmt, 4);
        e->rating = sqlite3_column_double(stmt, 5);
        const unsigned char *source = sqlite3_column_text(stmt, 6);
        if (source != NULL)
        {
            strncpy(e->source, (const char *)source, sizeof(e->source) - 1);
        }
        e->last_attempt = sqlite3_column_int64(stmt, 7);
        count++;
    }
    sqlite3_finalize(stmt);

    if (out_count)
    {
        *out_count = count;
    }
    return 0;
}

int bm_peer_manager_list_shareable(sqlite3 *db, int stream, int64_t now, struct bm_peer_entry *results,
                                    int max_results, int *out_count)
{
    static const char *SQL =
        "SELECT ip_address, port, stream, services, last_seen, rating, source "
        "FROM hosts WHERE stream = ?1 AND is_self = 0 AND rating >= 0 AND last_seen > ?2 "
        "AND ip_address NOT LIKE '%.onion' ORDER BY rating DESC LIMIT ?3;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, stream);
    sqlite3_bind_int64(stmt, 2, now - BM_PEER_SHARE_MAX_AGE_SECONDS);
    sqlite3_bind_int(stmt, 3, max_results);

    int count = 0;
    while (count < max_results && sqlite3_step(stmt) == SQLITE_ROW)
    {
        struct bm_peer_entry *e = &results[count];
        memset(e, 0, sizeof(*e));
        const unsigned char *ip = sqlite3_column_text(stmt, 0);
        strncpy(e->ip_address, (const char *)ip, sizeof(e->ip_address) - 1);
        e->port = sqlite3_column_int(stmt, 1);
        e->stream = sqlite3_column_int(stmt, 2);
        e->services = (uint64_t)sqlite3_column_int64(stmt, 3);
        e->last_seen = sqlite3_column_int64(stmt, 4);
        e->rating = sqlite3_column_double(stmt, 5);
        const unsigned char *source = sqlite3_column_text(stmt, 6);
        if (source != NULL)
        {
            strncpy(e->source, (const char *)source, sizeof(e->source) - 1);
        }
        count++;
    }
    sqlite3_finalize(stmt);

    if (out_count)
    {
        *out_count = count;
    }
    return 0;
}

int bm_peer_manager_load_observed_nodes(sqlite3 *db, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        return 0;
    }

    int64_t now = (int64_t)time(NULL);
    int loaded = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) != NULL)
    {
        char ip[64];
        int port = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t')
        {
            p++;
        }
        if (*p == '#' || *p == '\n' || *p == '\0')
        {
            continue;
        }
        if (sscanf(p, "%63s %d", ip, &port) != 2 || port <= 0 || port > 65535)
        {
            continue;
        }

        struct bm_peer_entry entry;
        memset(&entry, 0, sizeof(entry));
        /* §11 2026-08-24 backlog項目10(Releaseビルド検証)で発覚: strncpy+手動NUL終端の
         * 組み合わせでも、srcの最大長(sscanfの%63s)とdestサイズがちょうど一致する場合
         * -Wstringop-truncationが警告する(手動NUL終端の有無をGCCは追跡しない)。
         * snprintfなら常にNUL終端されることが型から明らかなため警告が出ない。 */
        snprintf(entry.ip_address, sizeof(entry.ip_address), "%s", ip);
        entry.port = port;
        entry.stream = 1;
        entry.services = 1;
        entry.last_seen = now;
        entry.rating = 0.0;
        strncpy(entry.source, "observed_seed", sizeof(entry.source) - 1);
        if (bm_peer_manager_upsert(db, &entry) == 0)
        {
            loaded++;
        }
    }
    fclose(f);
    return loaded;
}

int bm_peer_manager_seed_bootstrap(sqlite3 *db, int testnet, const char *observed_nodes_path)
{
    sqlite3_stmt *count_stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM hosts;", -1, &count_stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    int existing = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW)
    {
        existing = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);
    if (existing > 0)
    {
        return 0; /* 既に何かある場合は上書きしない */
    }

    const struct bootstrap_node *seeds = testnet ? TESTNET_SEEDS : MAINNET_SEEDS;
    size_t seed_count = testnet
        ? sizeof(TESTNET_SEEDS) / sizeof(TESTNET_SEEDS[0])
        : sizeof(MAINNET_SEEDS) / sizeof(MAINNET_SEEDS[0]);

    int64_t now = (int64_t)time(NULL);
    for (size_t i = 0; i < seed_count; i++)
    {
        struct bm_peer_entry entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.ip_address, seeds[i].ip, sizeof(entry.ip_address) - 1);
        entry.port = seeds[i].port;
        entry.stream = 1;
        entry.services = 1;
        entry.last_seen = now;
        entry.rating = 0.0;
        strncpy(entry.source, "seed", sizeof(entry.source) - 1);
        if (bm_peer_manager_upsert(db, &entry) != 0)
        {
            return -1;
        }
    }
    bm_log_info("[peer_manager] seeded %zu bootstrap nodes (%s)\n", seed_count,
            testnet ? "testnet" : "mainnet");

    if (!testnet)
    {
        int observed = bm_peer_manager_load_observed_nodes(db, observed_nodes_path);
        if (observed > 0)
        {
            bm_log_info(
                    "[peer_manager] seeded %d observed node(s) from %s "
                    "(unverified operators, see DESIGN.md §11)\n",
                    observed, observed_nodes_path);
        }
    }
    return 0;
}

int bm_peer_manager_upsert_learned(sqlite3 *db, const char *ip_address, int port, int stream,
                                    uint64_t services, int64_t last_seen, const char *source)
{
    static const char *SQL =
        "INSERT INTO hosts (ip_address, port, stream, services, last_seen, rating, source) "
        "VALUES (?1, ?2, ?3, ?4, ?5, 0.0, ?6) "
        "ON CONFLICT(ip_address, port, stream) DO UPDATE SET "
        "services=excluded.services, last_seen=excluded.last_seen;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)services);
    sqlite3_bind_int64(stmt, 5, last_seen);
    sqlite3_bind_text(stmt, 6, source, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_mark_self(sqlite3 *db, const char *ip_address, int port, int stream)
{
    /* 既存行(gossip等で自分のアドレスが既に"よそのpeer"として学習済みだった場合)があれば
     * is_selfだけ立てて他の列(rating/source等の履歴)はそのまま残す。無ければ新規に
     * source='self'の行として作る。 */
    static const char *SQL =
        "INSERT INTO hosts (ip_address, port, stream, services, last_seen, rating, source, is_self) "
        "VALUES (?1, ?2, ?3, 0, ?4, 0.0, 'self', 1) "
        "ON CONFLICT(ip_address, port, stream) DO UPDATE SET is_self = 1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_cleanup(sqlite3 *db, int64_t now)
{
    static const char *SQL =
        "DELETE FROM hosts WHERE "
        "(?1 - last_seen > ?2) OR "
        "(?1 - last_seen > ?3 AND rating <= ?4);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_int64(stmt, 2, BM_PEER_CLEANUP_MAX_AGE_SECONDS);
    sqlite3_bind_int64(stmt, 3, BM_PEER_CLEANUP_MIN_AGE_SECONDS);
    sqlite3_bind_double(stmt, 4, BM_PEER_CLEANUP_FORGET_RATING);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        return -1;
    }
    int deleted = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    return deleted;
}

int bm_peer_manager_record_result(sqlite3 *db, const char *ip_address, int port, int stream, int success)
{
    const char *sql = success
        ? "UPDATE hosts SET rating = MIN(1.0, rating + 0.1), last_seen = ?4 "
          "WHERE ip_address = ?1 AND port = ?2 AND stream = ?3;"
        : "UPDATE hosts SET rating = MAX(-1.0, rating - 0.1) "
          "WHERE ip_address = ?1 AND port = ?2 AND stream = ?3;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    if (success)
    {
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
    }

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bm_peer_manager_record_attempt(sqlite3 *db, const char *ip_address, int port, int stream, int64_t now)
{
    static const char *SQL = "UPDATE hosts SET last_attempt = ?4 WHERE ip_address = ?1 AND port = ?2 AND stream = ?3;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, stream);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
