#ifndef BM_CORE_CONFIG_FILE_H
#define BM_CORE_CONFIG_FILE_H

/*
 * §11 起動時設定ファイル(INI形式、既定"bitmessage.conf"、BM_CONFIG_FILEで別の場所を指定可能)。
 * v1.1まではBM_TESTNET/BM_API_PORT/BM_INBOUND_PORT/BM_TOR_(CONTROL等)/BM_ONION_ADDRESS/
 * BM_NO_CONNECTという6系統・計9個のenv varだけで起動時設定を渡していたが、実運用で毎回
 * 同じ設定を手打ちするのは非現実的になったため導入した(ユーザーとの合意、2026-08-22)。
 *
 * 設計方針: 「起動時にしか意味を持たない設定」はこのファイル、「実行時にAPI経由で変更できる
 * 設定」(SOCKS5プロキシ等)は引き続きconfig.db(core/config_store.c)を使う、と役割分担する。
 * 静的ファイルにAPI経由のホットリロードまで持たせると複雑になりすぎるための判断。
 *
 * 優先順位: env var > 設定ファイル > 組み込みの既定値。env varは削除せず、テスト/CI用の
 * 上書き手段として残す(既存のBM_NO_CONNECT等の使われ方をそのまま活かすため)。
 *
 * API認証情報(ユーザー名/パスワード)はこのファイルに含めない。起動毎のランダム生成・
 * 非永続という既存の設計(api_server.c参照)は意図的なセキュリティ判断であり、平文設定
 * ファイルへ持ち出す変更は別途の判断が必要なため、v1.1のスコープでは行わない。
 */

#include <stddef.h>

#define BM_CONFIG_FILE_STR_MAX 256

struct bm_config_file
{
    int testnet;
    int no_connect;
    int api_port;
    int inbound_port; /* 0 = 未設定(inbound無効)。BM_INBOUND_PORTのenv var版と同じ意味 */
    int tor_control;
    char tor_control_socket[BM_CONFIG_FILE_STR_MAX];
    char tor_control_host[BM_CONFIG_FILE_STR_MAX];
    int tor_control_port;
    int tor_virtual_port;
    char onion_address[BM_CONFIG_FILE_STR_MAX]; /* 空文字列 = 未設定 */
};

/*
 * outへ既定値(main.cが元々ハードコードしていた既定値と同一)をまず設定し、pathが存在すれば
 * INI形式("#"/";"行コメント、"[section]"、"key = value")として読み込んで上書きする。
 * ファイルが存在しない場合は既定値のまま何もしない(必須ファイルではない、正常系)。
 * 認識できないセクション/キーや"="の無い行は1行ごとにfprintf(stderr, "[config_file] ...")で
 * 警告するだけで処理を継続する(1行の誤りで起動全体を止めないため)。
 * 戻り値: ファイルが実際に開けて読み込まれたら1、存在しなかった(既定値のまま)なら0。
 */
int bm_config_file_load(const char *path, struct bm_config_file *out);

#endif /* BM_CORE_CONFIG_FILE_H */
