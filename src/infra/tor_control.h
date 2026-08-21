#ifndef BM_INFRA_TOR_CONTROL_H
#define BM_INFRA_TOR_CONTROL_H

/*
 * §11 inbound接続 Stage 2: Tor Control Protocol(control-spec.txt)経由でhidden serviceを
 * 自動作成する。Stage 1(network.cのbm_network_listen、Tor非依存の生TCP listen/accept)の上に
 * 被さる薄い層で、「外部からonion経由で received した接続をどこへ転送するか」の配線
 * (ADD_ONIONのPortマッピング)だけを担当する。PyBitmessageのproxyconfig_stem.py
 * (stemライブラリでControlPortに接続しADD_ONIONする)と同じアプローチ。
 *
 * 認証はCookie認証のみ対応(SAFECOOKIEのHMACチャレンジ/レスポンスは実装しない)。
 * ControlPortが同一ホスト上にあり、Cookieファイルを読めること自体が既に「ローカルの
 * 信頼された立場」の証明になっているため、Tor自体が本来SAFECOOKIEを要求する主目的
 * (ネットワーク越しの盗聴対策)はここでは当てはまらない。HASHEDPASSWORDのみの構成は
 * 現状サポートしない(パスワード管理をv1のスコープに含めない)。
 */

struct bm_tor_control_config
{
    /* NULL以外ならAF_UNIXでこのパスへの接続を優先的に試みる */
    const char *control_socket_path;
    /* control_socket_pathがNULL、または接続に失敗した場合のTCPフォールバック先 */
    const char *control_host;
    int control_port;
};

/*
 * ControlPortへ接続し、PROTOCOLINFOでCookie認証ファイルの場所を特定してAUTHENTICATEする。
 * 成功時は接続済みのfd(このままbm_tor_control_add_onionに渡す)、失敗時-1。
 * 失敗理由はfprintf(stderr, "[tor_control] ...")に診断ログを出す(peer_connector.cの
 * SOCKS5クライアントと同方針)。
 */
int bm_tor_control_connect_and_authenticate(const struct bm_tor_control_config *config);

/*
 * ADD_ONIONでhidden serviceを作成/再開する。
 * existing_private_keyがNULLなら新規鍵生成(NEW:ED25519-V3)、非NULLならその鍵を再利用する
 * (control-spec準拠の"ED25519-V3:<base64>"形式の文字列そのものを渡すこと)。
 * virtual_port(onion経由で外部から見えるポート番号。Bitmessageの慣習で8444)を
 * 127.0.0.1:local_port(bm_network_listenで実際にlistenしているポート)へフォワードする
 * よう設定する。
 *
 * 意図的にFlags=Detachは指定しない: この呼び出しに使ったfd(=bm_tor_control_connect_and_
 * authenticateが返したcontrol接続)をbitmessagedプロセスの生存期間ずっと開いたままにする
 * ことで、hidden serviceのライフサイクルをプロセスの生存期間と一致させる設計とした。
 * こうすると正常終了・クラッシュのどちらでもプロセス終了時にOSがfdを閉じ、Torがcontrol
 * 接続の切断を検知して自動的にhidden serviceを削除してくれるため、次回起動時に同じ
 * 永続化済みの鍵でADD_ONIONしても衝突しない。実際にFlags=Detachを付けて検証したところ、
 * 「control接続を閉じてもhidden serviceは残る」ため次回起動時に
 * "550 Onion address collision"で失敗することを確認した(tests/test_tor_control.c参照)。
 *
 * 成功時0を返し、*out_onion_address(malloc済み、"xxxxx.onion"形式、呼び出し側でfree)を
 * 設定する。existing_private_keyがNULLだった場合のみ*out_private_key(malloc済み、
 * "ED25519-V3:..."形式、呼び出し側でfree)も設定する(鍵再利用時はTorが鍵を返さないため
 * *out_private_keyはNULLのまま)。失敗時-1、out_onion_addressとout_private_keyはどちらも触らない。
 */
int bm_tor_control_add_onion(int fd, const char *existing_private_key, int virtual_port, int local_port,
                              char **out_onion_address, char **out_private_key);

#endif /* BM_INFRA_TOR_CONTROL_H */
