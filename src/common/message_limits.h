#ifndef BM_MESSAGE_LIMITS_H
#define BM_MESSAGE_LIMITS_H

#include <stddef.h>

/*
 * subject + body の合計バイト数の上限。
 *
 * §11 2026-09-16 CLIのsend-message/send-broadcastへ--body-file(長文の本文をファイル/
 * 標準入力から渡す手段)を追加するにあたり、それまで本文長の検査がsendMessage/
 * sendBroadcastのどちらにも無かったことが分かったので追加した。検査が無い状態では、
 * 上限超過は「PoWを回し切った後にinfra/object_sync.cのBM_MAX_OBJECT_PAYLOAD_SIZE
 * (= 1<<18)で弾かれる」という形でしか現れず、長時間待たされた末に配信されない。
 *
 * 値はPyBitmessage本家の実ソースを直接確認して合わせた(src/api.py:1212の
 * HandleSendMessage、および src/api.py:1258 の HandleSendBroadcast。いずれも
 *   if len(subject + message) > (2 ** 18 - 500):
 *       raise APIError(27, 'Message is too long.')
 * )。2^18はobject全体長の上限そのもの(object_sync.cのBM_MAX_OBJECT_PAYLOAD_SIZE参照)。
 * 500バイトのマージンの根拠は、現行ソースには残っていないが、導入時のコミット(PyBitmessage
 * c3060622、2014-08-27 "Bitmessage Protocol Version Three")のUI側コメントにある:
 *   "The whole network message must fit in 2^18 bytes. Let's assume 500 bytes of overhead."
 * つまり「object全体(ヘッダ・署名・暗号化・埋め込みack込み)を2^18に収めるための概算の
 * 余裕」である。独自に広げると仕様上の上限を超えるオブジェクトを作りうるため、あえて本家と
 * 同じ値のままにしている。
 *
 * なお「subjectとbodyの合計」で見るのは本家の判定式に合わせたもので、実際のmsg
 * payloadはこの2つ以外にも項目を含む(だからこそ上のマージンがある)。
 */
#define BM_MAX_SUBJECT_PLUS_BODY_LEN ((size_t)((1u << 18) - 500))

#endif /* BM_MESSAGE_LIMITS_H */
