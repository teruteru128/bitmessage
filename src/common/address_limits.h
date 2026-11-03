#ifndef BM_COMMON_ADDRESS_LIMITS_H
#define BM_COMMON_ADDRESS_LIMITS_H

/*
 * §11 2026-11-04 アドレス文字列("BM-..."、NUL終端込み)を固定長バッファで持つときの長さ。
 *
 * 以前はidentity_store.h(BM_IDENTITY_ADDRESS_MAX)・keyring.h(BM_KEYRING_MAX_ADDRESS_LEN)・
 * messages_store.h(BM_MESSAGES_ADDRESS_MAX)がそれぞれ40を定義し、trial_decrypt.h・
 * broadcast_decrypt.h・messages_store.hの一部は即値の[40]で持っていた。v4までの
 * アドレスは最長でも"BM-"+34文字程度で40に収まるが、ポスト量子拡張のv5アドレスは
 * idが32byteなので53文字(null_bytes=0なら54文字)になり収まらない(DESIGN-PQ.md §4.3)。
 * 各所のsnprintf/strncpyはバッファ長で切り詰めるので、そのままだとv5アドレスが
 * 黙って途中で切れる。フェーズ2(受信側、DESIGN-PQ.md §9.1)に入る前に、全てを
 * この1つの定数へ揃えた。
 *
 * 64にしたのはv5の54文字+NULに余裕を持たせた2の冪。SQLiteのTEXT列には長さの制約が
 * 無いので、DBスキーマ側の変更は要らない。
 */
#define BM_ADDRESS_STR_MAX 64

#endif /* BM_COMMON_ADDRESS_LIMITS_H */
