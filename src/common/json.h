#ifndef BM_COMMON_JSON_H
#define BM_COMMON_JSON_H

/*
 * 最小限のJSON実装。DESIGN.md §6の自前JSON-RPC 2.0で使う。
 * 汎用JSONライブラリの依存(§3.5の「依存を増やさない」方針)を避けるための自前実装で、
 * RFC 8259のvalue文法(null/bool/number/string/array/object)を一通りサポートする。
 */

#include <stddef.h>

enum bm_json_type
{
    BM_JSON_NULL,
    BM_JSON_BOOL,
    BM_JSON_NUMBER,
    BM_JSON_STRING,
    BM_JSON_ARRAY,
    BM_JSON_OBJECT,
};

typedef struct bm_json_value bm_json_value_t;

struct bm_json_value
{
    enum bm_json_type type;
    int boolean;              /* BM_JSON_BOOL */
    double number;             /* BM_JSON_NUMBER */
    char *string;               /* BM_JSON_STRING、malloc、NUL終端 */
    bm_json_value_t **items;     /* BM_JSON_ARRAY */
    size_t item_count;
    char **keys;                  /* BM_JSON_OBJECT、各keyはmalloc、NUL終端 */
    bm_json_value_t **values;      /* BM_JSON_OBJECT、keys[i]に対応する値 */
    size_t pair_count;
};

/* text[0..len)をパースする。成功時malloc済みの値を返す(bm_json_freeで解放)。失敗時NULL */
bm_json_value_t *bm_json_parse(const char *text, size_t len);
void bm_json_free(bm_json_value_t *v);

/* オブジェクトからキーで値を引く。objがBM_JSON_OBJECTでない/見つからなければNULL */
bm_json_value_t *bm_json_object_get(const bm_json_value_t *obj, const char *key);
/* 配列のi番目を取る。arrがBM_JSON_ARRAYでない/範囲外ならNULL */
bm_json_value_t *bm_json_array_get(const bm_json_value_t *arr, size_t i);

/* 型変換ヘルパー。型が違う/vがNULLならNULL(文字列)または0を返す */
const char *bm_json_as_string(const bm_json_value_t *v); /* 内部バッファへのポインタ、freeしないこと */
double bm_json_as_number(const bm_json_value_t *v);

/* 値構築ヘルパー(レスポンス組み立て用) */
bm_json_value_t *bm_json_new_null(void);
bm_json_value_t *bm_json_new_bool(int b);
bm_json_value_t *bm_json_new_number(double n);
bm_json_value_t *bm_json_new_string(const char *s); /* strをコピーする */
bm_json_value_t *bm_json_new_array(void);
bm_json_value_t *bm_json_new_object(void);
/* itemの所有権をarrへ渡す(以後arrがbm_json_freeで解放する) */
void bm_json_array_append(bm_json_value_t *arr, bm_json_value_t *item);
/* valueの所有権をobjへ渡す */
void bm_json_object_set(bm_json_value_t *obj, const char *key, bm_json_value_t *value);

/* シリアライズ。malloc済みのNUL終端文字列を返す(呼び出し側でfree) */
char *bm_json_serialize(const bm_json_value_t *v);

#endif /* BM_COMMON_JSON_H */
