/*
 * common/json.c のテスト。パース->シリアライズの往復、JSON-RPCリクエスト形状の
 * パース、エスケープ処理、不正入力の拒否を確認する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/json.h"

static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do                                                                       \
    {                                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void test_basic_types(void)
{
    bm_json_value_t *v;

    v = bm_json_parse("null", strlen("null"));
    CHECK(v != NULL && v->type == BM_JSON_NULL, "parse null");
    bm_json_free(v);

    v = bm_json_parse("true", strlen("true"));
    CHECK(v != NULL && v->type == BM_JSON_BOOL && v->boolean == 1, "parse true");
    bm_json_free(v);

    v = bm_json_parse("false", strlen("false"));
    CHECK(v != NULL && v->type == BM_JSON_BOOL && v->boolean == 0, "parse false");
    bm_json_free(v);

    v = bm_json_parse("42", strlen("42"));
    CHECK(v != NULL && v->type == BM_JSON_NUMBER && v->number == 42.0, "parse integer");
    bm_json_free(v);

    v = bm_json_parse("-3.5e2", strlen("-3.5e2"));
    CHECK(v != NULL && v->type == BM_JSON_NUMBER && v->number == -350.0, "parse negative exponent number");
    bm_json_free(v);

    v = bm_json_parse("\"hello\\nworld\"", strlen("\"hello\\nworld\""));
    CHECK(v != NULL && v->type == BM_JSON_STRING && strcmp(v->string, "hello\nworld") == 0,
          "parse string with escape");
    bm_json_free(v);
}

static void test_array_and_object(void)
{
    bm_json_value_t *v = bm_json_parse("[1,\"two\",true,null,[3,4]]", strlen("[1,\"two\",true,null,[3,4]]"));
    CHECK(v != NULL && v->type == BM_JSON_ARRAY && v->item_count == 5, "parse nested array");
    if (v != NULL && v->item_count == 5)
    {
        CHECK(bm_json_array_get(v, 0)->number == 1.0, "array[0]");
        CHECK(strcmp(bm_json_as_string(bm_json_array_get(v, 1)), "two") == 0, "array[1]");
        CHECK(bm_json_array_get(v, 2)->boolean == 1, "array[2]");
        CHECK(bm_json_array_get(v, 3)->type == BM_JSON_NULL, "array[3]");
        bm_json_value_t *inner = bm_json_array_get(v, 4);
        CHECK(inner != NULL && inner->type == BM_JSON_ARRAY && inner->item_count == 2, "array[4] nested");
    }
    bm_json_free(v);

    bm_json_value_t *obj = bm_json_parse("{\"a\":1,\"b\":{\"c\":2}}", strlen("{\"a\":1,\"b\":{\"c\":2}}"));
    CHECK(obj != NULL && obj->type == BM_JSON_OBJECT && obj->pair_count == 2, "parse nested object");
    if (obj != NULL)
    {
        CHECK(bm_json_as_number(bm_json_object_get(obj, "a")) == 1.0, "object.a");
        bm_json_value_t *b = bm_json_object_get(obj, "b");
        CHECK(b != NULL && bm_json_as_number(bm_json_object_get(b, "c")) == 2.0, "object.b.c");
        CHECK(bm_json_object_get(obj, "nonexistent") == NULL, "missing key returns NULL");
    }
    bm_json_free(obj);
}

static void test_jsonrpc_shape(void)
{
    const char *req = "{\"jsonrpc\":\"2.0\",\"method\":\"unlockAddress\","
                       "\"params\":[\"BM-abc\",\"my passphrase\"],\"id\":1}";
    bm_json_value_t *v = bm_json_parse(req, strlen(req));
    CHECK(v != NULL, "parse jsonrpc request");
    if (v != NULL)
    {
        CHECK(strcmp(bm_json_as_string(bm_json_object_get(v, "method")), "unlockAddress") == 0,
              "jsonrpc method field");
        bm_json_value_t *params = bm_json_object_get(v, "params");
        CHECK(params != NULL && params->type == BM_JSON_ARRAY && params->item_count == 2, "jsonrpc params array");
        CHECK(strcmp(bm_json_as_string(bm_json_array_get(params, 0)), "BM-abc") == 0, "jsonrpc params[0]");
        CHECK(bm_json_as_number(bm_json_object_get(v, "id")) == 1.0, "jsonrpc id field");
    }
    bm_json_free(v);
}

static void test_serialize_roundtrip(void)
{
    bm_json_value_t *obj = bm_json_new_object();
    bm_json_object_set(obj, "jsonrpc", bm_json_new_string("2.0"));
    bm_json_object_set(obj, "id", bm_json_new_number(7));
    bm_json_value_t *result = bm_json_new_array();
    bm_json_array_append(result, bm_json_new_string("BM-one"));
    bm_json_array_append(result, bm_json_new_string("BM-two \"quoted\""));
    bm_json_object_set(obj, "result", result);

    char *text = bm_json_serialize(obj);
    CHECK(text != NULL, "serialize produced text");

    bm_json_value_t *reparsed = bm_json_parse(text, strlen(text));
    CHECK(reparsed != NULL, "reparse serialized text");
    if (reparsed != NULL)
    {
        CHECK(strcmp(bm_json_as_string(bm_json_object_get(reparsed, "jsonrpc")), "2.0") == 0, "roundtrip jsonrpc");
        CHECK(bm_json_as_number(bm_json_object_get(reparsed, "id")) == 7.0, "roundtrip id");
        bm_json_value_t *r = bm_json_object_get(reparsed, "result");
        CHECK(r != NULL && r->item_count == 2, "roundtrip result array");
        CHECK(strcmp(bm_json_as_string(bm_json_array_get(r, 1)), "BM-two \"quoted\"") == 0,
              "roundtrip escaped quote content");
    }

    free(text);
    bm_json_free(obj);
    bm_json_free(reparsed);
}

static void test_utf8_roundtrip(void)
{
    /*
     * §11 2026-08-29 バグ修正の回帰テスト。以前はparse_string_rawがJSON文字列中の非ASCII
     * バイト(UTF-8マルチバイトシーケンスの各バイト)をそのままUnicodeコードポイントとして
     * append_utf8に渡してしまい、二重にUTF-8エンコードしてしまっていた(例: "で"の先頭バイト
     * 0xE3を「コードポイントU+00E3」と誤解釈し2バイトへ再エンコード、"Ã£ÂÂ"のような
     * 文字化けを引き起こす)。実際にkeys.datインポートで日本語ラベルが文字化けするバグとして
     * ユーザーに発見された。
     */
    const char *japanese = "でじこ"; /* UTF-8: E3 81 A7 E3 81 98 E3 81 93 (9byte) */

    bm_json_value_t *s = bm_json_new_string(japanese);
    char *text = bm_json_serialize(s);
    CHECK(text != NULL, "serialize japanese string produced text");

    bm_json_value_t *reparsed = text != NULL ? bm_json_parse(text, strlen(text)) : NULL;
    CHECK(reparsed != NULL, "reparse serialized japanese string");
    if (reparsed != NULL)
    {
        const char *round_tripped = bm_json_as_string(reparsed);
        CHECK(round_tripped != NULL && strcmp(round_tripped, japanese) == 0,
              "japanese string survives serialize/parse round-trip byte-for-byte");
    }
    free(text);
    bm_json_free(s);
    bm_json_free(reparsed);

    /* daemon側が受信するリクエストにより近い形: 生のUTF-8バイト列を直接埋め込んだJSON文字列
     * リテラルをパースしても、コードポイントとして再解釈されずそのまま復元されることを確認 */
    const char *literal = "\"でじこ\"";
    bm_json_value_t *v = bm_json_parse(literal, strlen(literal));
    CHECK(v != NULL, "parse json string literal containing raw utf-8 bytes");
    if (v != NULL)
    {
        const char *parsed_str = bm_json_as_string(v);
        CHECK(parsed_str != NULL && strcmp(parsed_str, japanese) == 0,
              "parsed value matches original utf-8 bytes exactly");
    }
    bm_json_free(v);
}

static void test_invalid_inputs(void)
{
    CHECK(bm_json_parse("{invalid}", strlen("{invalid}")) == NULL, "reject malformed object");
    CHECK(bm_json_parse("[1,2,]", strlen("[1,2,]")) == NULL, "reject trailing comma in array");
    CHECK(bm_json_parse("\"unterminated", strlen("\"unterminated")) == NULL, "reject unterminated string");
    CHECK(bm_json_parse("{\"a\":1} garbage", strlen("{\"a\":1} garbage")) == NULL, "reject trailing garbage after value");
    CHECK(bm_json_parse("", strlen("")) == NULL, "reject empty input");
}

int main(void)
{
    test_basic_types();
    test_array_and_object();
    test_jsonrpc_shape();
    test_serialize_roundtrip();
    test_utf8_roundtrip();
    test_invalid_inputs();

    if (failures == 0)
    {
        printf("ALL OK\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return EXIT_FAILURE;
}
