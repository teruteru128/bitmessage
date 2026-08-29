#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cursor
{
    const char *p;
    const char *end;
};

static void skip_ws(struct cursor *c)
{
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
    {
        c->p++;
    }
}

static bm_json_value_t *value_new(enum bm_json_type type)
{
    bm_json_value_t *v = calloc(1, sizeof(bm_json_value_t));
    if (v != NULL)
    {
        v->type = type;
    }
    return v;
}

void bm_json_free(bm_json_value_t *v)
{
    if (v == NULL)
    {
        return;
    }
    switch (v->type)
    {
    case BM_JSON_STRING:
        free(v->string);
        break;
    case BM_JSON_ARRAY:
        for (size_t i = 0; i < v->item_count; i++)
        {
            bm_json_free(v->items[i]);
        }
        free(v->items);
        break;
    case BM_JSON_OBJECT:
        for (size_t i = 0; i < v->pair_count; i++)
        {
            free(v->keys[i]);
            bm_json_free(v->values[i]);
        }
        free(v->keys);
        free(v->values);
        break;
    default:
        break;
    }
    free(v);
}

/* --- パーサ --- */

static bm_json_value_t *parse_value(struct cursor *c);

static int match_literal(struct cursor *c, const char *lit)
{
    size_t len = strlen(lit);
    if ((size_t)(c->end - c->p) < len || memcmp(c->p, lit, len) != 0)
    {
        return 0;
    }
    c->p += len;
    return 1;
}

static bm_json_value_t *parse_number(struct cursor *c)
{
    const char *start = c->p;
    if (c->p < c->end && *c->p == '-')
    {
        c->p++;
    }
    if (c->p >= c->end || *c->p < '0' || *c->p > '9')
    {
        return NULL;
    }
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9')
    {
        c->p++;
    }
    if (c->p < c->end && *c->p == '.')
    {
        c->p++;
        if (c->p >= c->end || *c->p < '0' || *c->p > '9')
        {
            return NULL;
        }
        while (c->p < c->end && *c->p >= '0' && *c->p <= '9')
        {
            c->p++;
        }
    }
    if (c->p < c->end && (*c->p == 'e' || *c->p == 'E'))
    {
        c->p++;
        if (c->p < c->end && (*c->p == '+' || *c->p == '-'))
        {
            c->p++;
        }
        if (c->p >= c->end || *c->p < '0' || *c->p > '9')
        {
            return NULL;
        }
        while (c->p < c->end && *c->p >= '0' && *c->p <= '9')
        {
            c->p++;
        }
    }

    size_t len = (size_t)(c->p - start);
    char *buf = malloc(len + 1);
    memcpy(buf, start, len);
    buf[len] = '\0';
    double d = strtod(buf, NULL);
    free(buf);

    bm_json_value_t *v = value_new(BM_JSON_NUMBER);
    if (v != NULL)
    {
        v->number = d;
    }
    return v;
}

/* UTF-8への簡易変換(BMPのみ、サロゲートペアは非対応で代替文字を出す) */
static void append_utf8(char **out, size_t *out_len, size_t *out_cap, unsigned int cp)
{
    unsigned char bytes[4];
    size_t n;
    if (cp < 0x80)
    {
        bytes[0] = (unsigned char)cp;
        n = 1;
    }
    else if (cp < 0x800)
    {
        bytes[0] = (unsigned char)(0xC0 | (cp >> 6));
        bytes[1] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 2;
    }
    else
    {
        bytes[0] = (unsigned char)(0xE0 | (cp >> 12));
        bytes[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        bytes[2] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 3;
    }
    if (*out_len + n + 1 > *out_cap)
    {
        *out_cap = (*out_cap == 0 ? 16 : *out_cap * 2);
        while (*out_len + n + 1 > *out_cap)
        {
            *out_cap *= 2;
        }
        *out = realloc(*out, *out_cap);
    }
    memcpy(*out + *out_len, bytes, n);
    *out_len += n;
}

/*
 * §11 2026-08-29 生バイトをそのままバッファへ追加する(append_utf8と違いUnicodeコードポイントとして
 * 再エンコードしない)。JSON文字列中の非ASCIIバイトは既にUTF-8としてエンコード済みの生バイト列
 * (仕様上そのまま埋め込んでよい)なので、これをコードポイントとして再解釈・再エンコードしてはいけない。
 */
static void append_raw_byte(char **out, size_t *out_len, size_t *out_cap, unsigned char byte)
{
    if (*out_len + 1 + 1 > *out_cap)
    {
        *out_cap = (*out_cap == 0 ? 16 : *out_cap * 2);
        while (*out_len + 1 + 1 > *out_cap)
        {
            *out_cap *= 2;
        }
        *out = realloc(*out, *out_cap);
    }
    (*out)[*out_len] = (char)byte;
    *out_len += 1;
}

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return ch - 'A' + 10;
    }
    return -1;
}

static char *parse_string_raw(struct cursor *c)
{
    if (c->p >= c->end || *c->p != '"')
    {
        return NULL;
    }
    c->p++;

    char *out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;

    while (c->p < c->end && *c->p != '"')
    {
        unsigned char ch = (unsigned char)*c->p;
        if (ch == '\\')
        {
            c->p++;
            if (c->p >= c->end)
            {
                free(out);
                return NULL;
            }
            char esc = *c->p;
            c->p++;
            switch (esc)
            {
            case '"':
                append_utf8(&out, &out_len, &out_cap, '"');
                break;
            case '\\':
                append_utf8(&out, &out_len, &out_cap, '\\');
                break;
            case '/':
                append_utf8(&out, &out_len, &out_cap, '/');
                break;
            case 'b':
                append_utf8(&out, &out_len, &out_cap, '\b');
                break;
            case 'f':
                append_utf8(&out, &out_len, &out_cap, '\f');
                break;
            case 'n':
                append_utf8(&out, &out_len, &out_cap, '\n');
                break;
            case 'r':
                append_utf8(&out, &out_len, &out_cap, '\r');
                break;
            case 't':
                append_utf8(&out, &out_len, &out_cap, '\t');
                break;
            case 'u':
            {
                if (c->end - c->p < 4)
                {
                    free(out);
                    return NULL;
                }
                unsigned int cp = 0;
                for (int i = 0; i < 4; i++)
                {
                    int d = hex_digit(c->p[i]);
                    if (d < 0)
                    {
                        free(out);
                        return NULL;
                    }
                    cp = (cp << 4) | (unsigned int)d;
                }
                c->p += 4;
                append_utf8(&out, &out_len, &out_cap, cp);
                break;
            }
            default:
                free(out);
                return NULL;
            }
        }
        else
        {
            /*
             * §11 2026-08-29 バグ修正: 以前はchをそのままUnicodeコードポイントとしてappend_utf8に
             * 渡していたため、JSON文字列中の非ASCII文字(UTF-8マルチバイトのバイト列、例えば"で"の
             * 先頭バイト0xE3)を「コードポイントU+00E3」と誤解釈し、append_utf8内で改めて2バイトに
             * 再エンコードしてしまっていた(いわゆるUTF-8のLatin-1誤読による二重エンコーディング、
             * "Ã£ÂÂ"のような文字化けパターン)。実際のkeys.datインポートで日本語ラベルが文字化けする
             * バグとしてユーザーに発見された。0x80以上のバイトは既にUTF-8としてエンコード済みの
             * 生バイト列(JSON仕様上そのまま埋め込んでよい)なので、コードポイントとして
             * 再解釈せず生バイトのままコピーする。ASCII範囲(0x7F以下)は従来通りappend_utf8でよい
             * (1バイトのままコピーされるだけで実質的に差は無いが、経路を分けて意図を明確にする)。
             */
            if (ch < 0x80)
            {
                append_utf8(&out, &out_len, &out_cap, ch);
            }
            else
            {
                append_raw_byte(&out, &out_len, &out_cap, ch);
            }
            c->p++;
        }
    }

    if (c->p >= c->end || *c->p != '"')
    {
        free(out);
        return NULL;
    }
    c->p++; /* 閉じる " */

    if (out == NULL)
    {
        out = malloc(1);
        out_len = 0;
    }
    if (out_len + 1 > out_cap)
    {
        out = realloc(out, out_len + 1);
    }
    out[out_len] = '\0';
    return out;
}

static bm_json_value_t *parse_string(struct cursor *c)
{
    char *s = parse_string_raw(c);
    if (s == NULL)
    {
        return NULL;
    }
    bm_json_value_t *v = value_new(BM_JSON_STRING);
    if (v == NULL)
    {
        free(s);
        return NULL;
    }
    v->string = s;
    return v;
}

static bm_json_value_t *parse_array(struct cursor *c)
{
    c->p++; /* '[' */
    bm_json_value_t *v = value_new(BM_JSON_ARRAY);
    if (v == NULL)
    {
        return NULL;
    }

    skip_ws(c);
    if (c->p < c->end && *c->p == ']')
    {
        c->p++;
        return v;
    }

    for (;;)
    {
        skip_ws(c);
        bm_json_value_t *item = parse_value(c);
        if (item == NULL)
        {
            bm_json_free(v);
            return NULL;
        }
        bm_json_array_append(v, item);
        skip_ws(c);
        if (c->p >= c->end)
        {
            bm_json_free(v);
            return NULL;
        }
        if (*c->p == ',')
        {
            c->p++;
            continue;
        }
        if (*c->p == ']')
        {
            c->p++;
            break;
        }
        bm_json_free(v);
        return NULL;
    }
    return v;
}

static bm_json_value_t *parse_object(struct cursor *c)
{
    c->p++; /* '{' */
    bm_json_value_t *v = value_new(BM_JSON_OBJECT);
    if (v == NULL)
    {
        return NULL;
    }

    skip_ws(c);
    if (c->p < c->end && *c->p == '}')
    {
        c->p++;
        return v;
    }

    for (;;)
    {
        skip_ws(c);
        char *key = parse_string_raw(c);
        if (key == NULL)
        {
            bm_json_free(v);
            return NULL;
        }
        skip_ws(c);
        if (c->p >= c->end || *c->p != ':')
        {
            free(key);
            bm_json_free(v);
            return NULL;
        }
        c->p++;
        skip_ws(c);
        bm_json_value_t *val = parse_value(c);
        if (val == NULL)
        {
            free(key);
            bm_json_free(v);
            return NULL;
        }
        bm_json_object_set(v, key, val);
        free(key);

        skip_ws(c);
        if (c->p >= c->end)
        {
            bm_json_free(v);
            return NULL;
        }
        if (*c->p == ',')
        {
            c->p++;
            continue;
        }
        if (*c->p == '}')
        {
            c->p++;
            break;
        }
        bm_json_free(v);
        return NULL;
    }
    return v;
}

static bm_json_value_t *parse_value(struct cursor *c)
{
    skip_ws(c);
    if (c->p >= c->end)
    {
        return NULL;
    }
    switch (*c->p)
    {
    case '"':
        return parse_string(c);
    case '[':
        return parse_array(c);
    case '{':
        return parse_object(c);
    case 't':
        if (match_literal(c, "true"))
        {
            bm_json_value_t *v = value_new(BM_JSON_BOOL);
            if (v != NULL)
            {
                v->boolean = 1;
            }
            return v;
        }
        return NULL;
    case 'f':
        if (match_literal(c, "false"))
        {
            bm_json_value_t *v = value_new(BM_JSON_BOOL);
            if (v != NULL)
            {
                v->boolean = 0;
            }
            return v;
        }
        return NULL;
    case 'n':
        if (match_literal(c, "null"))
        {
            return value_new(BM_JSON_NULL);
        }
        return NULL;
    default:
        return parse_number(c);
    }
}

bm_json_value_t *bm_json_parse(const char *text, size_t len)
{
    struct cursor c = {text, text + len};
    bm_json_value_t *v = parse_value(&c);
    if (v == NULL)
    {
        return NULL;
    }
    skip_ws(&c);
    if (c.p != c.end)
    {
        /* 末尾に余分なデータがある(トレーリングガベージ) */
        bm_json_free(v);
        return NULL;
    }
    return v;
}

/* --- アクセサ --- */

bm_json_value_t *bm_json_object_get(const bm_json_value_t *obj, const char *key)
{
    if (obj == NULL || obj->type != BM_JSON_OBJECT)
    {
        return NULL;
    }
    for (size_t i = 0; i < obj->pair_count; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return obj->values[i];
        }
    }
    return NULL;
}

bm_json_value_t *bm_json_array_get(const bm_json_value_t *arr, size_t i)
{
    if (arr == NULL || arr->type != BM_JSON_ARRAY || i >= arr->item_count)
    {
        return NULL;
    }
    return arr->items[i];
}

const char *bm_json_as_string(const bm_json_value_t *v)
{
    if (v == NULL || v->type != BM_JSON_STRING)
    {
        return NULL;
    }
    return v->string;
}

double bm_json_as_number(const bm_json_value_t *v)
{
    if (v == NULL || v->type != BM_JSON_NUMBER)
    {
        return 0.0;
    }
    return v->number;
}

/* --- 構築ヘルパー --- */

bm_json_value_t *bm_json_new_null(void)
{
    return value_new(BM_JSON_NULL);
}

bm_json_value_t *bm_json_new_bool(int b)
{
    bm_json_value_t *v = value_new(BM_JSON_BOOL);
    if (v != NULL)
    {
        v->boolean = b ? 1 : 0;
    }
    return v;
}

bm_json_value_t *bm_json_new_number(double n)
{
    bm_json_value_t *v = value_new(BM_JSON_NUMBER);
    if (v != NULL)
    {
        v->number = n;
    }
    return v;
}

bm_json_value_t *bm_json_new_string(const char *s)
{
    bm_json_value_t *v = value_new(BM_JSON_STRING);
    if (v == NULL)
    {
        return NULL;
    }
    size_t len = strlen(s);
    v->string = malloc(len + 1);
    memcpy(v->string, s, len + 1);
    return v;
}

bm_json_value_t *bm_json_new_array(void)
{
    return value_new(BM_JSON_ARRAY);
}

bm_json_value_t *bm_json_new_object(void)
{
    return value_new(BM_JSON_OBJECT);
}

void bm_json_array_append(bm_json_value_t *arr, bm_json_value_t *item)
{
    if (arr == NULL || arr->type != BM_JSON_ARRAY)
    {
        bm_json_free(item);
        return;
    }
    arr->items = realloc(arr->items, sizeof(bm_json_value_t *) * (arr->item_count + 1));
    arr->items[arr->item_count++] = item;
}

void bm_json_object_set(bm_json_value_t *obj, const char *key, bm_json_value_t *value)
{
    if (obj == NULL || obj->type != BM_JSON_OBJECT)
    {
        bm_json_free(value);
        return;
    }
    obj->keys = realloc(obj->keys, sizeof(char *) * (obj->pair_count + 1));
    obj->values = realloc(obj->values, sizeof(bm_json_value_t *) * (obj->pair_count + 1));
    size_t len = strlen(key);
    char *key_copy = malloc(len + 1);
    memcpy(key_copy, key, len + 1);
    obj->keys[obj->pair_count] = key_copy;
    obj->values[obj->pair_count] = value;
    obj->pair_count++;
}

/* --- シリアライザ --- */

struct strbuf
{
    char *data;
    size_t len;
    size_t cap;
};

static void sb_reserve(struct strbuf *b, size_t additional)
{
    if (b->len + additional + 1 <= b->cap)
    {
        return;
    }
    size_t new_cap = b->cap == 0 ? 64 : b->cap;
    while (new_cap < b->len + additional + 1)
    {
        new_cap *= 2;
    }
    b->data = realloc(b->data, new_cap);
    b->cap = new_cap;
}

static void sb_append(struct strbuf *b, const char *s, size_t len)
{
    sb_reserve(b, len);
    memcpy(b->data + b->len, s, len);
    b->len += len;
    b->data[b->len] = '\0';
}

static void sb_append_cstr(struct strbuf *b, const char *s)
{
    sb_append(b, s, strlen(s));
}

static void sb_append_escaped_string(struct strbuf *b, const char *s)
{
    sb_append_cstr(b, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++)
    {
        switch (*p)
        {
        case '"':
            sb_append_cstr(b, "\\\"");
            break;
        case '\\':
            sb_append_cstr(b, "\\\\");
            break;
        case '\n':
            sb_append_cstr(b, "\\n");
            break;
        case '\r':
            sb_append_cstr(b, "\\r");
            break;
        case '\t':
            sb_append_cstr(b, "\\t");
            break;
        default:
            if (*p < 0x20)
            {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", *p);
                sb_append_cstr(b, buf);
            }
            else
            {
                sb_append(b, (const char *)p, 1);
            }
            break;
        }
    }
    sb_append_cstr(b, "\"");
}

static void serialize_value(struct strbuf *b, const bm_json_value_t *v)
{
    if (v == NULL)
    {
        sb_append_cstr(b, "null");
        return;
    }
    switch (v->type)
    {
    case BM_JSON_NULL:
        sb_append_cstr(b, "null");
        break;
    case BM_JSON_BOOL:
        sb_append_cstr(b, v->boolean ? "true" : "false");
        break;
    case BM_JSON_NUMBER:
    {
        char buf[64];
        double d = v->number;
        if (d == (double)(long long)d)
        {
            snprintf(buf, sizeof(buf), "%lld", (long long)d);
        }
        else
        {
            snprintf(buf, sizeof(buf), "%.17g", d);
        }
        sb_append_cstr(b, buf);
        break;
    }
    case BM_JSON_STRING:
        sb_append_escaped_string(b, v->string);
        break;
    case BM_JSON_ARRAY:
        sb_append_cstr(b, "[");
        for (size_t i = 0; i < v->item_count; i++)
        {
            if (i > 0)
            {
                sb_append_cstr(b, ",");
            }
            serialize_value(b, v->items[i]);
        }
        sb_append_cstr(b, "]");
        break;
    case BM_JSON_OBJECT:
        sb_append_cstr(b, "{");
        for (size_t i = 0; i < v->pair_count; i++)
        {
            if (i > 0)
            {
                sb_append_cstr(b, ",");
            }
            sb_append_escaped_string(b, v->keys[i]);
            sb_append_cstr(b, ":");
            serialize_value(b, v->values[i]);
        }
        sb_append_cstr(b, "}");
        break;
    }
}

char *bm_json_serialize(const bm_json_value_t *v)
{
    struct strbuf b;
    memset(&b, 0, sizeof(b));
    serialize_value(&b, v);
    if (b.data == NULL)
    {
        b.data = malloc(1);
        b.data[0] = '\0';
    }
    return b.data;
}
