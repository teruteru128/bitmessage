#include "varint.h"

#include <string.h>

/* §11 2026-08-23発覚のバグ修正: 0xfd/0xfe/0xff以降の多バイト部分はBitcoinのCompactSize
 * (リトルエンディアン)とは異なり、Bitmessageプロトコルではビッグエンディアン
 * (PyBitmessageのaddresses.py encodeVarint/decodeVarintが`pack('>H'/'>I'/'>Q', ...)`を
 * 使っている)。以前はリトルエンディアンで実装しており、自分自身のencode/decodeでは
 * 自己整合的なため長らく気付かれなかったが、実peerが送ってきたOBJECT_ONIONPEERの
 * varint(port)フィールド(253以上の値になる=必ず多バイト表現になる)が
 * peers.dbへ64544(=8444のバイト入れ替わり)として登録される形で顕在化した。 */

size_t bm_varint_size(uint64_t v)
{
    if (v < 0xfd)
    {
        return 1;
    }
    if (v <= 0xffff)
    {
        return 3;
    }
    if (v <= 0xffffffffULL)
    {
        return 5;
    }
    return 9;
}

unsigned char *bm_varint_encode(unsigned char *out, uint64_t v)
{
    if (out == NULL)
    {
        return NULL;
    }
    if (v < 0xfd)
    {
        out[0] = (unsigned char)v;
    }
    else if (v <= 0xffff)
    {
        out[0] = 0xfd;
        out[1] = (unsigned char)((v >> 8) & 0xff);
        out[2] = (unsigned char)(v & 0xff);
    }
    else if (v <= 0xffffffffULL)
    {
        out[0] = 0xfe;
        out[1] = (unsigned char)((v >> 24) & 0xff);
        out[2] = (unsigned char)((v >> 16) & 0xff);
        out[3] = (unsigned char)((v >> 8) & 0xff);
        out[4] = (unsigned char)(v & 0xff);
    }
    else
    {
        out[0] = 0xff;
        out[1] = (unsigned char)((v >> 56) & 0xff);
        out[2] = (unsigned char)((v >> 48) & 0xff);
        out[3] = (unsigned char)((v >> 40) & 0xff);
        out[4] = (unsigned char)((v >> 32) & 0xff);
        out[5] = (unsigned char)((v >> 24) & 0xff);
        out[6] = (unsigned char)((v >> 16) & 0xff);
        out[7] = (unsigned char)((v >> 8) & 0xff);
        out[8] = (unsigned char)(v & 0xff);
    }
    return out;
}

size_t bm_varint_decode(const unsigned char *data, size_t data_len, uint64_t *value)
{
    if (data_len < 1)
    {
        return 0;
    }
    if (data[0] < 0xfd)
    {
        *value = data[0];
        return 1;
    }
    if (data[0] == 0xfd)
    {
        if (data_len < 3)
        {
            return 0;
        }
        *value = (((uint64_t)data[1]) << 8) | ((uint64_t)data[2]);
        return 3;
    }
    if (data[0] == 0xfe)
    {
        if (data_len < 5)
        {
            return 0;
        }
        *value = (((uint64_t)data[1]) << 24) | (((uint64_t)data[2]) << 16)
            | (((uint64_t)data[3]) << 8) | ((uint64_t)data[4]);
        return 5;
    }
    /* data[0] == 0xff */
    if (data_len < 9)
    {
        return 0;
    }
    *value = (((uint64_t)data[1]) << 56) | (((uint64_t)data[2]) << 48)
        | (((uint64_t)data[3]) << 40) | (((uint64_t)data[4]) << 32)
        | (((uint64_t)data[5]) << 24) | (((uint64_t)data[6]) << 16)
        | (((uint64_t)data[7]) << 8) | ((uint64_t)data[8]);
    return 9;
}

size_t bm_varstr_size(const char *str)
{
    size_t len = strlen(str);
    return bm_varint_size(len) + len;
}

unsigned char *bm_varstr_encode(unsigned char *out, const char *str)
{
    if (out == NULL)
    {
        return NULL;
    }
    size_t len = strlen(str);
    bm_varint_encode(out, len);
    memcpy(out + bm_varint_size(len), str, len);
    return out;
}

size_t bm_varbytes_size(size_t len)
{
    return bm_varint_size(len) + len;
}

unsigned char *bm_varbytes_encode(unsigned char *out, const unsigned char *data, size_t len)
{
    if (out == NULL)
    {
        return NULL;
    }
    bm_varint_encode(out, len);
    if (len > 0)
    {
        memcpy(out + bm_varint_size(len), data, len);
    }
    return out;
}
