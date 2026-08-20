#include "base58.h"

#include <openssl/bn.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#define BASE_58 58

static char divmod58(unsigned char *number, size_t length, size_t start_at)
{
    int remainder = 0;
    for (size_t i = start_at; i < length; i++)
    {
        int digit256 = number[i] & 0xFF;
        int temp = (remainder << 8) + digit256;
        number[i] = (unsigned char)(temp / BASE_58);
        remainder = temp % BASE_58;
    }
    return (char)remainder;
}

char *bm_base58_encode(const unsigned char *input, size_t length)
{
    if (input == NULL || length == 0)
    {
        return NULL;
    }

    unsigned char *work = malloc(length);
    if (work == NULL)
    {
        return NULL;
    }
    memcpy(work, input, length);

    size_t zero_count = 0;
    while (zero_count < length && work[zero_count] == 0)
    {
        zero_count++;
    }

    size_t temp_len = length * 2;
    char *temp = malloc(temp_len);
    if (temp == NULL)
    {
        free(work);
        return NULL;
    }
    memset(temp, 0, temp_len);

    size_t j = temp_len;
    size_t start_at = zero_count;
    while (start_at < length)
    {
        int mod = divmod58(work, length, start_at);
        if (work[start_at] == 0)
        {
            ++start_at;
        }
        temp[--j] = ALPHABET[(unsigned char)mod];
    }
    free(work);

    while (j < temp_len && temp[j] == ALPHABET[0])
    {
        ++j;
    }
    while (zero_count--)
    {
        temp[--j] = ALPHABET[0];
    }

    size_t output_len = temp_len - j;
    char *output = malloc(output_len + 1);
    if (output == NULL)
    {
        free(temp);
        return NULL;
    }
    memcpy(output, &temp[j], output_len);
    output[output_len] = '\0';
    free(temp);
    return output;
}

/*
 * PyBitmessageのdecodeBase58は「文字列全体を1個の多倍長整数として解釈しバイト列に変換する」
 * 純粋な整数往復(addresses.py:185, hex(integer)経由)であり、Bitcoin式の「先頭の0x00バイトを
 * '1'文字の個数で表現する」変換は行っていない。BMアドレスのpayloadは常にversion varint(非ゼロ)
 * から始まるため実害はないが、この関数もPyBitmessageに合わせて純粋な整数変換のみ行う
 * (bm_base58_encode側の先頭ゼロバイト保持ロジックとは非対称。WIF等、先頭ゼロバイトが
 * 起こりうるデータに使う場合は要再検証)。
 */
int bm_base58_decode(const char *input, unsigned char **out, size_t *out_len)
{
    if (input == NULL || input[0] == '\0')
    {
        return -1;
    }

    BIGNUM *value = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *digit_bn = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (value == NULL || base == NULL || digit_bn == NULL || ctx == NULL)
    {
        BN_free(value);
        BN_free(base);
        BN_free(digit_bn);
        BN_CTX_free(ctx);
        return -1;
    }
    BN_zero(value);
    BN_set_word(base, BASE_58);

    int rc = 0;
    for (const char *p = input; *p != '\0'; p++)
    {
        const char *pos = strchr(ALPHABET, *p);
        if (pos == NULL)
        {
            rc = -1;
            break;
        }
        int digit = (int)(pos - ALPHABET);
        BN_set_word(digit_bn, (unsigned long)digit);
        if (BN_mul(value, value, base, ctx) != 1 || BN_add(value, value, digit_bn) != 1)
        {
            rc = -1;
            break;
        }
    }

    if (rc == 0)
    {
        int num_bytes = BN_num_bytes(value);
        unsigned char *buf = malloc((size_t)num_bytes > 0 ? (size_t)num_bytes : 1);
        if (buf == NULL)
        {
            rc = -1;
        }
        else
        {
            BN_bn2bin(value, buf);
            *out = buf;
            *out_len = (size_t)num_bytes;
        }
    }

    BN_free(value);
    BN_free(base);
    BN_free(digit_bn);
    BN_CTX_free(ctx);
    return rc;
}
