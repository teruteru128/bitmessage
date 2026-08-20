#include "hash.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

static void digest_oneshot(const char *algo, const unsigned char *data, size_t len,
                            unsigned char *out, unsigned int out_len)
{
    EVP_MD *md = EVP_MD_fetch(NULL, algo, NULL);
    unsigned int written = 0;
    EVP_Digest(data, len, out, &written, md, NULL);
    EVP_MD_free(md);
    (void)out_len;
}

void bm_sha256(const unsigned char *data, size_t len, unsigned char out[32])
{
    digest_oneshot("SHA256", data, len, out, 32);
}

void bm_sha512(const unsigned char *data, size_t len, unsigned char out[64])
{
    digest_oneshot("SHA512", data, len, out, 64);
}

void bm_double_sha256(const unsigned char *data, size_t len, unsigned char out[32])
{
    unsigned char first[32];
    bm_sha256(data, len, first);
    bm_sha256(first, 32, out);
}

void bm_double_sha512(const unsigned char *data, size_t len, unsigned char out[64])
{
    unsigned char first[64];
    bm_sha512(data, len, first);
    bm_sha512(first, 64, out);
}

void bm_ripemd160(const unsigned char *data, size_t len, unsigned char out[20])
{
    digest_oneshot("RIPEMD160", data, len, out, 20);
}

void bm_inventory_hash(const unsigned char *payload, size_t len, unsigned char out[32])
{
    unsigned char full[64];
    bm_double_sha512(payload, len, full);
    for (int i = 0; i < 32; i++)
    {
        out[i] = full[i];
    }
}

int bm_hmac_sha256(const unsigned char *key, size_t key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char out[32])
{
    unsigned int out_len = 0;
    unsigned char *result = HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
    return (result != NULL && out_len == 32) ? 0 : -1;
}
