#include "crypto.h"

/* TODO(§3.1, §3.2): ECIES/ECDSAの実装。次の実装フェーズで着手する。 */

int bm_crypto_ecies_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                             const unsigned char recipient_pub[65],
                             unsigned char **out, size_t *out_len)
{
    (void)plaintext;
    (void)plaintext_len;
    (void)recipient_pub;
    (void)out;
    (void)out_len;
    return -1;
}

int bm_crypto_ecies_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                             const unsigned char priv[32],
                             unsigned char **out, size_t *out_len)
{
    (void)ciphertext;
    (void)ciphertext_len;
    (void)priv;
    (void)out;
    (void)out_len;
    return -1;
}

int bm_crypto_sign(const unsigned char *data, size_t data_len,
                    const unsigned char priv[32],
                    unsigned char **out_sig, size_t *out_sig_len)
{
    (void)data;
    (void)data_len;
    (void)priv;
    (void)out_sig;
    (void)out_sig_len;
    return -1;
}

int bm_crypto_verify(const unsigned char *data, size_t data_len,
                      const unsigned char *sig, size_t sig_len,
                      const unsigned char pub[65])
{
    (void)data;
    (void)data_len;
    (void)sig;
    (void)sig_len;
    (void)pub;
    return 0;
}
