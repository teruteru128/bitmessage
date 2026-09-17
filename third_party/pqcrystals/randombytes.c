/* randombytes.h の説明を参照。OpenSSLのCSPRNGへ委譲するだけの薄い実装。 */

#include "randombytes.h"

#include <stdlib.h>

#include <openssl/rand.h>

void randombytes(uint8_t *out, size_t outlen)
{
    /* RAND_bytesはint長しか受け取らない。PQ鍵生成で要求される長さは高々数十byteだが、
     * 将来の呼び出し元が大きな長さを渡しても安全なように分割して呼ぶ。失敗時は
     * 呼び出し元(参照実装側)へエラーを伝える戻り値が無いため、弱い乱数で鍵を
     * 作ってしまうよりabort()する方が安全と判断した。 */
    while (outlen > 0)
    {
        int chunk = (outlen > ((size_t)1 << 20)) ? (1 << 20) : (int)outlen;
        if (RAND_bytes(out, chunk) != 1)
        {
            abort();
        }
        out += chunk;
        outlen -= (size_t)chunk;
    }
}
