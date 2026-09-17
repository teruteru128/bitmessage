/*
 * src/pq/address_v5.c(v5ポスト量子アドレス)の検証。DESIGN-PQ.md §4。
 *
 * 検証観点:
 *   - パスフレーズ決定性生成が再現すること(同じパスフレーズ→同じアドレス、
 *     違うパスフレーズ→違うアドレス)。ユーザーの数千件規模の鍵運用がこの性質に
 *     依存するため、v4と同じく最優先で担保する
 *   - encode→decodeの往復、およびv4アドレス・チェックサム破壊・非正規エンコーディング
 *     (先頭0x00を残したもの)を拒否すること
 *   - idが公開鍵だけに依存し、version/streamには依存しないこと(2026-09-18に
 *     version/streamを混ぜる設計を取り下げた。v3/v4のripeと同じ意味論に戻した)。
 *     逆にtagはversion/streamに依存すること
 *   - アドレス由来のKEM鍵が「アドレスを知っていれば誰でも同じものを作れる」こと
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/address.h"
#include "../src/pq/address_v5.h"

static int test_deterministic_generation(void)
{
    struct bm_pqv5_identity a;
    struct bm_pqv5_identity b;
    struct bm_pqv5_identity c;

    if (bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 0, 0, &a) != 0 ||
        bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 0, 0, &b) != 0 ||
        bm_pqv5_identity_generate_deterministic("another passphrase", 1, 0, 0, &c) != 0)
    {
        fprintf(stderr, "FAIL: deterministic generation\n");
        return 1;
    }
    if (memcmp(a.id, b.id, BM_PQV5_ID_LEN) != 0 ||
        memcmp(a.sig_pk, b.sig_pk, BM_PQV5_SIG_PK_LEN) != 0 ||
        memcmp(a.kem_pk, b.kem_pk, BM_PQV5_KEM_PK_LEN) != 0)
    {
        fprintf(stderr, "FAIL: same passphrase produced different identities\n");
        return 1;
    }
    if (memcmp(a.id, c.id, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: different passphrases produced the same id\n");
        return 1;
    }
    if (a.version != BM_PQV5_ADDRESS_VERSION || a.stream != 1)
    {
        fprintf(stderr, "FAIL: version/stream not set\n");
        return 1;
    }
    /* null_bytes=0なので探索は起きず、最初のnonceペアで確定する */
    if (a.sig_nonce != 0 || a.kem_nonce != 1)
    {
        fprintf(stderr, "FAIL: unexpected nonces %llu/%llu\n", (unsigned long long)a.sig_nonce,
                (unsigned long long)a.kem_nonce);
        return 1;
    }

    /* start_nonceを変えれば同じパスフレーズから別のアドレスが得られる(複数アドレス運用) */
    if (bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 2, 0, &b) != 0 ||
        memcmp(a.id, b.id, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: start_nonce did not change the identity\n");
        return 1;
    }
    return 0;
}

static int test_id_depends_only_on_keys(void)
{
    struct bm_pqv5_identity a;
    unsigned char id1[BM_PQV5_ID_LEN];
    unsigned char id2[BM_PQV5_ID_LEN];
    unsigned char tag1[32];
    unsigned char tag2[32];

    if (bm_pqv5_identity_generate_deterministic("id binding test", 1, 0, 0, &a) != 0)
    {
        fprintf(stderr, "FAIL: generation\n");
        return 1;
    }
    bm_pqv5_calc_id(a.sig_pk, a.kem_pk, id1);
    if (memcmp(id1, a.id, BM_PQV5_ID_LEN) != 0)
    {
        fprintf(stderr, "FAIL: calc_id does not reproduce the identity's id\n");
        return 1;
    }

    /* 公開鍵1bitの違いでidが変わること(署名鍵側・KEM鍵側の両方) */
    a.sig_pk[0] ^= 0x01;
    bm_pqv5_calc_id(a.sig_pk, a.kem_pk, id2);
    if (memcmp(id1, id2, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: id does not depend on the signing public key\n");
        return 1;
    }
    a.sig_pk[0] ^= 0x01;
    a.kem_pk[BM_PQV5_KEM_PK_LEN - 1] ^= 0x01;
    bm_pqv5_calc_id(a.sig_pk, a.kem_pk, id2);
    if (memcmp(id1, id2, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: id does not depend on the KEM public key\n");
        return 1;
    }
    a.kem_pk[BM_PQV5_KEM_PK_LEN - 1] ^= 0x01;

    /* version/streamにはidが依存しないこと(v3/v4のripeと同じ性質。
     * 同じ鍵を別version・別streamのアドレスとしても表現できる) */
    bm_pqv5_calc_id(a.sig_pk, a.kem_pk, id2);
    if (memcmp(id1, id2, BM_PQV5_ID_LEN) != 0)
    {
        fprintf(stderr, "FAIL: id is not stable\n");
        return 1;
    }

    /* 一方tagはversion/streamに依存すること(束縛はこちらが担う) */
    bm_pqv5_derive_secret_and_tag(5, 1, a.id, NULL, tag1);
    bm_pqv5_derive_secret_and_tag(5, 2, a.id, NULL, tag2);
    if (memcmp(tag1, tag2, sizeof(tag1)) == 0)
    {
        fprintf(stderr, "FAIL: tag does not depend on stream\n");
        return 1;
    }
    bm_pqv5_derive_secret_and_tag(6, 1, a.id, NULL, tag2);
    if (memcmp(tag1, tag2, sizeof(tag1)) == 0)
    {
        fprintf(stderr, "FAIL: tag does not depend on version\n");
        return 1;
    }
    return 0;
}

static int test_encode_decode(void)
{
    struct bm_pqv5_identity a;
    char *address;
    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char id[BM_PQV5_ID_LEN];
    size_t len;
    int rc = 1;

    if (bm_pqv5_identity_generate_deterministic("encode decode test", 1, 0, 0, &a) != 0)
    {
        fprintf(stderr, "FAIL: generation\n");
        return 1;
    }
    address = bm_pqv5_address_encode(a.version, a.stream, a.id);
    if (address == NULL || strncmp(address, "BM-", 3) != 0)
    {
        fprintf(stderr, "FAIL: encode\n");
        free(address);
        return 1;
    }
    len = strlen(address);
    /* 3("BM-") + Base58(varint*2 + 32byte + checksum4) は概ね50〜56文字に収まる */
    if (len < 50 || len > 60)
    {
        fprintf(stderr, "FAIL: unexpected address length %zu (%s)\n", len, address);
        goto out;
    }
    if (bm_pqv5_address_decode(address, &version, &stream, id) != 0)
    {
        fprintf(stderr, "FAIL: decode\n");
        goto out;
    }
    if (version != a.version || stream != a.stream || memcmp(id, a.id, BM_PQV5_ID_LEN) != 0)
    {
        fprintf(stderr, "FAIL: decoded values differ (version=%llu stream=%llu)\n",
                (unsigned long long)version, (unsigned long long)stream);
        goto out;
    }
    /* "BM-"は省略可 */
    if (bm_pqv5_address_decode(address + 3, &version, &stream, id) != 0)
    {
        fprintf(stderr, "FAIL: decode without the BM- prefix\n");
        goto out;
    }
    /* 1文字壊したらchecksumで落ちること(Base58の文字集合内で壊す) */
    {
        char *broken = strdup(address);
        size_t pos = strlen(broken) - 2;
        broken[pos] = (broken[pos] == 'a') ? 'b' : 'a';
        if (bm_pqv5_address_decode(broken, &version, &stream, id) == 0)
        {
            fprintf(stderr, "FAIL: corrupted address accepted\n");
            free(broken);
            goto out;
        }
        free(broken);
    }
    rc = 0;

out:
    free(address);
    return rc;
}

static int test_rejects_v4_address(void)
{
    struct bm_generated_address v4;
    char *address;
    uint64_t version = 0;
    uint64_t stream = 0;
    unsigned char id[BM_PQV5_ID_LEN];
    int rc = 1;

    if (bm_address_generate_deterministic("v4 address for rejection test", 1, &v4) != 0)
    {
        fprintf(stderr, "FAIL: v4 generation\n");
        return 1;
    }
    address = bm_address_encode(4, 1, v4.ripe, BM_RIPE_LEN);
    if (address == NULL)
    {
        fprintf(stderr, "FAIL: v4 encode\n");
        return 1;
    }
    /* チェックサムは正しいがversionが4なので、v5デコーダは拒否しなければならない */
    if (bm_pqv5_address_decode(address, &version, &stream, id) == 0)
    {
        fprintf(stderr, "FAIL: v5 decoder accepted a v4 address\n");
        goto out;
    }
    rc = 0;

out:
    free(address);
    return rc;
}

static int test_address_derived_kem_key(void)
{
    struct bm_pqv5_identity a;
    unsigned char pk1[BM_PQV5_KEM_PK_LEN];
    unsigned char sk1[BM_PQV5_KEM_SK_LEN];
    unsigned char pk2[BM_PQV5_KEM_PK_LEN];
    unsigned char sk2[BM_PQV5_KEM_SK_LEN];
    unsigned char tag1[32];
    unsigned char tag2[32];

    if (bm_pqv5_identity_generate_deterministic("address derived key test", 1, 0, 0, &a) != 0)
    {
        fprintf(stderr, "FAIL: generation\n");
        return 1;
    }
    if (bm_pqv5_address_kem_keypair(a.version, a.stream, a.id, pk1, sk1) != 0 ||
        bm_pqv5_address_kem_keypair(a.version, a.stream, a.id, pk2, sk2) != 0)
    {
        fprintf(stderr, "FAIL: address kem keypair\n");
        return 1;
    }
    if (memcmp(pk1, pk2, sizeof(pk1)) != 0 || memcmp(sk1, sk2, sizeof(sk1)) != 0)
    {
        fprintf(stderr, "FAIL: address-derived key is not deterministic\n");
        return 1;
    }
    /* アドレス由来鍵は、そのidentityが持つ本来のKEM鍵とは別物であること */
    if (memcmp(pk1, a.kem_pk, sizeof(pk1)) == 0)
    {
        fprintf(stderr, "FAIL: address-derived key equals the identity key\n");
        return 1;
    }

    bm_pqv5_derive_secret_and_tag(a.version, a.stream, a.id, NULL, tag1);
    bm_pqv5_derive_secret_and_tag(a.version, a.stream + 1, a.id, NULL, tag2);
    if (memcmp(tag1, tag2, sizeof(tag1)) == 0)
    {
        fprintf(stderr, "FAIL: tag does not depend on stream\n");
        return 1;
    }
    return 0;
}

/*
 * §11 2026-09-17 id先頭0x00の探索(null_bytes>=1)。「どちらの鍵を引き直すか」の3モードが
 * いずれも条件を満たすidを返し、かつ決定性である(同じ入力で同じアドレスになる)ことを見る。
 * 既定値BM_PQV5_DEFAULT_NULL_BYTESが実際に効いていることの確認も兼ねる。
 */
/*
 * §11 2026-09-18 id先頭0x00の探索(既定null_bytes=1)を、決定性・ランダムの両経路で見る。
 * 経路によって引き直す鍵が違う(決定性=KEM鍵ペアまるごと、ランダム=X25519だけ)ので、
 * どちらも条件を満たすidを返すこと、決定性側は再現すること、アドレス長が53文字に
 * 揃うことを確認する。
 */
static int test_null_byte_search(void)
{
    struct bm_pqv5_identity a;
    struct bm_pqv5_identity b;
    char *address;

    if (bm_pqv5_identity_generate_deterministic("null byte search", 1, 0,
                                                 BM_PQV5_DEFAULT_NULL_BYTES, &a) != 0 ||
        bm_pqv5_identity_generate_deterministic("null byte search", 1, 0,
                                                 BM_PQV5_DEFAULT_NULL_BYTES, &b) != 0)
    {
        fprintf(stderr, "FAIL: deterministic null byte search\n");
        return 1;
    }
    if (a.id[0] != 0x00)
    {
        fprintf(stderr, "FAIL: leading null byte not satisfied (deterministic)\n");
        return 1;
    }
    if (memcmp(a.id, b.id, BM_PQV5_ID_LEN) != 0 || a.sig_nonce != b.sig_nonce ||
        a.kem_nonce != b.kem_nonce)
    {
        fprintf(stderr, "FAIL: deterministic search is not reproducible\n");
        return 1;
    }
    /* v4と同じく両方のnonceが2ずつ進み、署名鍵=偶数側・KEM鍵=奇数側の割り当てが保たれる */
    if ((a.sig_nonce % 2) != 0 || a.kem_nonce != a.sig_nonce + 1)
    {
        fprintf(stderr, "FAIL: unexpected nonce layout sig=%llu kem=%llu\n",
                (unsigned long long)a.sig_nonce, (unsigned long long)a.kem_nonce);
        return 1;
    }
    /* 探索したのだから、探索なしの場合とは別のアドレスになっているはず */
    if (bm_pqv5_identity_generate_deterministic("null byte search", 1, 0, 0, &b) != 0)
    {
        fprintf(stderr, "FAIL: regeneration\n");
        return 1;
    }
    if (a.sig_nonce != 0 && memcmp(a.id, b.id, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: search did not change the id\n");
        return 1;
    }
    /* 先頭0x00が1byte削られるので、アドレスは探索なしより1文字短い53文字になる */
    address = bm_pqv5_address_encode(a.version, a.stream, a.id);
    if (address == NULL || strlen(address) != 53)
    {
        fprintf(stderr, "FAIL: unexpected address length %zu\n", address ? strlen(address) : 0);
        free(address);
        return 1;
    }
    free(address);

    /* ランダム生成側(X25519だけを引き直す経路) */
    if (bm_pqv5_identity_generate_random(1, BM_PQV5_DEFAULT_NULL_BYTES, &a) != 0 ||
        bm_pqv5_identity_generate_random(1, BM_PQV5_DEFAULT_NULL_BYTES, &b) != 0)
    {
        fprintf(stderr, "FAIL: random generation\n");
        return 1;
    }
    if (a.id[0] != 0x00 || b.id[0] != 0x00)
    {
        fprintf(stderr, "FAIL: leading null byte not satisfied (random)\n");
        return 1;
    }
    if (memcmp(a.id, b.id, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: two random identities are identical\n");
        return 1;
    }
    if (a.sig_nonce != 0 || a.kem_nonce != 0)
    {
        fprintf(stderr, "FAIL: random identity should not carry nonces\n");
        return 1;
    }
    address = bm_pqv5_address_encode(a.version, a.stream, a.id);
    if (address == NULL || strlen(address) != 53)
    {
        fprintf(stderr, "FAIL: unexpected random address length %zu\n", address ? strlen(address) : 0);
        free(address);
        return 1;
    }
    free(address);
    return 0;
}

/*
 * §11 2026-09-18 同じパスフレーズから複数アドレスを作るときのnonce領域の非重複。
 * 探索がKEM鍵nonceを2ずつ進めるため、start_nonceを素朴に0,2,4,...とすると
 * 別アドレスが同じKEM鍵を持ちうる(本家はnonceをアドレス間で継続させてこれを避けている)。
 * bm_pqv5_next_start_nonceを使えば重ならないことを確認する。
 */
static int test_multiple_addresses_do_not_share_nonces(void)
{
    struct bm_pqv5_identity a;
    struct bm_pqv5_identity b;
    uint64_t next;

    if (bm_pqv5_identity_generate_deterministic("multi address test", 1, 0,
                                                 BM_PQV5_DEFAULT_NULL_BYTES, &a) != 0)
    {
        fprintf(stderr, "FAIL: first address\n");
        return 1;
    }
    next = bm_pqv5_next_start_nonce(&a);
    if (next <= a.kem_nonce || (next % 2) != 0)
    {
        fprintf(stderr, "FAIL: next start nonce %llu is not a fresh even nonce\n",
                (unsigned long long)next);
        return 1;
    }
    if (bm_pqv5_identity_generate_deterministic("multi address test", 1, next,
                                                 BM_PQV5_DEFAULT_NULL_BYTES, &b) != 0)
    {
        fprintf(stderr, "FAIL: second address\n");
        return 1;
    }
    /* 2本目が使ったnonce域が1本目と重なっていないこと */
    if (b.sig_nonce <= a.kem_nonce)
    {
        fprintf(stderr, "FAIL: nonce ranges overlap (a.kem=%llu b.sig=%llu)\n",
                (unsigned long long)a.kem_nonce, (unsigned long long)b.sig_nonce);
        return 1;
    }
    if (memcmp(a.id, b.id, BM_PQV5_ID_LEN) == 0 ||
        memcmp(a.kem_pk, b.kem_pk, BM_PQV5_KEM_PK_LEN) == 0 ||
        memcmp(a.sig_pk, b.sig_pk, BM_PQV5_SIG_PK_LEN) == 0)
    {
        fprintf(stderr, "FAIL: two addresses share keys\n");
        return 1;
    }

    /* §11 2026-09-18: 同じstart_nonceでnull_bytesだけ変えても署名鍵を共有しないこと。
     * 署名鍵nonceを固定する実装だとここが共有され、2本のアドレスが公開的に
     * 紐付け可能になっていた(pk_sigはpubkeyオブジェクトで公開されるため) */
    if (bm_pqv5_identity_generate_deterministic("multi address test", 1, 0, 0, &b) != 0)
    {
        fprintf(stderr, "FAIL: null_bytes=0 variant\n");
        return 1;
    }
    if (memcmp(a.sig_pk, b.sig_pk, BM_PQV5_SIG_PK_LEN) == 0)
    {
        fprintf(stderr, "FAIL: addresses with different null_bytes share the signing key\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_deterministic_generation() != 0)
    {
        return 1;
    }
    if (test_id_depends_only_on_keys() != 0)
    {
        return 1;
    }
    if (test_encode_decode() != 0)
    {
        return 1;
    }
    if (test_rejects_v4_address() != 0)
    {
        return 1;
    }
    if (test_address_derived_kem_key() != 0)
    {
        return 1;
    }
    if (test_null_byte_search() != 0)
    {
        return 1;
    }
    if (test_multiple_addresses_do_not_share_nonces() != 0)
    {
        return 1;
    }
    printf("test_pq_address: OK\n");
    return 0;
}
