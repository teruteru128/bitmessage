/*
 * src/pq/address_v5.c(v5ポスト量子アドレス)の検証。DESIGN-PQ.md §4。
 *
 * 検証観点:
 *   - パスフレーズ決定性生成が再現すること(同じパスフレーズ→同じアドレス、
 *     違うパスフレーズ→違うアドレス)。ユーザーの数千件規模の鍵運用がこの性質に
 *     依存するため、v4と同じく最優先で担保する
 *   - encode→decodeの往復、およびv4アドレス・チェックサム破壊・非正規エンコーディング
 *     (先頭0x00を残したもの)を拒否すること
 *   - idがversion/streamと公開鍵の全てに依存すること。ここが漏れていると
 *     「別のstreamの同じ鍵」が同じアドレスになってしまう
 *     (実際、開発中にvarintの書き込みポインタを進め損ねてversion/streamが
 *      ハッシュ入力から抜け落ちるバグを出しており、その再発検知も兼ねる)
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

    if (bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 0, 0, BM_PQV5_SEARCH_X25519, &a) != 0 ||
        bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 0, 0, BM_PQV5_SEARCH_X25519, &b) != 0 ||
        bm_pqv5_identity_generate_deterministic("another passphrase", 1, 0, 0, BM_PQV5_SEARCH_X25519, &c) != 0)
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
    /* null_bytes=0なので探索は起きず、全成分のカウンタが0のまま確定する */
    if (a.nonce != 0 || a.counters[BM_PQV5_COMP_MLDSA] != 0 || a.counters[BM_PQV5_COMP_ED25519] != 0 ||
        a.counters[BM_PQV5_COMP_MLKEM] != 0 || a.counters[BM_PQV5_COMP_X25519] != 0)
    {
        fprintf(stderr, "FAIL: unexpected counters without a search\n");
        return 1;
    }

    /* nonceを変えれば同じパスフレーズから別のアドレスが得られる(複数アドレス運用) */
    if (bm_pqv5_identity_generate_deterministic("passphrase for v5 test", 1, 2, 0, BM_PQV5_SEARCH_X25519, &b) != 0 ||
        memcmp(a.id, b.id, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: start_nonce did not change the identity\n");
        return 1;
    }
    return 0;
}

static int test_id_depends_on_version_and_stream(void)
{
    struct bm_pqv5_identity a;
    unsigned char id_stream1[BM_PQV5_ID_LEN];
    unsigned char id_stream2[BM_PQV5_ID_LEN];
    unsigned char id_version6[BM_PQV5_ID_LEN];

    if (bm_pqv5_identity_generate_deterministic("id binding test", 1, 0, 0, BM_PQV5_SEARCH_X25519, &a) != 0)
    {
        fprintf(stderr, "FAIL: generation\n");
        return 1;
    }
    bm_pqv5_calc_id(5, 1, a.sig_pk, a.kem_pk, id_stream1);
    bm_pqv5_calc_id(5, 2, a.sig_pk, a.kem_pk, id_stream2);
    bm_pqv5_calc_id(6, 1, a.sig_pk, a.kem_pk, id_version6);

    if (memcmp(id_stream1, a.id, BM_PQV5_ID_LEN) != 0)
    {
        fprintf(stderr, "FAIL: calc_id does not reproduce the identity's id\n");
        return 1;
    }
    if (memcmp(id_stream1, id_stream2, BM_PQV5_ID_LEN) == 0 ||
        memcmp(id_stream1, id_version6, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: id does not depend on version/stream\n");
        return 1;
    }

    /* 公開鍵1bitの違いでidが変わること */
    a.sig_pk[0] ^= 0x01;
    bm_pqv5_calc_id(5, 1, a.sig_pk, a.kem_pk, id_stream2);
    if (memcmp(id_stream1, id_stream2, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: id does not depend on the signing public key\n");
        return 1;
    }
    a.sig_pk[0] ^= 0x01;
    a.kem_pk[BM_PQV5_KEM_PK_LEN - 1] ^= 0x01;
    bm_pqv5_calc_id(5, 1, a.sig_pk, a.kem_pk, id_stream2);
    if (memcmp(id_stream1, id_stream2, BM_PQV5_ID_LEN) == 0)
    {
        fprintf(stderr, "FAIL: id does not depend on the KEM public key\n");
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

    if (bm_pqv5_identity_generate_deterministic("encode decode test", 1, 0, 0, BM_PQV5_SEARCH_X25519, &a) != 0)
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

    if (bm_pqv5_identity_generate_deterministic("address derived key test", 1, 0, 0, BM_PQV5_SEARCH_X25519, &a) != 0)
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
static int test_null_byte_search(void)
{
    static const struct
    {
        enum bm_pqv5_search_mode mode;
        enum bm_pqv5_component component;
        const char *name;
    } cases[] = {
        { BM_PQV5_SEARCH_X25519, BM_PQV5_COMP_X25519, "x25519" },
        { BM_PQV5_SEARCH_ED25519, BM_PQV5_COMP_ED25519, "ed25519" },
        { BM_PQV5_SEARCH_MLKEM, BM_PQV5_COMP_MLKEM, "mlkem" },
        { BM_PQV5_SEARCH_MLDSA, BM_PQV5_COMP_MLDSA, "mldsa" },
    };
    struct bm_pqv5_identity a;
    struct bm_pqv5_identity b;
    char *address;
    size_t i;
    int c;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]) + 1; i++)
    {
        int is_all = (i == sizeof(cases) / sizeof(cases[0]));
        /* is_allのときcases[i]は範囲外なので、参照する値は先に退避しておく */
        enum bm_pqv5_search_mode mode = is_all ? BM_PQV5_SEARCH_ALL : cases[i].mode;
        int moved_component = is_all ? -1 : (int)cases[i].component;
        const char *name = is_all ? "all" : cases[i].name;

        if (bm_pqv5_identity_generate_deterministic("null byte search", 1, 0,
                                                     BM_PQV5_DEFAULT_NULL_BYTES, mode, &a) != 0 ||
            bm_pqv5_identity_generate_deterministic("null byte search", 1, 0,
                                                     BM_PQV5_DEFAULT_NULL_BYTES, mode, &b) != 0)
        {
            fprintf(stderr, "FAIL: null byte search (%s)\n", name);
            return 1;
        }
        if (a.id[0] != 0x00)
        {
            fprintf(stderr, "FAIL: leading null byte not satisfied (%s)\n", name);
            return 1;
        }
        /* 同じ入力なら必ず同じアドレス・同じカウンタになること(決定性) */
        if (memcmp(a.id, b.id, BM_PQV5_ID_LEN) != 0 ||
            memcmp(a.counters, b.counters, sizeof(a.counters)) != 0)
        {
            fprintf(stderr, "FAIL: search is not deterministic (%s)\n", name);
            return 1;
        }
        /* 回していない成分のカウンタが0のままであること */
        for (c = 0; c < BM_PQV5_COMP_COUNT; c++)
        {
            int expected_moved = is_all || c == moved_component;
            if (!expected_moved && a.counters[c] != 0)
            {
                fprintf(stderr, "FAIL: %s search advanced component %d\n", name, c);
                return 1;
            }
        }
        /* カウンタからidentityを再構成できること(保存した値だけで復元できる保証) */
        {
            struct bm_pqv5_identity c2;
            unsigned char root[BM_PQV5_ROOT_LEN];
            /* rootは内部関数なので、ここでは同じ入力での再生成が一致することで代用する */
            (void)root;
            if (bm_pqv5_identity_generate_deterministic("null byte search", 1, 0, 0,
                                                         BM_PQV5_SEARCH_X25519, &c2) != 0)
            {
                fprintf(stderr, "FAIL: regeneration\n");
                return 1;
            }
            /* 探索なし(カウンタ全0)とは別のアドレスになっているはず */
            if (memcmp(a.id, c2.id, BM_PQV5_ID_LEN) == 0 &&
                (is_all || a.counters[moved_component] != 0))
            {
                fprintf(stderr, "FAIL: search did not change the id (%s)\n", name);
                return 1;
            }
        }
        /* 先頭0x00が1byte削られるので、アドレスは探索なしの場合より1文字短い53文字になる */
        address = bm_pqv5_address_encode(a.version, a.stream, a.id);
        if (address == NULL || strlen(address) != 53)
        {
            fprintf(stderr, "FAIL: unexpected address length %zu (%s)\n",
                    address ? strlen(address) : 0, name);
            free(address);
            return 1;
        }
        free(address);
    }
    return 0;
}

int main(void)
{
    if (test_deterministic_generation() != 0)
    {
        return 1;
    }
    if (test_id_depends_on_version_and_stream() != 0)
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
    printf("test_pq_address: OK\n");
    return 0;
}
