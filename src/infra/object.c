#include "object.h"

#include "../common/varint.h"

static uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_be64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
    {
        v = (v << 8) | p[i];
    }
    return v;
}

int bm_object_parse_header(const unsigned char *data, size_t data_len, struct bm_object_header *out)
{
    if (data_len < 8 + 8 + 4)
    {
        return -1;
    }
    out->nonce = read_be64(data);
    out->expires_time = read_be64(data + 8);
    out->object_type = read_be32(data + 16);

    size_t offset = 20;
    uint64_t version = 0;
    size_t consumed = bm_varint_decode(data + offset, data_len - offset, &version);
    if (consumed == 0)
    {
        return -1;
    }
    offset += consumed;
    out->version = version;

    uint64_t stream = 0;
    consumed = bm_varint_decode(data + offset, data_len - offset, &stream);
    if (consumed == 0)
    {
        return -1;
    }
    offset += consumed;
    out->stream = stream;

    out->header_len = offset;
    return 0;
}

enum bm_propagation_mode bm_decide_propagation(const unsigned char object_hash[32],
                                                const struct bm_fd_data *target_connection)
{
    (void)object_hash;
    (void)target_connection;
    /* TODO(§9): Dandelion++実装時、stem状態(struct dandelion_state)を見て
     * PROPAGATE_STEM/PROPAGATE_SKIPを返すよう差し替える。v1は常時fluff。 */
    return BM_PROPAGATE_FLUFF;
}
