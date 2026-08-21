#include "protocol.h"

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "../common/hash.h"
#include "../common/varint.h"

static const unsigned char MAGIC_MAINNET[4] = {0xe9, 0xbe, 0xb4, 0xd9};
static const unsigned char MAGIC_TESTNET[4] = {0xfb, 0x11, 0x09, 0x07};

unsigned char bm_magicbytes[4] = {0xe9, 0xbe, 0xb4, 0xd9}; /* 既定mainnet */
const unsigned char bm_empty_payload_checksum[4] = {0xcf, 0x83, 0xe1, 0x35};
static int g_is_testnet = 0;

void bm_protocol_set_testnet(int enabled)
{
    g_is_testnet = enabled ? 1 : 0;
    memcpy(bm_magicbytes, g_is_testnet ? MAGIC_TESTNET : MAGIC_MAINNET, 4);
}

int bm_protocol_is_testnet(void)
{
    return g_is_testnet;
}

static uint32_t read_be32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

static uint64_t read_be64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return be64toh(v);
}

static void write_be32(unsigned char *p, uint32_t v)
{
    uint32_t n = htonl(v);
    memcpy(p, &n, 4);
}

static void write_be64(unsigned char *p, uint64_t v)
{
    uint64_t n = htobe64(v);
    memcpy(p, &n, 8);
}

enum bm_parse_result bm_parse_message(const unsigned char *data, size_t data_len,
                                       struct bm_message **out_msg, size_t *out_consumed)
{
    if (data_len < BM_MESSAGE_HEADER_SIZE)
    {
        return BM_PARSE_INCOMPLETE;
    }

    if (memcmp(data, bm_magicbytes, 4) != 0)
    {
        /* mainnet/testnet取り違え、または単なるノイズ。1byteだけ進めてresyncを試みる
         * (次の呼び出しで先頭がずれた状態から再度magic bytesを探すことになる) */
        if (out_consumed)
        {
            *out_consumed = 1;
        }
        return BM_PARSE_BAD_MAGIC;
    }

    uint32_t length = read_be32(data + 16);
    size_t total = (size_t)BM_MESSAGE_HEADER_SIZE + length;
    if (data_len < total)
    {
        return BM_PARSE_INCOMPLETE;
    }

    unsigned char hash[64];
    bm_sha512(data + BM_MESSAGE_HEADER_SIZE, length, hash);
    if (memcmp(hash, data + 20, 4) != 0)
    {
        if (out_consumed)
        {
            *out_consumed = total;
        }
        return BM_PARSE_BAD_CHECKSUM;
    }

    struct bm_message *msg = malloc(sizeof(struct bm_message));
    memcpy(msg->command, data + 4, 12);
    msg->length = length;
    msg->checksum = read_be32(data + 20);
    if (length > 0)
    {
        msg->payload = malloc(length);
        memcpy(msg->payload, data + BM_MESSAGE_HEADER_SIZE, length);
    }
    else
    {
        msg->payload = NULL;
    }

    *out_msg = msg;
    if (out_consumed)
    {
        *out_consumed = total;
    }
    return BM_PARSE_OK;
}

void bm_free_message(struct bm_message *msg)
{
    if (msg == NULL)
    {
        return;
    }
    free(msg->payload);
    free(msg);
}

void bm_encode_time_and_stream(unsigned char *addr, uint64_t time_val, uint32_t stream)
{
    write_be64(addr, time_val);
    write_be32(addr + 8, stream);
}

void bm_encode_network_address(unsigned char addr[26], const struct sockaddr_storage *local_addr)
{
    memset(addr, 0, 26);
    if (local_addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)local_addr;
        addr[10] = 0xff;
        addr[11] = 0xff;
        memcpy(addr + 12, &sin->sin_addr, 4);
        memcpy(addr + 24, &sin->sin_port, 2);
    }
    else if (local_addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)local_addr;
        memcpy(addr + 8, &sin6->sin6_addr, 16);
        memcpy(addr + 24, &sin6->sin6_port, 2);
    }
}

void bm_parse_version_message(const unsigned char *payload, size_t payload_len,
                               struct bm_version_message *out_msg)
{
    (void)payload_len; /* TODO: 境界チェックを追加する(現状は移植元と同様に信頼している) */
    size_t offset = 0;
    out_msg->version = read_be32(payload + offset);
    offset += 4;
    out_msg->services = read_be64(payload + offset);
    offset += 8;
    out_msg->timestamp = read_be64(payload + offset);
    offset += 8;
    memcpy(out_msg->addr_recv, payload + offset, 26);
    offset += 26;
    memcpy(out_msg->addr_from, payload + offset, 26);
    offset += 26;
    out_msg->nonce = read_be64(payload + offset);
    offset += 8;

    uint64_t ua_len = 0;
    size_t consumed = bm_varint_decode(payload + offset, payload_len - offset, &ua_len);
    offset += consumed;
    out_msg->user_agent = malloc(ua_len + 1);
    memcpy(out_msg->user_agent, payload + offset, ua_len);
    out_msg->user_agent[ua_len] = '\0';
    offset += ua_len;

    uint64_t stream_count = 0;
    consumed = bm_varint_decode(payload + offset, payload_len - offset, &stream_count);
    offset += consumed;
    out_msg->stream_numbers_len = stream_count;
    out_msg->stream_numbers = malloc(sizeof(uint64_t) * stream_count);
    for (uint64_t i = 0; i < stream_count; i++)
    {
        uint64_t v = 0;
        consumed = bm_varint_decode(payload + offset, payload_len - offset, &v);
        out_msg->stream_numbers[i] = v;
        offset += consumed;
    }
}

void bm_free_version_message(struct bm_version_message *msg)
{
    free(msg->user_agent);
    msg->user_agent = NULL;
    free(msg->stream_numbers);
    msg->stream_numbers = NULL;
}

size_t bm_version_payload_size(const char *user_agent_str)
{
    /* version(4)+services(8)+timestamp(8)+addr_recv(26)+addr_from(26)+nonce(8) = 80
     * + varstr(user_agent) + stream_numbers(varint count=1byte + 1本のstream varint=1byte) */
    return 80 + bm_varstr_size(user_agent_str) + 2;
}

size_t bm_version_message_size(const char *user_agent_str)
{
    return BM_MESSAGE_HEADER_SIZE + bm_version_payload_size(user_agent_str);
}

unsigned char *bm_create_version_payload(unsigned char *out, const char *user_agent_str, int version,
                                          const struct sockaddr_storage *peer_addr,
                                          const struct sockaddr_storage *local_addr)
{
    if (out == NULL)
    {
        return NULL;
    }
    size_t offset = 0;
    write_be32(out + offset, (uint32_t)version);
    offset += 4;
    write_be64(out + offset, 0); /* services: 未対応(NODE_NETWORK等は将来追加) */
    offset += 8;
    write_be64(out + offset, (uint64_t)time(NULL));
    offset += 8;
    bm_encode_network_address(out + offset, peer_addr);
    offset += 26;
    bm_encode_network_address(out + offset, local_addr);
    offset += 26;
    uint64_t nonce = 0;
    getrandom(&nonce, sizeof(nonce), 0);
    write_be64(out + offset, nonce);
    offset += 8;
    bm_varstr_encode(out + offset, user_agent_str);
    offset += bm_varstr_size(user_agent_str);
    /* stream_numbers: count=1, [1] (ストリーム1のみ対応) */
    out[offset] = 1;
    offset += 1;
    out[offset] = 1;
    offset += 1;
    return out;
}

unsigned char *bm_new_version_message(const char *user_agent_str, int version,
                                       const struct sockaddr_storage *peer_addr,
                                       const struct sockaddr_storage *local_addr,
                                       size_t *out_len)
{
    size_t payload_len = bm_version_payload_size(user_agent_str);
    size_t total = BM_MESSAGE_HEADER_SIZE + payload_len;
    unsigned char *msg = malloc(total);
    bm_create_version_payload(msg + BM_MESSAGE_HEADER_SIZE, user_agent_str, version, peer_addr, local_addr);

    memcpy(msg, bm_magicbytes, 4);
    memset(msg + 4, 0, 12);
    memcpy(msg + 4, "version", 7);
    write_be32(msg + 16, (uint32_t)payload_len);
    unsigned char hash[64];
    bm_sha512(msg + BM_MESSAGE_HEADER_SIZE, payload_len, hash);
    memcpy(msg + 20, hash, 4);

    if (out_len)
    {
        *out_len = total;
    }
    return msg;
}

int bm_parse_addr_message(const unsigned char *payload, size_t payload_len, struct bm_addr_message *out_msg)
{
    size_t offset = 0;
    uint64_t count = 0;
    size_t consumed = bm_varint_decode(payload, payload_len, &count);
    if (consumed == 0)
    {
        return -1;
    }
    offset += consumed;

    out_msg->count = count;
    out_msg->addresses = malloc(sizeof(struct bm_address_info) * count);
    for (uint64_t i = 0; i < count; i++)
    {
        if (offset + 38 > payload_len)
        {
            free(out_msg->addresses);
            out_msg->addresses = NULL;
            return -1;
        }
        out_msg->addresses[i].time = read_be64(payload + offset);
        offset += 8;
        out_msg->addresses[i].stream = read_be32(payload + offset);
        offset += 4;
        out_msg->addresses[i].services = read_be64(payload + offset);
        offset += 8;
        memcpy(out_msg->addresses[i].ip, payload + offset, 16);
        offset += 16;
        uint16_t port;
        memcpy(&port, payload + offset, 2);
        out_msg->addresses[i].port = ntohs(port);
        offset += 2;
    }
    return 0;
}

void bm_free_addr_message(struct bm_addr_message *msg)
{
    free(msg->addresses);
    msg->addresses = NULL;
}

int bm_parse_inventory_message(const unsigned char *payload, size_t payload_len,
                                struct bm_inventory_message *out_msg)
{
    uint64_t declared_count = 0;
    size_t offset = bm_varint_decode(payload, payload_len, &declared_count);
    if (offset == 0)
    {
        return -1;
    }
    if ((payload_len - offset) % 32 != 0)
    {
        return -1;
    }
    uint64_t actual_count = (payload_len - offset) / 32;
    out_msg->count = actual_count;
    out_msg->items = malloc(sizeof(*out_msg->items) * actual_count);
    for (uint64_t i = 0; i < actual_count; i++)
    {
        memcpy(out_msg->items[i], payload + offset, 32);
        offset += 32;
    }
    return 0;
}

void bm_free_inventory_message(struct bm_inventory_message *msg)
{
    free(msg->items);
    msg->items = NULL;
}

unsigned char *bm_create_packet(const char *command, const unsigned char *payload,
                                 size_t payload_len, size_t *out_len)
{
    size_t total = BM_MESSAGE_HEADER_SIZE + payload_len;
    unsigned char *out = malloc(total);
    memcpy(out, bm_magicbytes, 4);
    memset(out + 4, 0, 12);
    size_t cmd_len = strlen(command);
    if (cmd_len > 12)
    {
        cmd_len = 12;
    }
    memcpy(out + 4, command, cmd_len);
    write_be32(out + 16, (uint32_t)payload_len);
    if (payload_len > 0)
    {
        unsigned char hash[64];
        bm_sha512(payload, payload_len, hash);
        memcpy(out + 20, hash, 4);
        memcpy(out + BM_MESSAGE_HEADER_SIZE, payload, payload_len);
    }
    else
    {
        memcpy(out + 20, bm_empty_payload_checksum, 4);
    }
    if (out_len)
    {
        *out_len = total;
    }
    return out;
}

unsigned char *bm_create_inventory_message(const char *command, const unsigned char (*hashes)[32],
                                            size_t count, size_t *out_len)
{
    size_t payload_len = bm_varint_size(count) + count * 32;
    unsigned char *payload = malloc(payload_len);
    bm_varint_encode(payload, count);
    unsigned char *p = payload + bm_varint_size(count); /* bm_varint_encodeはoutをそのまま返す(進めない) */
    for (size_t i = 0; i < count; i++)
    {
        memcpy(p, hashes[i], 32);
        p += 32;
    }
    unsigned char *packet = bm_create_packet(command, payload, payload_len, out_len);
    free(payload);
    return packet;
}
