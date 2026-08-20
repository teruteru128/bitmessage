#include "base58.h"

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

int bm_base58_decode(const char *input, unsigned char **out, size_t *out_len)
{
    (void)input;
    (void)out;
    (void)out_len;
    /* TODO(§6.2 importAddress): 未実装 */
    return -1;
}
