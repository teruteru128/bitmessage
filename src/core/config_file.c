#include "config_file.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/logging.h"

static void set_defaults(struct bm_config_file *out)
{
    memset(out, 0, sizeof(*out));
    out->testnet = 0;
    out->no_connect = 0;
    out->max_outbound_connections = 3;
    out->api_port = 8442;
    out->inbound_port = 0;
    out->tor_control = 0;
    strncpy(out->tor_control_socket, "/run/tor/control", sizeof(out->tor_control_socket) - 1);
    strncpy(out->tor_control_host, "127.0.0.1", sizeof(out->tor_control_host) - 1);
    out->tor_control_port = 9051;
    out->tor_virtual_port = 8444;
    out->onion_address[0] = '\0';
    out->default_nonce_trials_per_byte = 1000;
    out->default_payload_length_extra_bytes = 1000;
}

/* 先頭・末尾の空白を取り除く(inを直接書き換えてポインタを返す、strdup等はしない) */
static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
    {
        s++;
    }
    if (*s == '\0')
    {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
    {
        *end = '\0';
        end--;
    }
    return s;
}

static void apply_kv(struct bm_config_file *out, const char *section, const char *key, const char *value,
                      const char *path, int line_no)
{
    if (strcmp(section, "network") == 0)
    {
        if (strcmp(key, "testnet") == 0)
        {
            out->testnet = atoi(value);
            return;
        }
        if (strcmp(key, "no_connect") == 0)
        {
            out->no_connect = atoi(value);
            return;
        }
        if (strcmp(key, "max_outbound_connections") == 0)
        {
            int v = atoi(value);
            if (v <= 0)
            {
                fprintf(stderr,
                        "[config_file] %s:%d: max_outbound_connections must be positive, ignoring "
                        "(keeping %d)\n",
                        path, line_no, out->max_outbound_connections);
                return;
            }
            out->max_outbound_connections = v;
            return;
        }
    }
    else if (strcmp(section, "identity") == 0)
    {
        if (strcmp(key, "default_nonce_trials_per_byte") == 0)
        {
            long long v = atoll(value);
            if (v <= 0)
            {
                fprintf(stderr,
                        "[config_file] %s:%d: default_nonce_trials_per_byte must be positive, ignoring "
                        "(a value of 0 would make PoW target calculation divide by zero)\n",
                        path, line_no);
                return;
            }
            out->default_nonce_trials_per_byte = (uint64_t)v;
            return;
        }
        if (strcmp(key, "default_payload_length_extra_bytes") == 0)
        {
            long long v = atoll(value);
            if (v <= 0)
            {
                fprintf(stderr,
                        "[config_file] %s:%d: default_payload_length_extra_bytes must be positive, "
                        "ignoring\n",
                        path, line_no);
                return;
            }
            out->default_payload_length_extra_bytes = (uint64_t)v;
            return;
        }
    }
    else if (strcmp(section, "api") == 0)
    {
        if (strcmp(key, "port") == 0)
        {
            out->api_port = atoi(value);
            return;
        }
    }
    else if (strcmp(section, "inbound") == 0)
    {
        if (strcmp(key, "port") == 0)
        {
            out->inbound_port = atoi(value);
            return;
        }
    }
    else if (strcmp(section, "tor") == 0)
    {
        if (strcmp(key, "control") == 0)
        {
            out->tor_control = atoi(value);
            return;
        }
        if (strcmp(key, "control_socket") == 0)
        {
            strncpy(out->tor_control_socket, value, sizeof(out->tor_control_socket) - 1);
            return;
        }
        if (strcmp(key, "control_host") == 0)
        {
            strncpy(out->tor_control_host, value, sizeof(out->tor_control_host) - 1);
            return;
        }
        if (strcmp(key, "control_port") == 0)
        {
            out->tor_control_port = atoi(value);
            return;
        }
        if (strcmp(key, "virtual_port") == 0)
        {
            out->tor_virtual_port = atoi(value);
            return;
        }
        if (strcmp(key, "onion_address") == 0)
        {
            strncpy(out->onion_address, value, sizeof(out->onion_address) - 1);
            return;
        }
    }
    bm_log("[config_file] %s:%d: unknown key '%s' in section [%s], ignoring\n", path, line_no, key,
            section);
}

int bm_config_file_load(const char *path, struct bm_config_file *out)
{
    set_defaults(out);

    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        return 0; /* ファイルが無いのは正常系(既定値のまま起動する) */
    }

    char section[64] = "";
    char line[512];
    int line_no = 0;
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        line_no++;
        char *trimmed = trim(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';')
        {
            continue;
        }

        size_t len = strlen(trimmed);
        if (trimmed[0] == '[' && trimmed[len - 1] == ']')
        {
            trimmed[len - 1] = '\0';
            strncpy(section, trimmed + 1, sizeof(section) - 1);
            section[sizeof(section) - 1] = '\0';
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (eq == NULL)
        {
            bm_log("[config_file] %s:%d: malformed line (no '='), ignoring: %s\n", path, line_no,
                    trimmed);
            continue;
        }
        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);
        apply_kv(out, section, key, value, path, line_no);
    }

    fclose(fp);
    return 1;
}
