#include "poly_client.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char *dup_str(const char *s) {
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (d) memcpy(d, s, len);
    return d;
}

/* ---------- Mock encryption (matches Go/Rust MockEncryption) ---------- */

/* Deterministic keys: public = 0xAA×32, secret = 0xBB×32 */
static void mock_keygen(uint8_t pk[32], uint8_t sk[32]) {
    memset(pk, 0xAA, 32);
    memset(sk, 0xBB, 32);
}

/* Mock encrypt: produce JSON {"tokens":[t0,t1,...]} */
static char *mock_encrypt(const uint32_t *tokens, size_t n) {
    /* Estimate size: ~12 chars per token + overhead */
    size_t buf_sz = n * 12 + 64;
    char *buf = malloc(buf_sz);
    int pos = 0;
    pos += snprintf(buf + pos, buf_sz - pos, "{\"tokens\":[");
    for (size_t i = 0; i < n; i++) {
        if (i > 0) pos += snprintf(buf + pos, buf_sz - pos, ",");
        pos += snprintf(buf + pos, buf_sz - pos, "%u", tokens[i]);
    }
    snprintf(buf + pos, buf_sz - pos, "]}");
    return buf;
}

/* Mock decrypt: parse JSON {"tokens":[t0,t1,...]} → token array */
static uint32_t *mock_decrypt(const char *json, size_t *out_count) {
    *out_count = 0;
    const char *p = strstr(json, "\"tokens\"");
    if (!p) return NULL;
    p = strchr(p, '[');
    if (!p) return NULL;
    p++; /* skip [ */

    /* Count tokens first */
    size_t cap = 64;
    uint32_t *tokens = malloc(cap * sizeof(uint32_t));
    size_t count = 0;

    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        if (*p == ',') { p++; continue; }

        char *end;
        unsigned long val = strtoul(p, &end, 10);
        if (end == p) break;

        if (count >= cap) {
            cap *= 2;
            tokens = realloc(tokens, cap * sizeof(uint32_t));
        }
        tokens[count++] = (uint32_t)val;
        p = end;
    }

    *out_count = count;
    return tokens;
}

/* ---------- Client struct ---------- */

struct pc_client_s {
    char   *model_id;
    int     mode;
    uint8_t public_key[32];
    uint8_t secret_key[32];
};

pc_client_t *pc_client_new(const char *model_id, int mode) {
    pc_client_t *c = calloc(1, sizeof(*c));
    c->model_id = dup_str(model_id);
    c->mode = mode;
    mock_keygen(c->public_key, c->secret_key);
    return c;
}

void pc_client_free(pc_client_t *client) {
    if (!client) return;
    free(client->model_id);
    free(client);
}

const char *pc_client_model_id(const pc_client_t *client) {
    return client->model_id;
}

int pc_client_mode(const pc_client_t *client) {
    return client->mode;
}

/* ---------- Protocol ---------- */

/* Mode name for JSON serialization */
static const char *mode_to_str(int mode) {
    switch (mode) {
    case PV_MODE_TRANSPARENT:    return "Transparent";
    case PV_MODE_PRIVATE_PROVEN: return "PrivateProven";
    case PV_MODE_PRIVATE:        return "Private";
    case PV_MODE_ENCRYPTED:      return "Encrypted";
    default:                     return "Transparent";
    }
}

char *pc_client_prepare_request_json(pc_client_t *client,
                                      const uint32_t *tokens, size_t n,
                                      uint32_t max_tokens, uint32_t temperature,
                                      uint64_t seed) {
    char *encrypted = mock_encrypt(tokens, n);

    /* Build the JSON request envelope */
    size_t buf_sz = strlen(encrypted) + 512;
    char *buf = malloc(buf_sz);
    snprintf(buf, buf_sz,
        "{\"model_id\":\"%s\",\"mode\":\"%s\",\"encrypted_input\":%s,"
        "\"max_tokens\":%u,\"temperature\":%u,\"seed\":%llu}",
        client->model_id, mode_to_str(client->mode), encrypted,
        max_tokens, temperature, (unsigned long long)seed);

    free(encrypted);
    return buf;
}

/* Extract a JSON object value starting at a key (returns pointer into json) */
static const char *find_json_object(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Find matching closing brace/bracket, counting nesting */
static const char *find_matching_close(const char *p, char open, char close) {
    if (*p != open) return NULL;
    int depth = 1;
    p++;
    while (*p && depth > 0) {
        if (*p == '"') { /* skip strings */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\') p++;
                p++;
            }
        } else if (*p == open) {
            depth++;
        } else if (*p == close) {
            depth--;
            if (depth == 0) return p;
        }
        p++;
    }
    return NULL;
}

/* Extract a JSON sub-object/array as a string */
static char *extract_json_value(const char *json, const char *key) {
    const char *p = find_json_object(json, key);
    if (!p) return NULL;

    const char *end = NULL;
    if (*p == '{') end = find_matching_close(p, '{', '}');
    else if (*p == '[') end = find_matching_close(p, '[', ']');
    else return NULL;

    if (!end) return NULL;
    size_t len = end - p + 1;
    char *out = malloc(len + 1);
    memcpy(out, p, len);
    out[len] = '\0';
    return out;
}

pc_verified_response_t *pc_client_process_response_json(pc_client_t *client,
                                                         const char *json) {
    /* Extract encrypted_output */
    char *enc_output = extract_json_value(json, "encrypted_output");
    if (!enc_output) return NULL;

    /* Extract proof (the full {"HashIvc":{...}} object) */
    char *proof_json = extract_json_value(json, "proof");
    if (!proof_json) { free(enc_output); return NULL; }

    /* Decrypt tokens */
    size_t token_count;
    uint32_t *tokens = mock_decrypt(enc_output, &token_count);
    free(enc_output);

    /* Parse proof */
    pv_proof_t *proof = pv_proof_from_wire_json(proof_json);
    free(proof_json);

    if (!proof) {
        free(tokens);
        return NULL;
    }

    pc_verified_response_t *resp = calloc(1, sizeof(*resp));
    resp->token_ids = tokens;
    resp->count = token_count;
    resp->proof = *proof;

    /* Structural verification */
    resp->verified = (proof->step_count > 0) ? 1 : 0;
    if (proof->privacy != PV_TRANSPARENT && !proof->has_blinding) {
        resp->verified = 0;
    }

    pv_proof_free(proof);
    return resp;
}

int pc_verified_response_is_verified(const pc_verified_response_t *resp) {
    if (!resp) return 0;
    return resp->verified;
}

pv_disclosure_t *pc_verified_response_disclose(const pc_verified_response_t *resp,
                                                const size_t *indices, size_t n) {
    if (!resp) return NULL;
    return pv_disclosure_create(resp->token_ids, resp->count,
                                &resp->proof, indices, n);
}

void pc_verified_response_free(pc_verified_response_t *resp) {
    if (!resp) return;
    free(resp->token_ids);
    free(resp);
}
