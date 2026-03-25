#include "poly_verified.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

const pv_hash_t PV_ZERO_HASH = {0};

/* ---------- SHA-256 via OpenSSL EVP ---------- */

static void sha256(const uint8_t *in, size_t len, pv_hash_t out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int olen = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, len);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
}

/* Domain-separated hashing: prepend a single tag byte before data.
 * Tag bytes match Go/Rust implementations exactly:
 *   0x00 = leaf, 0x01 = transition, 0x02 = chain_step,
 *   0x03 = combine/interior, 0x04 = blinding                       */

static void tagged_hash(uint8_t tag, const uint8_t *in, size_t len, pv_hash_t out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int olen = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &tag, 1);
    EVP_DigestUpdate(ctx, in, len);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
}

void pv_hash_data(const uint8_t *in, size_t len, pv_hash_t out) {
    sha256(in, len, out);
}

void pv_hash_leaf(const uint8_t *in, size_t len, pv_hash_t out) {
    tagged_hash(0x00, in, len, out);
}

void pv_hash_combine(const pv_hash_t left, const pv_hash_t right, pv_hash_t out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int olen = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    uint8_t tag = 0x03;
    EVP_DigestUpdate(ctx, &tag, 1);
    EVP_DigestUpdate(ctx, left, 32);
    EVP_DigestUpdate(ctx, right, 32);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
}

void pv_hash_transition(const pv_hash_t prev, const pv_hash_t input,
                         const pv_hash_t claimed, pv_hash_t out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int olen = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    uint8_t tag = 0x01;
    EVP_DigestUpdate(ctx, &tag, 1);
    EVP_DigestUpdate(ctx, prev, 32);
    EVP_DigestUpdate(ctx, input, 32);
    EVP_DigestUpdate(ctx, claimed, 32);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
}

void pv_hash_chain_step(const pv_hash_t tip, const pv_hash_t state, pv_hash_t out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int olen = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    uint8_t tag = 0x02;
    EVP_DigestUpdate(ctx, &tag, 1);
    EVP_DigestUpdate(ctx, tip, 32);
    EVP_DigestUpdate(ctx, state, 32);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
}

void pv_hash_blinding(const uint8_t *in, size_t len, pv_hash_t out) {
    tagged_hash(0x04, in, len, out);
}

int pv_hash_eq(const pv_hash_t a, const pv_hash_t b) {
    /* constant-time comparison via OR accumulator */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* ---------- Internal Merkle tree ---------- */

typedef struct {
    pv_hash_t *layers;      /* flattened layer storage */
    size_t *layer_offsets;   /* start offset of each layer in the flat array */
    size_t *layer_sizes;     /* number of elements in each layer */
    size_t num_layers;
    pv_hash_t root;
} merkle_tree_t;

static merkle_tree_t *merkle_tree_build(const pv_hash_t *leaves, size_t n) {
    merkle_tree_t *t = calloc(1, sizeof(*t));
    if (n == 0) {
        t->num_layers = 1;
        t->layer_offsets = calloc(1, sizeof(size_t));
        t->layer_sizes  = calloc(1, sizeof(size_t));
        t->layer_sizes[0] = 0;
        t->layers = NULL;
        memset(t->root, 0, 32);
        return t;
    }

    /* Count layers */
    size_t total_nodes = 0;
    size_t cap_layers = 0;
    {
        size_t sz = n;
        while (sz > 1) { total_nodes += sz; sz = (sz + 1) / 2; cap_layers++; }
        total_nodes += 1; /* root layer */
        cap_layers += 1;
    }

    t->num_layers    = cap_layers;
    t->layer_offsets = calloc(cap_layers, sizeof(size_t));
    t->layer_sizes   = calloc(cap_layers, sizeof(size_t));
    t->layers        = calloc(total_nodes, sizeof(pv_hash_t));

    /* Copy leaf layer */
    t->layer_offsets[0] = 0;
    t->layer_sizes[0]   = n;
    for (size_t i = 0; i < n; i++) memcpy(t->layers[i], leaves[i], 32);

    /* Build upper layers */
    size_t prev_off = 0, prev_sz = n;
    size_t next_off = n;
    for (size_t layer = 1; layer < cap_layers; layer++) {
        size_t next_sz = (prev_sz + 1) / 2;
        t->layer_offsets[layer] = next_off;
        t->layer_sizes[layer]   = next_sz;

        for (size_t i = 0; i < prev_sz; i += 2) {
            size_t li = prev_off + i;
            size_t ri = (i + 1 < prev_sz) ? prev_off + i + 1 : li; /* dup for odd */
            pv_hash_combine(t->layers[li], t->layers[ri], t->layers[next_off + i / 2]);
        }

        prev_off = next_off;
        prev_sz  = next_sz;
        next_off += next_sz;
    }

    memcpy(t->root, t->layers[prev_off], 32);
    return t;
}

static void merkle_tree_free(merkle_tree_t *t) {
    if (!t) return;
    free(t->layers);
    free(t->layer_offsets);
    free(t->layer_sizes);
    free(t);
}

/* ---------- Public Merkle API ---------- */

pv_merkle_proof_t *pv_merkle_build_and_prove(const pv_hash_t *leaves, size_t n,
                                              uint64_t leaf_index,
                                              const pv_hash_t code_hash) {
    if (leaf_index >= n) return NULL;

    merkle_tree_t *tree = merkle_tree_build(leaves, n);

    size_t depth = tree->num_layers - 1;
    pv_merkle_proof_t *p = calloc(1, sizeof(*p));
    memcpy(p->leaf, leaves[leaf_index], 32);
    p->leaf_index    = leaf_index;
    memcpy(p->root, tree->root, 32);
    memcpy(p->code_hash, code_hash, 32);
    p->sibling_count = depth;
    p->siblings      = calloc(depth, sizeof(pv_proof_node_t));

    size_t idx = (size_t)leaf_index;
    for (size_t layer = 0; layer < depth; layer++) {
        size_t sib;
        int is_left;
        if (idx % 2 == 0) {
            sib = idx + 1;
            is_left = 0;
        } else {
            sib = idx - 1;
            is_left = 1;
        }

        size_t off = tree->layer_offsets[layer];
        size_t sz  = tree->layer_sizes[layer];
        size_t src = (sib < sz) ? sib : idx;  /* dup last for odd */

        memcpy(p->siblings[layer].hash, tree->layers[off + src], 32);
        p->siblings[layer].is_left = is_left;

        idx /= 2;
    }

    merkle_tree_free(tree);
    return p;
}

int pv_merkle_verify(const pv_merkle_proof_t *proof) {
    pv_hash_t current;
    memcpy(current, proof->leaf, 32);

    for (size_t i = 0; i < proof->sibling_count; i++) {
        pv_hash_t tmp;
        if (proof->siblings[i].is_left) {
            pv_hash_combine(proof->siblings[i].hash, current, tmp);
        } else {
            pv_hash_combine(current, proof->siblings[i].hash, tmp);
        }
        memcpy(current, tmp, 32);
    }

    return pv_hash_eq(current, proof->root);
}

void pv_merkle_proof_free(pv_merkle_proof_t *proof) {
    if (!proof) return;
    free(proof->siblings);
    free(proof);
}

/* ---------- Hash chain ---------- */

typedef struct {
    pv_hash_t tip;
    uint64_t length;
} hash_chain_t;

static hash_chain_t chain_new(void) {
    hash_chain_t c;
    memset(c.tip, 0, 32);
    c.length = 0;
    return c;
}

static void chain_append(hash_chain_t *c, const pv_hash_t state) {
    pv_hash_t next;
    pv_hash_chain_step(c->tip, state, next);
    memcpy(c->tip, next, 32);
    c->length++;
}

/* ---------- IVC accumulator ---------- */

struct pv_ivc_s {
    hash_chain_t chain;
    pv_hash_t   *checkpoints;
    size_t        cp_count;
    size_t        cp_cap;
    pv_hash_t    code_hash;
    uint8_t      privacy;
    pv_hash_t    blinding_hash;
};

pv_ivc_t *pv_ivc_new(const pv_hash_t code_hash, uint8_t privacy) {
    pv_ivc_t *ivc = calloc(1, sizeof(*ivc));
    ivc->chain = chain_new();
    ivc->cp_cap  = 16;
    ivc->checkpoints = calloc(ivc->cp_cap, sizeof(pv_hash_t));
    ivc->cp_count = 0;
    memcpy(ivc->code_hash, code_hash, 32);
    ivc->privacy = privacy;
    memset(ivc->blinding_hash, 0, 32);
    return ivc;
}

int pv_ivc_fold_step(pv_ivc_t *ivc, const pv_step_witness_t *w) {
    pv_hash_t transition;
    pv_hash_transition(w->state_before, w->step_inputs, w->state_after, transition);

    chain_append(&ivc->chain, transition);

    /* Grow checkpoint array if needed */
    if (ivc->cp_count >= ivc->cp_cap) {
        ivc->cp_cap *= 2;
        ivc->checkpoints = realloc(ivc->checkpoints, ivc->cp_cap * sizeof(pv_hash_t));
    }
    memcpy(ivc->checkpoints[ivc->cp_count++], transition, 32);

    /* Blinding for private modes */
    if (ivc->privacy != PV_TRANSPARENT) {
        uint8_t blinding_input[40];
        memcpy(blinding_input, transition, 32);
        /* step counter as LE uint64 */
        uint64_t step = ivc->chain.length;
        for (int i = 0; i < 8; i++) blinding_input[32 + i] = (uint8_t)(step >> (i * 8));

        pv_hash_t blinding;
        pv_hash_blinding(blinding_input, 40, blinding);
        pv_hash_t combined;
        pv_hash_combine(ivc->blinding_hash, blinding, combined);
        memcpy(ivc->blinding_hash, combined, 32);
    }

    return 0;
}

pv_proof_t *pv_ivc_finalize(pv_ivc_t *ivc) {
    if (ivc->cp_count == 0) {
        free(ivc->checkpoints);
        free(ivc);
        return NULL;
    }

    merkle_tree_t *tree = merkle_tree_build((const pv_hash_t *)ivc->checkpoints, ivc->cp_count);

    pv_proof_t *p = calloc(1, sizeof(*p));
    memcpy(p->chain_tip, ivc->chain.tip, 32);
    memcpy(p->merkle_root, tree->root, 32);
    p->step_count = ivc->chain.length;
    memcpy(p->code_hash, ivc->code_hash, 32);
    p->privacy = ivc->privacy;

    if (ivc->privacy != PV_TRANSPARENT) {
        memcpy(p->blinding_commitment, ivc->blinding_hash, 32);
        p->has_blinding = 1;
    } else {
        p->has_blinding = 0;
    }

    merkle_tree_free(tree);
    free(ivc->checkpoints);
    free(ivc);
    return p;
}

void pv_proof_free(pv_proof_t *proof) {
    free(proof);
}

/* ---------- Disclosure ---------- */

static void token_leaf(uint32_t token_id, pv_hash_t out) {
    uint8_t buf[4];
    buf[0] = (uint8_t)(token_id);
    buf[1] = (uint8_t)(token_id >> 8);
    buf[2] = (uint8_t)(token_id >> 16);
    buf[3] = (uint8_t)(token_id >> 24);
    pv_hash_leaf(buf, 4, out);
}

pv_disclosure_t *pv_disclosure_create(const uint32_t *tokens, size_t n,
                                       const pv_proof_t *proof,
                                       const size_t *indices, size_t num_indices) {
    /* Validate indices */
    for (size_t i = 0; i < num_indices; i++) {
        if (indices[i] >= n) return NULL;
    }

    /* Build reveal set (simple linear scan — small n expected) */
    uint8_t *reveal = calloc(n, 1);
    for (size_t i = 0; i < num_indices; i++) reveal[indices[i]] = 1;

    /* Build Merkle leaves */
    pv_hash_t *leaves = calloc(n, sizeof(pv_hash_t));
    for (size_t i = 0; i < n; i++) token_leaf(tokens[i], leaves[i]);

    /* Build Merkle tree */
    merkle_tree_t *tree = merkle_tree_build(leaves, n);

    pv_disclosure_t *d = calloc(1, sizeof(*d));
    d->token_count  = n;
    d->total_tokens = n;
    d->tokens = calloc(n, sizeof(pv_disclosed_token_t));
    memcpy(d->output_root, tree->root, 32);
    d->execution_proof = *proof;

    /* Count revealed for proof allocation */
    d->proof_count = num_indices;
    d->proofs = calloc(num_indices, sizeof(pv_merkle_proof_t));

    size_t proof_idx = 0;
    for (size_t i = 0; i < n; i++) {
        d->tokens[i].index = i;
        if (reveal[i]) {
            d->tokens[i].revealed = 1;
            d->tokens[i].token_id = tokens[i];

            /* Generate Merkle proof for this leaf */
            pv_merkle_proof_t *mp = pv_merkle_build_and_prove(leaves, n, i, proof->code_hash);
            d->proofs[proof_idx] = *mp;
            /* Deep-copy siblings since mp->siblings will be freed */
            d->proofs[proof_idx].siblings = calloc(mp->sibling_count, sizeof(pv_proof_node_t));
            memcpy(d->proofs[proof_idx].siblings, mp->siblings, mp->sibling_count * sizeof(pv_proof_node_t));
            pv_merkle_proof_free(mp);
            proof_idx++;
        } else {
            d->tokens[i].revealed = 0;
            memcpy(d->tokens[i].leaf_hash, leaves[i], 32);
        }
    }

    merkle_tree_free(tree);
    free(leaves);
    free(reveal);
    return d;
}

int pv_disclosure_verify(const pv_disclosure_t *d) {
    if (!d) return 0;
    if (d->token_count != d->total_tokens) return 0;

    /* Sequential indices */
    for (size_t i = 0; i < d->token_count; i++) {
        if (d->tokens[i].index != i) return 0;
    }

    /* Verify revealed tokens against Merkle proofs */
    size_t proof_idx = 0;
    for (size_t i = 0; i < d->token_count; i++) {
        if (d->tokens[i].revealed) {
            if (proof_idx >= d->proof_count) return 0;

            const pv_merkle_proof_t *mp = &d->proofs[proof_idx];

            /* Recompute expected leaf */
            pv_hash_t expected;
            token_leaf(d->tokens[i].token_id, expected);
            if (!pv_hash_eq(expected, mp->leaf)) return 0;

            /* Verify Merkle proof */
            if (!pv_merkle_verify(mp)) return 0;

            /* Root must match disclosure root */
            if (!pv_hash_eq(mp->root, d->output_root)) return 0;

            proof_idx++;
        } else {
            /* Redacted tokens must have a non-zero leaf hash */
            if (pv_hash_eq(d->tokens[i].leaf_hash, PV_ZERO_HASH)) return 0;
        }
    }

    /* All proofs consumed */
    if (proof_idx != d->proof_count) return 0;

    /* Execution proof structural check */
    return d->execution_proof.step_count > 0;
}

void pv_disclosure_free(pv_disclosure_t *d) {
    if (!d) return;
    for (size_t i = 0; i < d->proof_count; i++) {
        free(d->proofs[i].siblings);
    }
    free(d->proofs);
    free(d->tokens);
    free(d);
}

/* ---------- JSON serialization ---------- */

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

char *pv_proof_to_json(const pv_proof_t *proof) {
    char tip[65], root[65], code[65], blind[65];
    hex_encode(proof->chain_tip, 32, tip);
    hex_encode(proof->merkle_root, 32, root);
    hex_encode(proof->code_hash, 32, code);

    const char *priv_str;
    switch (proof->privacy) {
    case PV_PRIVATE: priv_str = "Private"; break;
    case PV_PRIVATE_INPUTS: priv_str = "PrivateInputs"; break;
    default: priv_str = "Transparent"; break;
    }

    char *buf = malloc(1024);
    if (proof->has_blinding) {
        hex_encode(proof->blinding_commitment, 32, blind);
        snprintf(buf, 1024,
            "{\"chain_tip\":\"%s\",\"merkle_root\":\"%s\",\"step_count\":%llu,"
            "\"code_hash\":\"%s\",\"privacy_mode\":\"%s\",\"blinding_commitment\":\"%s\"}",
            tip, root, (unsigned long long)proof->step_count, code, priv_str, blind);
    } else {
        snprintf(buf, 1024,
            "{\"chain_tip\":\"%s\",\"merkle_root\":\"%s\",\"step_count\":%llu,"
            "\"code_hash\":\"%s\",\"privacy_mode\":\"%s\"}",
            tip, root, (unsigned long long)proof->step_count, code, priv_str);
    }
    return buf;
}

/* Wire format uses integer arrays for hashes, matching Rust serde [u8; 32]:
 * {"HashIvc":{"chain_tip":[0,1,...,31],"merkle_root":[...],...}}            */

static void hash_to_int_array(const pv_hash_t h, char *out, size_t out_sz) {
    int pos = 0;
    pos += snprintf(out + pos, out_sz - pos, "[");
    for (int i = 0; i < 32; i++) {
        if (i > 0) pos += snprintf(out + pos, out_sz - pos, ",");
        pos += snprintf(out + pos, out_sz - pos, "%u", h[i]);
    }
    snprintf(out + pos, out_sz - pos, "]");
}

char *pv_proof_to_wire_json(const pv_proof_t *proof) {
    char tip[256], root[256], code[256], blind[256];
    hash_to_int_array(proof->chain_tip, tip, sizeof(tip));
    hash_to_int_array(proof->merkle_root, root, sizeof(root));
    hash_to_int_array(proof->code_hash, code, sizeof(code));

    const char *priv_str;
    switch (proof->privacy) {
    case PV_PRIVATE: priv_str = "Private"; break;
    case PV_PRIVATE_INPUTS: priv_str = "PrivateInputs"; break;
    default: priv_str = "Transparent"; break;
    }

    size_t buf_sz = 2048;
    char *buf = malloc(buf_sz);
    int pos = 0;

    pos += snprintf(buf + pos, buf_sz - pos,
        "{\"HashIvc\":{\"chain_tip\":%s,\"merkle_root\":%s,\"step_count\":%llu,"
        "\"code_hash\":%s,\"privacy_mode\":\"%s\"",
        tip, root, (unsigned long long)proof->step_count, code, priv_str);

    if (proof->has_blinding) {
        hash_to_int_array(proof->blinding_commitment, blind, sizeof(blind));
        pos += snprintf(buf + pos, buf_sz - pos, ",\"blinding_commitment\":%s", blind);
    }

    snprintf(buf + pos, buf_sz - pos, "}}");
    return buf;
}

/* ---------- Wire JSON parser ---------- */

/* Find a JSON key and extract the value string. Returns pointer into json. */
static const char *find_json_key(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Parse a JSON integer array [0,1,...,31] into a 32-byte hash */
static int parse_int_array_hash(const char *p, pv_hash_t out) {
    if (*p != '[') return -1;
    p++;
    for (int i = 0; i < 32; i++) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        char *end;
        long val = strtol(p, &end, 10);
        if (end == p || val < 0 || val > 255) return -1;
        out[i] = (uint8_t)val;
        p = end;
        if (i < 31) {
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
            if (*p != ',') return -1;
            p++;
        }
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ']') return -1;
    return 0;
}

/* Parse a JSON string value starting at p (expects opening quote) */
static int parse_json_string(const char *p, char *out, size_t out_sz) {
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1) out[i++] = *p++;
    out[i] = '\0';
    return (*p == '"') ? 0 : -1;
}

/* Parse uint64 at position p */
static int parse_uint64(const char *p, uint64_t *out) {
    char *end;
    *out = strtoull(p, &end, 10);
    return (end != p) ? 0 : -1;
}

pv_proof_t *pv_proof_from_wire_json(const char *json_str) {
    /* Find HashIvc envelope */
    const char *inner = find_json_key(json_str, "HashIvc");
    if (!inner || *inner != '{') return NULL;
    inner++; /* skip { */

    pv_proof_t *p = calloc(1, sizeof(*p));

    const char *v;
    if ((v = find_json_key(json_str, "chain_tip")) && *v == '[') {
        if (parse_int_array_hash(v, p->chain_tip) != 0) goto fail;
    } else goto fail;

    if ((v = find_json_key(json_str, "merkle_root")) && *v == '[') {
        if (parse_int_array_hash(v, p->merkle_root) != 0) goto fail;
    } else goto fail;

    if ((v = find_json_key(json_str, "code_hash")) && *v == '[') {
        if (parse_int_array_hash(v, p->code_hash) != 0) goto fail;
    } else goto fail;

    if ((v = find_json_key(json_str, "step_count"))) {
        if (parse_uint64(v, &p->step_count) != 0) goto fail;
    } else goto fail;

    if ((v = find_json_key(json_str, "privacy_mode"))) {
        char mode_str[32];
        if (parse_json_string(v, mode_str, sizeof(mode_str)) != 0) goto fail;
        if (strcmp(mode_str, "Private") == 0) p->privacy = PV_PRIVATE;
        else if (strcmp(mode_str, "PrivateInputs") == 0) p->privacy = PV_PRIVATE_INPUTS;
        else p->privacy = PV_TRANSPARENT;
    } else goto fail;

    if ((v = find_json_key(json_str, "blinding_commitment")) && *v == '[') {
        if (parse_int_array_hash(v, p->blinding_commitment) == 0)
            p->has_blinding = 1;
    }

    return p;
fail:
    free(p);
    return NULL;
}
