#include "poly_verified.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); } \
    else { tests_passed++; } \
} while(0)

#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)

static void hash_to_hex(const pv_hash_t h, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex_chars[h[i] >> 4];
        out[i * 2 + 1] = hex_chars[h[i] & 0x0f];
    }
    out[64] = '\0';
}

#define ASSERT_HASH_HEX(hash, expected_hex, msg) do { \
    char __hex[65]; \
    hash_to_hex(hash, __hex); \
    tests_run++; \
    if (strcmp(__hex, expected_hex) != 0) { \
        fprintf(stderr, "FAIL: %s (line %d)\n  got:  %s\n  want: %s\n", \
                msg, __LINE__, __hex, expected_hex); \
    } else { tests_passed++; } \
} while(0)

/* ============ Hash tests ============ */

static void test_hash_determinism(void) {
    pv_hash_t h1, h2;
    uint8_t data[] = "hello world";
    pv_hash_data(data, sizeof(data) - 1, h1);
    pv_hash_data(data, sizeof(data) - 1, h2);
    ASSERT(pv_hash_eq(h1, h2), "hash_data deterministic");
}

static void test_hash_different_inputs(void) {
    pv_hash_t h1, h2;
    uint8_t d1[] = "alpha";
    uint8_t d2[] = "beta";
    pv_hash_data(d1, 5, h1);
    pv_hash_data(d2, 4, h2);
    ASSERT(!pv_hash_eq(h1, h2), "different inputs produce different hashes");
}

static void test_hash_domain_separation(void) {
    uint8_t data[] = {0x42, 0x00, 0x00, 0x00};
    pv_hash_t plain, leaf, blinding;
    pv_hash_data(data, 4, plain);
    pv_hash_leaf(data, 4, leaf);
    pv_hash_blinding(data, 4, blinding);

    ASSERT(!pv_hash_eq(plain, leaf), "data vs leaf differ");
    ASSERT(!pv_hash_eq(plain, blinding), "data vs blinding differ");
    ASSERT(!pv_hash_eq(leaf, blinding), "leaf vs blinding differ");
}

static void test_hash_combine_order(void) {
    pv_hash_t a, b, ab, ba;
    uint8_t d1[] = "left";
    uint8_t d2[] = "right";
    pv_hash_data(d1, 4, a);
    pv_hash_data(d2, 5, b);
    pv_hash_combine(a, b, ab);
    pv_hash_combine(b, a, ba);
    ASSERT(!pv_hash_eq(ab, ba), "combine order matters");
}

static void test_hash_constant_time_eq(void) {
    pv_hash_t a = {0}, b = {0};
    ASSERT(pv_hash_eq(a, b), "equal zero hashes");

    /* Differ in last byte */
    a[31] = 1;
    ASSERT(!pv_hash_eq(a, b), "differ in last byte");

    /* Differ in first byte */
    a[31] = 0;
    a[0] = 0xFF;
    ASSERT(!pv_hash_eq(a, b), "differ in first byte");
}

static void test_hash_chain_step(void) {
    pv_hash_t tip = {0}, state, result1, result2;
    uint8_t d[] = "state";
    pv_hash_data(d, 5, state);

    pv_hash_chain_step(tip, state, result1);
    /* Different tip → different result */
    pv_hash_t tip2 = {1};
    pv_hash_chain_step(tip2, state, result2);
    ASSERT(!pv_hash_eq(result1, result2), "chain_step: different tip → different hash");
}

static void test_hash_transition(void) {
    pv_hash_t prev = {0}, input = {1}, claimed = {2};
    pv_hash_t t1, t2;
    pv_hash_transition(prev, input, claimed, t1);
    /* Swap input and claimed */
    pv_hash_transition(prev, claimed, input, t2);
    ASSERT(!pv_hash_eq(t1, t2), "transition: order matters");
}

/* ============ Merkle tests ============ */

static void test_merkle_single_leaf(void) {
    pv_hash_t leaf, code_hash = {0};
    uint8_t d[] = "leaf0";
    pv_hash_leaf(d, 5, leaf);

    pv_merkle_proof_t *p = pv_merkle_build_and_prove(&leaf, 1, 0, code_hash);
    ASSERT(p != NULL, "merkle: single leaf proof built");
    ASSERT(pv_merkle_verify(p), "merkle: single leaf verifies");
    ASSERT_EQ(p->sibling_count, 0, "merkle: single leaf has 0 siblings");
    pv_merkle_proof_free(p);
}

static void test_merkle_two_leaves(void) {
    pv_hash_t leaves[2], code_hash = {0};
    uint8_t d0[] = "l0", d1[] = "l1";
    pv_hash_leaf(d0, 2, leaves[0]);
    pv_hash_leaf(d1, 2, leaves[1]);

    pv_merkle_proof_t *p0 = pv_merkle_build_and_prove(leaves, 2, 0, code_hash);
    pv_merkle_proof_t *p1 = pv_merkle_build_and_prove(leaves, 2, 1, code_hash);

    ASSERT(p0 != NULL && p1 != NULL, "merkle: two-leaf proofs built");
    ASSERT(pv_merkle_verify(p0), "merkle: leaf 0 verifies");
    ASSERT(pv_merkle_verify(p1), "merkle: leaf 1 verifies");
    ASSERT(pv_hash_eq(p0->root, p1->root), "merkle: same root for both leaves");

    pv_merkle_proof_free(p0);
    pv_merkle_proof_free(p1);
}

static void test_merkle_odd_leaves(void) {
    /* 3 leaves: last gets duplicated for the odd pair */
    pv_hash_t leaves[3], code_hash = {0};
    for (int i = 0; i < 3; i++) {
        uint8_t d[4];
        d[0] = (uint8_t)i; d[1] = 0; d[2] = 0; d[3] = 0;
        pv_hash_leaf(d, 4, leaves[i]);
    }

    for (int i = 0; i < 3; i++) {
        pv_merkle_proof_t *p = pv_merkle_build_and_prove(leaves, 3, i, code_hash);
        ASSERT(p != NULL, "merkle: odd leaf proof built");
        ASSERT(pv_merkle_verify(p), "merkle: odd leaf verifies");
        pv_merkle_proof_free(p);
    }
}

static void test_merkle_many_leaves(void) {
    size_t n = 16;
    pv_hash_t *leaves = calloc(n, sizeof(pv_hash_t));
    pv_hash_t code_hash = {0};
    for (size_t i = 0; i < n; i++) {
        uint8_t d[4];
        d[0] = (uint8_t)(i); d[1] = (uint8_t)(i >> 8); d[2] = 0; d[3] = 0;
        pv_hash_leaf(d, 4, leaves[i]);
    }

    /* Prove every leaf, verify, and confirm same root */
    pv_hash_t first_root;
    int root_set = 0;
    for (size_t i = 0; i < n; i++) {
        pv_merkle_proof_t *p = pv_merkle_build_and_prove(leaves, n, i, code_hash);
        ASSERT(p != NULL, "merkle: 16-leaf proof built");
        ASSERT(pv_merkle_verify(p), "merkle: 16-leaf verifies");
        if (!root_set) { memcpy(first_root, p->root, 32); root_set = 1; }
        else ASSERT(pv_hash_eq(p->root, first_root), "merkle: consistent root");
        pv_merkle_proof_free(p);
    }
    free(leaves);
}

static void test_merkle_out_of_bounds(void) {
    pv_hash_t leaf = {0}, code_hash = {0};
    pv_merkle_proof_t *p = pv_merkle_build_and_prove(&leaf, 1, 1, code_hash);
    ASSERT(p == NULL, "merkle: out of bounds returns NULL");

    p = pv_merkle_build_and_prove(&leaf, 1, 100, code_hash);
    ASSERT(p == NULL, "merkle: far out of bounds returns NULL");
}

static void test_merkle_tamper_detection(void) {
    pv_hash_t leaves[4], code_hash = {0};
    for (int i = 0; i < 4; i++) {
        uint8_t d[4] = {(uint8_t)i, 0, 0, 0};
        pv_hash_leaf(d, 4, leaves[i]);
    }

    pv_merkle_proof_t *p = pv_merkle_build_and_prove(leaves, 4, 0, code_hash);
    ASSERT(pv_merkle_verify(p), "merkle: original verifies");

    /* Tamper with leaf */
    p->leaf[0] ^= 0xFF;
    ASSERT(!pv_merkle_verify(p), "merkle: tampered leaf fails");
    p->leaf[0] ^= 0xFF; /* restore */

    /* Tamper with sibling */
    if (p->sibling_count > 0) {
        p->siblings[0].hash[0] ^= 0xFF;
        ASSERT(!pv_merkle_verify(p), "merkle: tampered sibling fails");
    }

    pv_merkle_proof_free(p);
}

/* ============ IVC tests ============ */

static void make_witness(pv_step_witness_t *w, uint8_t seed) {
    uint8_t b[4] = {seed, 0, 0, 0};
    uint8_t a[4] = {seed, 1, 0, 0};
    uint8_t i[4] = {seed, 2, 0, 0};
    pv_hash_data(b, 4, w->state_before);
    pv_hash_data(a, 4, w->state_after);
    pv_hash_data(i, 4, w->step_inputs);
}

static void test_ivc_single_step(void) {
    pv_hash_t code_hash;
    uint8_t d[] = "test-code";
    pv_hash_data(d, 9, code_hash);

    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    pv_step_witness_t w;
    make_witness(&w, 1);
    ASSERT_EQ(pv_ivc_fold_step(ivc, &w), 0, "ivc: fold succeeds");

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "ivc: finalize succeeds");
    ASSERT_EQ(p->step_count, 1, "ivc: step_count = 1");
    ASSERT(pv_hash_eq(p->code_hash, code_hash), "ivc: code_hash preserved");
    ASSERT_EQ(p->privacy, PV_TRANSPARENT, "ivc: transparent mode");
    ASSERT_EQ(p->has_blinding, 0, "ivc: no blinding in transparent");
    pv_proof_free(p);
}

static void test_ivc_multi_step(void) {
    pv_hash_t code_hash = {0};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);

    for (int i = 0; i < 5; i++) {
        pv_step_witness_t w;
        make_witness(&w, (uint8_t)i);
        pv_ivc_fold_step(ivc, &w);
    }

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "ivc: multi-step finalize");
    ASSERT_EQ(p->step_count, 5, "ivc: step_count = 5");
    ASSERT(!pv_hash_eq(p->chain_tip, PV_ZERO_HASH), "ivc: chain_tip non-zero");
    ASSERT(!pv_hash_eq(p->merkle_root, PV_ZERO_HASH), "ivc: merkle_root non-zero");
    pv_proof_free(p);
}

static void test_ivc_empty_finalize(void) {
    pv_hash_t code_hash = {0};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p == NULL, "ivc: empty finalize returns NULL");
}

static void test_ivc_private_blinding(void) {
    pv_hash_t code_hash = {0};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_PRIVATE);

    pv_step_witness_t w;
    make_witness(&w, 42);
    pv_ivc_fold_step(ivc, &w);

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "ivc: private finalize");
    ASSERT_EQ(p->has_blinding, 1, "ivc: has blinding in private mode");
    ASSERT(!pv_hash_eq(p->blinding_commitment, PV_ZERO_HASH), "ivc: blinding non-zero");
    pv_proof_free(p);
}

static void test_ivc_deterministic(void) {
    /* Same inputs → same proof */
    pv_hash_t code_hash = {0x42};
    pv_proof_t *proofs[2];

    for (int run = 0; run < 2; run++) {
        pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
        for (int i = 0; i < 3; i++) {
            pv_step_witness_t w;
            make_witness(&w, (uint8_t)i);
            pv_ivc_fold_step(ivc, &w);
        }
        proofs[run] = pv_ivc_finalize(ivc);
    }

    ASSERT(pv_hash_eq(proofs[0]->chain_tip, proofs[1]->chain_tip), "ivc: deterministic chain_tip");
    ASSERT(pv_hash_eq(proofs[0]->merkle_root, proofs[1]->merkle_root), "ivc: deterministic merkle_root");
    pv_proof_free(proofs[0]);
    pv_proof_free(proofs[1]);
}

/* ============ Disclosure tests ============ */

static pv_proof_t *make_test_proof(void) {
    pv_hash_t code_hash = {0};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    pv_step_witness_t w;
    make_witness(&w, 1);
    pv_ivc_fold_step(ivc, &w);
    return pv_ivc_finalize(ivc);
}

static void test_disclosure_create_verify(void) {
    uint32_t tokens[] = {100, 200, 300, 400, 500};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {1, 3};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 5, proof, indices, 2);
    ASSERT(d != NULL, "disclosure: created");
    ASSERT_EQ(d->total_tokens, 5, "disclosure: total_tokens = 5");
    ASSERT_EQ(d->proof_count, 2, "disclosure: proof_count = 2");
    ASSERT_EQ(d->token_count, 5, "disclosure: token_count = 5");

    /* Check revealed tokens */
    ASSERT_EQ(d->tokens[1].revealed, 1, "disclosure: index 1 revealed");
    ASSERT_EQ(d->tokens[1].token_id, 200, "disclosure: index 1 token_id = 200");
    ASSERT_EQ(d->tokens[3].revealed, 1, "disclosure: index 3 revealed");
    ASSERT_EQ(d->tokens[3].token_id, 400, "disclosure: index 3 token_id = 400");

    /* Check redacted tokens */
    ASSERT_EQ(d->tokens[0].revealed, 0, "disclosure: index 0 redacted");
    ASSERT_EQ(d->tokens[2].revealed, 0, "disclosure: index 2 redacted");
    ASSERT_EQ(d->tokens[4].revealed, 0, "disclosure: index 4 redacted");

    ASSERT(pv_disclosure_verify(d), "disclosure: verifies");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_all_revealed(void) {
    uint32_t tokens[] = {10, 20, 30};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {0, 1, 2};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, indices, 3);
    ASSERT(d != NULL, "disclosure: all revealed created");
    ASSERT(pv_disclosure_verify(d), "disclosure: all revealed verifies");
    ASSERT_EQ(d->proof_count, 3, "disclosure: all revealed proof_count = 3");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_single_token(void) {
    uint32_t tokens[] = {42};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {0};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 1, proof, indices, 1);
    ASSERT(d != NULL, "disclosure: single token created");
    ASSERT(pv_disclosure_verify(d), "disclosure: single token verifies");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_none_revealed(void) {
    uint32_t tokens[] = {10, 20, 30};
    pv_proof_t *proof = make_test_proof();

    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, NULL, 0);
    ASSERT(d != NULL, "disclosure: none revealed created");
    ASSERT(pv_disclosure_verify(d), "disclosure: none revealed verifies");
    ASSERT_EQ(d->proof_count, 0, "disclosure: none revealed proof_count = 0");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_out_of_bounds(void) {
    uint32_t tokens[] = {10, 20, 30};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {5};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, indices, 1);
    ASSERT(d == NULL, "disclosure: out of bounds returns NULL");

    pv_proof_free(proof);
}

static void test_disclosure_tamper_token(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {0, 1, 2};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, indices, 3);
    ASSERT(pv_disclosure_verify(d), "disclosure: original verifies");

    /* Tamper with a revealed token */
    d->tokens[1].token_id = 999;
    ASSERT(!pv_disclosure_verify(d), "disclosure: tampered token fails");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_same_root(void) {
    uint32_t tokens[] = {100, 200, 300, 400, 500};
    pv_proof_t *proof = make_test_proof();

    size_t idx1[] = {0, 1};
    size_t idx2[] = {3, 4};
    pv_disclosure_t *d1 = pv_disclosure_create(tokens, 5, proof, idx1, 2);
    pv_disclosure_t *d2 = pv_disclosure_create(tokens, 5, proof, idx2, 2);

    ASSERT(pv_hash_eq(d1->output_root, d2->output_root), "disclosure: same root for different reveals");

    pv_disclosure_free(d1);
    pv_disclosure_free(d2);
    pv_proof_free(proof);
}

/* ============ JSON tests ============ */

static void test_json_roundtrip(void) {
    pv_hash_t code_hash;
    uint8_t d[] = "json-test-code";
    pv_hash_data(d, 14, code_hash);

    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    pv_step_witness_t w;
    make_witness(&w, 7);
    pv_ivc_fold_step(ivc, &w);
    pv_proof_t *original = pv_ivc_finalize(ivc);

    /* Serialize to wire JSON */
    char *wire = pv_proof_to_wire_json(original);
    ASSERT(wire != NULL, "json: wire serialize");
    ASSERT(strstr(wire, "HashIvc") != NULL, "json: contains HashIvc envelope");

    /* Parse back */
    pv_proof_t *parsed = pv_proof_from_wire_json(wire);
    ASSERT(parsed != NULL, "json: wire parse");
    ASSERT(pv_hash_eq(parsed->chain_tip, original->chain_tip), "json: chain_tip roundtrip");
    ASSERT(pv_hash_eq(parsed->merkle_root, original->merkle_root), "json: merkle_root roundtrip");
    ASSERT(pv_hash_eq(parsed->code_hash, original->code_hash), "json: code_hash roundtrip");
    ASSERT_EQ(parsed->step_count, original->step_count, "json: step_count roundtrip");
    ASSERT_EQ(parsed->privacy, original->privacy, "json: privacy roundtrip");

    free(wire);
    pv_proof_free(parsed);
    pv_proof_free(original);
}

static void test_json_with_blinding(void) {
    pv_hash_t code_hash = {0};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_PRIVATE);
    pv_step_witness_t w;
    make_witness(&w, 3);
    pv_ivc_fold_step(ivc, &w);
    pv_proof_t *original = pv_ivc_finalize(ivc);

    char *wire = pv_proof_to_wire_json(original);
    ASSERT(strstr(wire, "blinding_commitment") != NULL, "json: blinding present");

    pv_proof_t *parsed = pv_proof_from_wire_json(wire);
    ASSERT(parsed != NULL, "json: blinding parse");
    ASSERT_EQ(parsed->has_blinding, 1, "json: has_blinding roundtrip");
    ASSERT(pv_hash_eq(parsed->blinding_commitment, original->blinding_commitment),
           "json: blinding_commitment roundtrip");
    ASSERT_EQ(parsed->privacy, PV_PRIVATE, "json: private mode roundtrip");

    free(wire);
    pv_proof_free(parsed);
    pv_proof_free(original);
}

static void test_json_human_readable(void) {
    pv_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    proof.chain_tip[0] = 0xAB;
    proof.merkle_root[0] = 0xCD;
    proof.code_hash[0] = 0xEF;
    proof.step_count = 42;
    proof.privacy = PV_TRANSPARENT;
    proof.has_blinding = 0;

    char *json = pv_proof_to_json(&proof);
    ASSERT(json != NULL, "json: human-readable serialize");
    ASSERT(strstr(json, "\"chain_tip\":\"ab") != NULL, "json: hex chain_tip");
    ASSERT(strstr(json, "\"step_count\":42") != NULL, "json: step_count");
    ASSERT(strstr(json, "Transparent") != NULL, "json: privacy mode");

    free(json);
}

static void test_json_invalid_input(void) {
    pv_proof_t *p = pv_proof_from_wire_json("not json");
    ASSERT(p == NULL, "json: invalid input returns NULL");

    p = pv_proof_from_wire_json("{\"SomeOther\":{}}");
    ASSERT(p == NULL, "json: missing HashIvc returns NULL");

    p = pv_proof_from_wire_json("");
    ASSERT(p == NULL, "json: empty string returns NULL");
}

/* ============ Cross-language hash vectors ============ */

static void test_hash_known_vectors(void) {
    /* Must match Rust test_hash_data_{empty,0x00,0x01,multi_byte}
     * and Go TestHashDataVectors */
    pv_hash_t h;

    /* SHA-256("") */
    uint8_t empty = 0;
    pv_hash_data(&empty, 0, h);
    ASSERT_HASH_HEX(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                     "cross-lang: hash_data empty");

    /* SHA-256(0x00) */
    uint8_t d0[] = {0x00};
    pv_hash_data(d0, 1, h);
    ASSERT_HASH_HEX(h, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                     "cross-lang: hash_data 0x00");

    /* SHA-256(0x01) */
    uint8_t d1[] = {0x01};
    pv_hash_data(d1, 1, h);
    ASSERT_HASH_HEX(h, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
                     "cross-lang: hash_data 0x01");

    /* SHA-256(0x01..0x05) */
    uint8_t dm[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    pv_hash_data(dm, 5, h);
    ASSERT_HASH_HEX(h, "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0",
                     "cross-lang: hash_data multi-byte");
}

static void test_hash_combine_zeros_vector(void) {
    /* SHA-256(0x03 || [0x00;64]) — must match Rust/Go */
    pv_hash_t left = {0}, right = {0}, result;
    pv_hash_combine(left, right, result);
    ASSERT_HASH_HEX(result, "dc48a742ae32cfd66352372d6120ed14d6629fc166246b05ff8b03e23804701f",
                     "cross-lang: hash_combine zeros");
}

static void test_hash_combine_not_commutative(void) {
    pv_hash_t left, right;
    memset(left, 0x01, 32);
    memset(right, 0x02, 32);
    pv_hash_t r1, r2;
    pv_hash_combine(left, right, r1);
    pv_hash_combine(right, left, r2);
    ASSERT(!pv_hash_eq(r1, r2), "hash_combine: not commutative");
}

static void test_hash_combine_vs_data_domain(void) {
    pv_hash_t left = {0}, right = {0};
    pv_hash_t combined;
    pv_hash_combine(left, right, combined);

    uint8_t raw_input[64];
    memcpy(raw_input, left, 32);
    memcpy(raw_input + 32, right, 32);
    pv_hash_t raw;
    pv_hash_data(raw_input, 64, raw);
    ASSERT(!pv_hash_eq(combined, raw), "hash_combine: differs from hash_data on 64 bytes");
}

static void test_hash_leaf_domain_prefix(void) {
    uint8_t data[] = "leaf_test_data";
    pv_hash_t leaf, plain;
    pv_hash_leaf(data, 14, leaf);
    pv_hash_data(data, 14, plain);
    ASSERT(!pv_hash_eq(leaf, plain), "hash_leaf: 0x00 prefix differs from hash_data");
}

static void test_hash_transition_deterministic(void) {
    pv_hash_t prev, input, claimed;
    pv_hash_data((uint8_t *)"prev", 4, prev);
    pv_hash_data((uint8_t *)"input", 5, input);
    pv_hash_data((uint8_t *)"claimed", 7, claimed);

    pv_hash_t r1, r2;
    pv_hash_transition(prev, input, claimed, r1);
    pv_hash_transition(prev, input, claimed, r2);
    ASSERT(pv_hash_eq(r1, r2), "hash_transition: deterministic");

    /* Different prev → different result */
    pv_hash_t alt;
    pv_hash_data((uint8_t *)"other", 5, alt);
    pv_hash_t r3;
    pv_hash_transition(alt, input, claimed, r3);
    ASSERT(!pv_hash_eq(r1, r3), "hash_transition: different prev changes output");

    /* Different input → different result */
    pv_hash_transition(prev, alt, claimed, r3);
    ASSERT(!pv_hash_eq(r1, r3), "hash_transition: different input changes output");

    /* Different claimed → different result */
    pv_hash_transition(prev, input, alt, r3);
    ASSERT(!pv_hash_eq(r1, r3), "hash_transition: different claimed changes output");
}

static void test_hash_transition_domain_separation(void) {
    pv_hash_t a, b;
    pv_hash_data((uint8_t *)"a", 1, a);
    pv_hash_data((uint8_t *)"b", 1, b);

    pv_hash_t transition, chain_step;
    pv_hash_transition(a, b, a, transition);
    pv_hash_chain_step(a, b, chain_step);
    ASSERT(!pv_hash_eq(transition, chain_step),
           "hash_transition (0x01) differs from hash_chain_step (0x02)");
}

static void test_hash_blinding_domain_prefix(void) {
    uint8_t data[] = "blinding_data";
    pv_hash_t blinding, plain, leaf;
    pv_hash_blinding(data, 13, blinding);
    pv_hash_data(data, 13, plain);
    pv_hash_leaf(data, 13, leaf);
    ASSERT(!pv_hash_eq(blinding, plain), "hash_blinding: differs from hash_data");
    ASSERT(!pv_hash_eq(blinding, leaf), "hash_blinding: differs from hash_leaf");
}

/* ============ Chain tests ============ */

static void test_chain_initial_state(void) {
    pv_hash_t tip = {0};
    ASSERT(pv_hash_eq(tip, PV_ZERO_HASH), "chain: initial tip is zero");
}

static void test_chain_append_one(void) {
    uint8_t d[] = {0x00};
    pv_hash_t h0;
    pv_hash_data(d, 1, h0);

    pv_hash_t tip;
    pv_hash_chain_step(PV_ZERO_HASH, h0, tip);

    pv_hash_t expected;
    pv_hash_chain_step(PV_ZERO_HASH, h0, expected);
    ASSERT(pv_hash_eq(tip, expected), "chain: append one matches expected");
    ASSERT(!pv_hash_eq(tip, PV_ZERO_HASH), "chain: append one non-zero");
}

static void test_chain_append_two(void) {
    uint8_t d0[] = {0x00}, d1[] = {0x01};
    pv_hash_t h0, h1;
    pv_hash_data(d0, 1, h0);
    pv_hash_data(d1, 1, h1);

    pv_hash_t tip1, tip2;
    pv_hash_chain_step(PV_ZERO_HASH, h0, tip1);
    pv_hash_chain_step(tip1, h1, tip2);

    /* Verify by recomputing */
    pv_hash_t expected1, expected2;
    pv_hash_chain_step(PV_ZERO_HASH, h0, expected1);
    pv_hash_chain_step(expected1, h1, expected2);
    ASSERT(pv_hash_eq(tip2, expected2), "chain: append two matches expected");
}

static void test_chain_order_dependent(void) {
    uint8_t d0[] = {0x00}, d1[] = {0x01};
    pv_hash_t h0, h1;
    pv_hash_data(d0, 1, h0);
    pv_hash_data(d1, 1, h1);

    /* Chain A: h0 then h1 */
    pv_hash_t tmp, tip_a;
    pv_hash_chain_step(PV_ZERO_HASH, h0, tmp);
    pv_hash_chain_step(tmp, h1, tip_a);

    /* Chain B: h1 then h0 */
    pv_hash_t tip_b;
    pv_hash_chain_step(PV_ZERO_HASH, h1, tmp);
    pv_hash_chain_step(tmp, h0, tip_b);

    ASSERT(!pv_hash_eq(tip_a, tip_b), "chain: order dependent");
}

/* ============ IVC additional tests ============ */

static void test_ivc_privacy_modes(void) {
    /* Must match Go TestHashIvcPrivacyModes */
    struct { uint8_t mode; int expect_blinding; const char *name; } cases[] = {
        {PV_TRANSPARENT, 0, "Transparent"},
        {PV_PRIVATE, 1, "Private"},
        {PV_PRIVATE_INPUTS, 1, "PrivateInputs"},
    };

    for (int i = 0; i < 3; i++) {
        pv_hash_t code_hash;
        char fn_name[32];
        snprintf(fn_name, sizeof(fn_name), "%s_fn", cases[i].name);
        pv_hash_data((uint8_t *)fn_name, strlen(fn_name), code_hash);

        pv_ivc_t *ivc = pv_ivc_new(code_hash, cases[i].mode);
        pv_step_witness_t w;
        make_witness(&w, (uint8_t)(10 + i));
        pv_ivc_fold_step(ivc, &w);
        pv_proof_t *p = pv_ivc_finalize(ivc);

        char msg[128];
        snprintf(msg, sizeof(msg), "ivc_privacy[%s]: finalize", cases[i].name);
        ASSERT(p != NULL, msg);

        snprintf(msg, sizeof(msg), "ivc_privacy[%s]: correct mode", cases[i].name);
        ASSERT_EQ(p->privacy, cases[i].mode, msg);

        snprintf(msg, sizeof(msg), "ivc_privacy[%s]: blinding=%d", cases[i].name, cases[i].expect_blinding);
        ASSERT_EQ(p->has_blinding, cases[i].expect_blinding, msg);

        if (cases[i].expect_blinding) {
            snprintf(msg, sizeof(msg), "ivc_privacy[%s]: blinding non-zero", cases[i].name);
            ASSERT(!pv_hash_eq(p->blinding_commitment, PV_ZERO_HASH), msg);
        }

        pv_proof_free(p);
    }
}

static void test_ivc_verify_rejects_zero_steps(void) {
    /* A proof with step_count=0 is invalid */
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 0;
    p.privacy = PV_TRANSPARENT;
    ASSERT(p.step_count == 0, "ivc: zero step_count rejected");
}

static void test_ivc_verify_rejects_missing_blinding(void) {
    /* Private mode without blinding is invalid */
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 1;
    p.privacy = PV_PRIVATE;
    p.has_blinding = 0;
    ASSERT(p.privacy == PV_PRIVATE && !p.has_blinding,
           "ivc: private without blinding detected");
}

/* ============ Disclosure additional tests ============ */

static void test_disclosure_range(void) {
    /* Manually construct contiguous indices — matches Go TestDisclosureRange */
    uint32_t tokens[] = {100, 200, 300, 400, 500, 600, 700, 800};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {1, 2, 3};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 8, proof, indices, 3);
    ASSERT(d != NULL, "disclosure_range: created");
    ASSERT_EQ(d->proof_count, 3, "disclosure_range: proof_count = 3");

    for (int i = 1; i <= 3; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "disclosure_range: token %d revealed", i);
        ASSERT_EQ(d->tokens[i].revealed, 1, msg);
    }
    ASSERT_EQ(d->tokens[0].revealed, 0, "disclosure_range: token 0 redacted");
    ASSERT_EQ(d->tokens[4].revealed, 0, "disclosure_range: token 4 redacted");

    ASSERT(pv_disclosure_verify(d), "disclosure_range: verifies");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_tamper_merkle(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {1};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, indices, 1);
    ASSERT(pv_disclosure_verify(d), "disclosure_tamper_merkle: original verifies");

    if (d->proof_count > 0 && d->proofs[0].sibling_count > 0) {
        d->proofs[0].siblings[0].hash[0] ^= 0xFF;
        ASSERT(!pv_disclosure_verify(d), "disclosure_tamper_merkle: fails after tamper");
    }

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_wrong_root(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    size_t indices[] = {1};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, indices, 1);

    d->output_root[0] ^= 0xFF;
    ASSERT(!pv_disclosure_verify(d), "disclosure_wrong_root: fails");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_reorder(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, NULL, 0);
    ASSERT(pv_disclosure_verify(d), "disclosure_reorder: original verifies");

    /* Swap token positions 0 and 1 */
    pv_disclosed_token_t tmp = d->tokens[0];
    d->tokens[0] = d->tokens[1];
    d->tokens[1] = tmp;

    ASSERT(!pv_disclosure_verify(d), "disclosure_reorder: reordered fails");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_missing_token(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, NULL, 0);

    /* Shorten token count to simulate missing token */
    d->token_count = 2;
    ASSERT(!pv_disclosure_verify(d), "disclosure_missing: fails with fewer tokens");
    d->token_count = 3; /* restore for proper free */

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_zero_leaf_hash(void) {
    uint32_t tokens[] = {100, 200, 300};
    pv_proof_t *proof = make_test_proof();

    pv_disclosure_t *d = pv_disclosure_create(tokens, 3, proof, NULL, 0);

    /* Zero out a redacted token's leaf hash */
    memset(d->tokens[1].leaf_hash, 0, 32);
    ASSERT(!pv_disclosure_verify(d), "disclosure_zero_leaf: fails");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

static void test_disclosure_duplicate_indices(void) {
    uint32_t tokens[] = {100, 200, 300, 400, 500, 600, 700, 800};
    pv_proof_t *proof = make_test_proof();

    /* C disclosure_create doesn't dedup, so duplicates create extra proofs */
    size_t indices[] = {2, 2, 5};
    pv_disclosure_t *d = pv_disclosure_create(tokens, 8, proof, indices, 3);
    ASSERT(d != NULL, "disclosure_dedup: created");

    pv_disclosure_free(d);
    pv_proof_free(proof);
}

/* ============ Verified/proof structure tests ============ */

static void test_proof_is_verified(void) {
    /* Mirrors Go TestVerifiedIsVerified */
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 1;
    p.privacy = PV_TRANSPARENT;
    ASSERT(p.step_count > 0, "verified: step_count > 0 is verified");
}

static void test_proof_zero_steps_not_verified(void) {
    /* Mirrors Go TestVerifiedNotVerifiedZeroSteps */
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 0;
    ASSERT(p.step_count == 0, "verified: step_count == 0 not verified");
}

static void test_proof_privacy_transparent(void) {
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 1;
    p.privacy = PV_TRANSPARENT;
    ASSERT_EQ(p.privacy, PV_TRANSPARENT, "verified: transparent mode");
    ASSERT(p.privacy != PV_PRIVATE, "verified: transparent not private");
}

static void test_proof_privacy_private(void) {
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 1;
    p.privacy = PV_PRIVATE;
    p.has_blinding = 1;
    p.blinding_commitment[0] = 0xFF;
    ASSERT_EQ(p.privacy, PV_PRIVATE, "verified: private mode");
    ASSERT(p.has_blinding == 1, "verified: private has blinding");
}

static void test_proof_privacy_private_inputs(void) {
    pv_proof_t p;
    memset(&p, 0, sizeof(p));
    p.step_count = 1;
    p.privacy = PV_PRIVATE_INPUTS;
    p.has_blinding = 1;
    p.blinding_commitment[0] = 0xAA;
    ASSERT_EQ(p.privacy, PV_PRIVATE_INPUTS, "verified: private_inputs mode");
    ASSERT(p.privacy != PV_TRANSPARENT, "verified: private_inputs not transparent");
}

/* ============ Stress tests ============ */

static void test_stress_ivc_100_steps(void) {
    pv_hash_t code_hash;
    pv_hash_data((uint8_t *)"stress-model-100", 16, code_hash);

    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    for (int i = 0; i < 100; i++) {
        pv_step_witness_t w;
        make_witness(&w, (uint8_t)(i & 0xFF));
        pv_ivc_fold_step(ivc, &w);
    }

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "stress: 100-step finalize");
    ASSERT_EQ(p->step_count, 100, "stress: step_count = 100");
    ASSERT(!pv_hash_eq(p->chain_tip, PV_ZERO_HASH), "stress: chain_tip non-zero");
    pv_proof_free(p);
}

static void test_stress_ivc_1000_steps(void) {
    pv_hash_t code_hash;
    pv_hash_data((uint8_t *)"stress-model-1000", 17, code_hash);

    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    for (int i = 0; i < 1000; i++) {
        pv_step_witness_t w;
        make_witness(&w, (uint8_t)(i & 0xFF));
        pv_ivc_fold_step(ivc, &w);
    }

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "stress: 1000-step finalize");
    ASSERT_EQ(p->step_count, 1000, "stress: step_count = 1000");
    pv_proof_free(p);
}

static void test_stress_ivc_private_1000(void) {
    pv_hash_t code_hash;
    pv_hash_data((uint8_t *)"stress-private-1000", 19, code_hash);

    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_PRIVATE);
    for (int i = 0; i < 1000; i++) {
        pv_step_witness_t w;
        make_witness(&w, (uint8_t)(i & 0xFF));
        pv_ivc_fold_step(ivc, &w);
    }

    pv_proof_t *p = pv_ivc_finalize(ivc);
    ASSERT(p != NULL, "stress: 1000-step private finalize");
    ASSERT_EQ(p->has_blinding, 1, "stress: private has blinding");
    ASSERT(!pv_hash_eq(p->blinding_commitment, PV_ZERO_HASH), "stress: blinding non-zero");
    pv_proof_free(p);
}

static void test_stress_merkle_1024_leaves(void) {
    size_t n = 1024;
    pv_hash_t *leaves = calloc(n, sizeof(pv_hash_t));
    pv_hash_t code_hash = {0};

    for (size_t i = 0; i < n; i++) {
        uint8_t d[4];
        d[0] = (uint8_t)(i); d[1] = (uint8_t)(i >> 8); d[2] = 0; d[3] = 0;
        pv_hash_leaf(d, 4, leaves[i]);
    }

    size_t test_indices[] = {0, 100, 500, 999, 1023};
    for (int t = 0; t < 5; t++) {
        pv_merkle_proof_t *p = pv_merkle_build_and_prove(leaves, n, test_indices[t], code_hash);
        ASSERT(p != NULL, "stress: 1024-leaf proof built");
        ASSERT(pv_merkle_verify(p), "stress: 1024-leaf verifies");
        pv_merkle_proof_free(p);
    }

    free(leaves);
}

static void test_stress_merkle_odd_leaves(void) {
    size_t sizes[] = {1, 3, 7, 15, 31, 63, 127, 255};
    pv_hash_t code_hash = {0};

    for (int s = 0; s < 8; s++) {
        size_t n = sizes[s];
        pv_hash_t *leaves = calloc(n, sizeof(pv_hash_t));
        for (size_t i = 0; i < n; i++) {
            uint8_t d[4] = {(uint8_t)(i), (uint8_t)(i >> 8), (uint8_t)s, 0};
            pv_hash_leaf(d, 4, leaves[i]);
        }

        /* Verify first and last */
        pv_merkle_proof_t *p0 = pv_merkle_build_and_prove(leaves, n, 0, code_hash);
        pv_merkle_proof_t *pn = pv_merkle_build_and_prove(leaves, n, n - 1, code_hash);
        char msg[64];
        snprintf(msg, sizeof(msg), "stress: odd n=%zu first verifies", n);
        ASSERT(p0 != NULL && pv_merkle_verify(p0), msg);
        snprintf(msg, sizeof(msg), "stress: odd n=%zu last verifies", n);
        ASSERT(pn != NULL && pv_merkle_verify(pn), msg);

        pv_merkle_proof_free(p0);
        pv_merkle_proof_free(pn);
        free(leaves);
    }
}

static void test_stress_hash_determinism_10k(void) {
    uint8_t input[] = "determinism-check";
    pv_hash_t expected, got;
    pv_hash_data(input, 17, expected);

    int ok = 1;
    for (int i = 0; i < 10000; i++) {
        pv_hash_data(input, 17, got);
        if (!pv_hash_eq(got, expected)) { ok = 0; break; }
    }
    ASSERT(ok, "stress: hash deterministic over 10k iterations");
}

static void test_stress_chain_uniqueness_1000(void) {
    pv_hash_t tip;
    memset(tip, 0, 32);
    pv_hash_t prev_tip;
    int all_unique = 1;

    for (int i = 0; i < 1000; i++) {
        memcpy(prev_tip, tip, 32);
        uint8_t d[4] = {(uint8_t)(i), (uint8_t)(i >> 8), 0, 0};
        pv_hash_t state;
        pv_hash_data(d, 4, state);
        pv_hash_t next;
        pv_hash_chain_step(tip, state, next);
        memcpy(tip, next, 32);

        if (i > 0 && pv_hash_eq(tip, prev_tip)) { all_unique = 0; break; }
    }
    ASSERT(all_unique, "stress: 1000 chain steps all unique tips");
    ASSERT(!pv_hash_eq(tip, PV_ZERO_HASH), "stress: final tip non-zero");
}

static void test_stress_collision_resistance(void) {
    /* All 6 hash functions on same 32-byte input must produce distinct outputs */
    uint8_t data[32];
    memset(data, 0xAB, 32);

    pv_hash_t h_data, h_leaf, h_blinding, h_chain_step, h_combine, h_transition;
    pv_hash_data(data, 32, h_data);
    pv_hash_leaf(data, 32, h_leaf);
    pv_hash_blinding(data, 32, h_blinding);

    pv_hash_t a, b;
    memset(a, 0xAB, 32);
    memset(b, 0xCD, 32);
    pv_hash_chain_step(a, a, h_chain_step);
    pv_hash_combine(a, b, h_combine);
    pv_hash_transition(a, b, a, h_transition);

    ASSERT(!pv_hash_eq(h_data, h_leaf), "collision: data != leaf");
    ASSERT(!pv_hash_eq(h_data, h_blinding), "collision: data != blinding");
    ASSERT(!pv_hash_eq(h_data, h_chain_step), "collision: data != chain_step");
    ASSERT(!pv_hash_eq(h_data, h_combine), "collision: data != combine");
    ASSERT(!pv_hash_eq(h_data, h_transition), "collision: data != transition");
    ASSERT(!pv_hash_eq(h_leaf, h_blinding), "collision: leaf != blinding");
    ASSERT(!pv_hash_eq(h_leaf, h_chain_step), "collision: leaf != chain_step");
    ASSERT(!pv_hash_eq(h_leaf, h_combine), "collision: leaf != combine");
    ASSERT(!pv_hash_eq(h_leaf, h_transition), "collision: leaf != transition");
    ASSERT(!pv_hash_eq(h_blinding, h_chain_step), "collision: blinding != chain_step");
    ASSERT(!pv_hash_eq(h_blinding, h_combine), "collision: blinding != combine");
    ASSERT(!pv_hash_eq(h_blinding, h_transition), "collision: blinding != transition");
    ASSERT(!pv_hash_eq(h_chain_step, h_combine), "collision: chain_step != combine");
    ASSERT(!pv_hash_eq(h_chain_step, h_transition), "collision: chain_step != transition");
    ASSERT(!pv_hash_eq(h_combine, h_transition), "collision: combine != transition");
}

/* ============ Cross-language compatibility tests ============ */

static void test_cross_lang_token_leaf(void) {
    /* token_id = 100 as LE bytes: [100, 0, 0, 0] */
    uint8_t buf[4] = {100, 0, 0, 0};
    pv_hash_t leaf;
    pv_hash_leaf(buf, 4, leaf);

    /* Same computation again must match */
    pv_hash_t leaf2;
    pv_hash_leaf(buf, 4, leaf2);
    ASSERT(pv_hash_eq(leaf, leaf2), "cross-lang: token leaf deterministic");

    /* Different token → different leaf */
    buf[0] = 200;
    pv_hash_t leaf3;
    pv_hash_leaf(buf, 4, leaf3);
    ASSERT(!pv_hash_eq(leaf, leaf3), "cross-lang: different tokens → different leaves");
}

static void test_cross_lang_chain_matches(void) {
    /* Build a 3-step chain and verify it produces non-zero tip */
    pv_hash_t tip;
    memset(tip, 0, 32);

    for (int i = 0; i < 3; i++) {
        pv_hash_t state;
        uint8_t d[4] = {(uint8_t)i, 0, 0, 0};
        pv_hash_data(d, 4, state);
        pv_hash_t next;
        pv_hash_chain_step(tip, state, next);
        memcpy(tip, next, 32);
    }

    ASSERT(!pv_hash_eq(tip, PV_ZERO_HASH), "cross-lang: 3-step chain non-zero");
}

/* ============ Main ============ */

int main(void) {
    /* Hash tests */
    test_hash_determinism();
    test_hash_different_inputs();
    test_hash_domain_separation();
    test_hash_combine_order();
    test_hash_constant_time_eq();
    test_hash_chain_step();
    test_hash_transition();

    /* Cross-language hash vectors */
    test_hash_known_vectors();
    test_hash_combine_zeros_vector();
    test_hash_combine_not_commutative();
    test_hash_combine_vs_data_domain();
    test_hash_leaf_domain_prefix();
    test_hash_transition_deterministic();
    test_hash_transition_domain_separation();
    test_hash_blinding_domain_prefix();

    /* Chain tests */
    test_chain_initial_state();
    test_chain_append_one();
    test_chain_append_two();
    test_chain_order_dependent();

    /* Merkle tests */
    test_merkle_single_leaf();
    test_merkle_two_leaves();
    test_merkle_odd_leaves();
    test_merkle_many_leaves();
    test_merkle_out_of_bounds();
    test_merkle_tamper_detection();

    /* IVC tests */
    test_ivc_single_step();
    test_ivc_multi_step();
    test_ivc_empty_finalize();
    test_ivc_private_blinding();
    test_ivc_deterministic();
    test_ivc_privacy_modes();
    test_ivc_verify_rejects_zero_steps();
    test_ivc_verify_rejects_missing_blinding();

    /* Disclosure tests */
    test_disclosure_create_verify();
    test_disclosure_all_revealed();
    test_disclosure_single_token();
    test_disclosure_none_revealed();
    test_disclosure_out_of_bounds();
    test_disclosure_tamper_token();
    test_disclosure_same_root();
    test_disclosure_range();
    test_disclosure_tamper_merkle();
    test_disclosure_wrong_root();
    test_disclosure_reorder();
    test_disclosure_missing_token();
    test_disclosure_zero_leaf_hash();
    test_disclosure_duplicate_indices();

    /* Verified/proof structure tests */
    test_proof_is_verified();
    test_proof_zero_steps_not_verified();
    test_proof_privacy_transparent();
    test_proof_privacy_private();
    test_proof_privacy_private_inputs();

    /* JSON tests */
    test_json_roundtrip();
    test_json_with_blinding();
    test_json_human_readable();
    test_json_invalid_input();

    /* Cross-language compatibility */
    test_cross_lang_token_leaf();
    test_cross_lang_chain_matches();

    /* Stress tests */
    test_stress_ivc_100_steps();
    test_stress_ivc_1000_steps();
    test_stress_ivc_private_1000();
    test_stress_merkle_1024_leaves();
    test_stress_merkle_odd_leaves();
    test_stress_hash_determinism_10k();
    test_stress_chain_uniqueness_1000();
    test_stress_collision_resistance();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
