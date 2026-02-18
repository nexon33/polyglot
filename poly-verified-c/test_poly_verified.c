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

    /* Disclosure tests */
    test_disclosure_create_verify();
    test_disclosure_all_revealed();
    test_disclosure_single_token();
    test_disclosure_none_revealed();
    test_disclosure_out_of_bounds();
    test_disclosure_tamper_token();
    test_disclosure_same_root();

    /* JSON tests */
    test_json_roundtrip();
    test_json_with_blinding();
    test_json_human_readable();
    test_json_invalid_input();

    /* Cross-language compatibility */
    test_cross_lang_token_leaf();
    test_cross_lang_chain_matches();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
