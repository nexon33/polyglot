#include "poly_client.h"
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
#define ASSERT_STREQ(a, b, msg) ASSERT(strcmp((a), (b)) == 0, msg)

/* ---------- Helpers ---------- */

/* Build a mock server response JSON with the given tokens and a valid proof */
static char *mock_server_response(const uint32_t *tokens, size_t n) {
    /* Build encrypted_output (mock ciphertext) */
    size_t enc_sz = n * 12 + 64;
    char *enc = malloc(enc_sz);
    int pos = 0;
    pos += snprintf(enc + pos, enc_sz - pos, "{\"tokens\":[");
    for (size_t i = 0; i < n; i++) {
        if (i > 0) pos += snprintf(enc + pos, enc_sz - pos, ",");
        pos += snprintf(enc + pos, enc_sz - pos, "%u", tokens[i]);
    }
    snprintf(enc + pos, enc_sz - pos, "]}");

    /* Build a real proof via IVC */
    pv_hash_t code_hash = {0x03};
    pv_ivc_t *ivc = pv_ivc_new(code_hash, PV_TRANSPARENT);
    pv_step_witness_t w;
    uint8_t b[] = {1,0,0,0}, a[] = {1,1,0,0}, inp[] = {1,2,0,0};
    pv_hash_data(b, 4, w.state_before);
    pv_hash_data(a, 4, w.state_after);
    pv_hash_data(inp, 4, w.step_inputs);
    pv_ivc_fold_step(ivc, &w);
    pv_proof_t *proof = pv_ivc_finalize(ivc);

    char *wire_proof = pv_proof_to_wire_json(proof);

    /* Assemble full response JSON */
    size_t buf_sz = strlen(enc) + strlen(wire_proof) + 256;
    char *buf = malloc(buf_sz);
    snprintf(buf, buf_sz,
        "{\"encrypted_output\":%s,\"proof\":%s,\"model_id\":\"test-model\"}",
        enc, wire_proof);

    free(enc);
    free(wire_proof);
    pv_proof_free(proof);
    return buf;
}

/* ---------- Tests ---------- */

static void test_client_creation(void) {
    pc_client_t *c = pc_client_new("Qwen/Qwen3-0.6B", PV_MODE_ENCRYPTED);
    ASSERT(c != NULL, "client: created");
    ASSERT_STREQ(pc_client_model_id(c), "Qwen/Qwen3-0.6B", "client: model_id");
    ASSERT_EQ(pc_client_mode(c), PV_MODE_ENCRYPTED, "client: mode");
    pc_client_free(c);
}

static void test_prepare_request(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_PRIVATE_PROVEN);
    uint32_t tokens[] = {100, 200, 300};
    char *req = pc_client_prepare_request_json(c, tokens, 3, 50, 700, 42);

    ASSERT(req != NULL, "prepare: json produced");
    ASSERT(strstr(req, "\"model_id\":\"test-model\"") != NULL, "prepare: model_id");
    ASSERT(strstr(req, "\"mode\":\"PrivateProven\"") != NULL, "prepare: mode");
    ASSERT(strstr(req, "\"max_tokens\":50") != NULL, "prepare: max_tokens");
    ASSERT(strstr(req, "\"temperature\":700") != NULL, "prepare: temperature");
    ASSERT(strstr(req, "\"seed\":42") != NULL, "prepare: seed");
    ASSERT(strstr(req, "\"tokens\":[100,200,300]") != NULL, "prepare: encrypted tokens");

    free(req);
    pc_client_free(c);
}

static void test_process_response(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_TRANSPARENT);
    uint32_t tokens[] = {100, 200, 300, 400, 500};
    char *resp_json = mock_server_response(tokens, 5);

    pc_verified_response_t *vr = pc_client_process_response_json(c, resp_json);
    ASSERT(vr != NULL, "process: response parsed");
    ASSERT_EQ(vr->count, 5, "process: token count = 5");
    ASSERT_EQ(vr->token_ids[0], 100, "process: token[0] = 100");
    ASSERT_EQ(vr->token_ids[4], 500, "process: token[4] = 500");
    ASSERT(pc_verified_response_is_verified(vr), "process: response verified");

    pc_verified_response_free(vr);
    free(resp_json);
    pc_client_free(c);
}

static void test_full_protocol_flow(void) {
    int modes[] = {
        PV_MODE_TRANSPARENT,
        PV_MODE_PRIVATE_PROVEN,
        PV_MODE_PRIVATE,
        PV_MODE_ENCRYPTED,
    };
    const char *mode_names[] = {"Transparent", "PrivateProven", "Private", "Encrypted"};

    for (int m = 0; m < 4; m++) {
        pc_client_t *c = pc_client_new("Qwen/Qwen3-0.6B", modes[m]);

        uint32_t input[] = {1, 2, 3, 4, 5};
        char *req = pc_client_prepare_request_json(c, input, 5, 50, 700, 42);
        ASSERT(req != NULL, "flow: request prepared");

        /* Server side: just echo the tokens back with generated ones appended */
        uint32_t output[] = {1, 2, 3, 4, 5, 10, 20, 30, 40, 50};
        char *resp_json = mock_server_response(output, 10);

        pc_verified_response_t *vr = pc_client_process_response_json(c, resp_json);
        char msg[128];
        snprintf(msg, sizeof(msg), "flow[%s]: token count = 10", mode_names[m]);
        ASSERT(vr != NULL && vr->count == 10, msg);

        snprintf(msg, sizeof(msg), "flow[%s]: verified", mode_names[m]);
        ASSERT(pc_verified_response_is_verified(vr), msg);

        pc_verified_response_free(vr);
        free(resp_json);
        free(req);
        pc_client_free(c);
    }
}

static void test_disclosure_from_response(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_PRIVATE_PROVEN);
    uint32_t tokens[] = {100, 200, 300, 400, 500, 600, 700, 800};
    char *resp_json = mock_server_response(tokens, 8);

    pc_verified_response_t *vr = pc_client_process_response_json(c, resp_json);
    ASSERT(vr != NULL, "disclosure: response parsed");

    /* Pharmacist sees tokens 1, 2, 3 */
    size_t pharm_idx[] = {1, 2, 3};
    pv_disclosure_t *pharm = pc_verified_response_disclose(vr, pharm_idx, 3);
    ASSERT(pharm != NULL, "disclosure: pharmacist created");
    ASSERT(pv_disclosure_verify(pharm), "disclosure: pharmacist verifies");
    ASSERT_EQ(pharm->proof_count, 3, "disclosure: pharmacist proof_count = 3");

    /* Insurer sees token 6 */
    size_t ins_idx[] = {6};
    pv_disclosure_t *ins = pc_verified_response_disclose(vr, ins_idx, 1);
    ASSERT(ins != NULL, "disclosure: insurer created");
    ASSERT(pv_disclosure_verify(ins), "disclosure: insurer verifies");
    ASSERT_EQ(ins->proof_count, 1, "disclosure: insurer proof_count = 1");

    /* Same output root */
    ASSERT(pv_hash_eq(pharm->output_root, ins->output_root), "disclosure: same output root");

    pv_disclosure_free(pharm);
    pv_disclosure_free(ins);
    pc_verified_response_free(vr);
    free(resp_json);
    pc_client_free(c);
}

static void test_empty_response(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_TRANSPARENT);
    char *resp_json = mock_server_response(NULL, 0);

    pc_verified_response_t *vr = pc_client_process_response_json(c, resp_json);
    ASSERT(vr != NULL, "empty: response parsed");
    ASSERT_EQ(vr->count, 0, "empty: token count = 0");

    pc_verified_response_free(vr);
    free(resp_json);
    pc_client_free(c);
}

static void test_large_input(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_ENCRYPTED);
    size_t n = 10000;
    uint32_t *tokens = malloc(n * sizeof(uint32_t));
    for (size_t i = 0; i < n; i++) tokens[i] = (uint32_t)i;

    char *req = pc_client_prepare_request_json(c, tokens, n, 100, 700, 42);
    ASSERT(req != NULL, "large: request prepared");
    ASSERT(strlen(req) > 10000, "large: request has substantial size");

    free(req);
    free(tokens);
    pc_client_free(c);
}

static void test_mode_propagation(void) {
    int modes[] = {
        PV_MODE_TRANSPARENT, PV_MODE_PRIVATE_PROVEN,
        PV_MODE_PRIVATE, PV_MODE_ENCRYPTED
    };
    const char *expected[] = {"Transparent", "PrivateProven", "Private", "Encrypted"};

    for (int m = 0; m < 4; m++) {
        pc_client_t *c = pc_client_new("model", modes[m]);
        uint32_t t[] = {1};
        char *req = pc_client_prepare_request_json(c, t, 1, 10, 700, 42);

        char search[64];
        snprintf(search, sizeof(search), "\"mode\":\"%s\"", expected[m]);
        char msg[128];
        snprintf(msg, sizeof(msg), "mode[%s]: propagated in request", expected[m]);
        ASSERT(strstr(req, search) != NULL, msg);

        free(req);
        pc_client_free(c);
    }
}

static void test_invalid_response(void) {
    pc_client_t *c = pc_client_new("test-model", PV_MODE_TRANSPARENT);

    pc_verified_response_t *vr = pc_client_process_response_json(c, "not json");
    ASSERT(vr == NULL, "invalid: garbage returns NULL");

    vr = pc_client_process_response_json(c, "{\"encrypted_output\":{\"tokens\":[1]}}");
    ASSERT(vr == NULL, "invalid: missing proof returns NULL");

    pc_client_free(c);
}

/* ---------- Main ---------- */

int main(void) {
    test_client_creation();
    test_prepare_request();
    test_process_response();
    test_full_protocol_flow();
    test_disclosure_from_response();
    test_empty_response();
    test_large_input();
    test_mode_propagation();
    test_invalid_response();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
