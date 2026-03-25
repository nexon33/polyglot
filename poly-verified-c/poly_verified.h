#ifndef POLY_VERIFIED_H
#define POLY_VERIFIED_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t pv_hash_t[32];

#define PV_TRANSPARENT    0
#define PV_PRIVATE        1
#define PV_PRIVATE_INPUTS 2

#define PV_MODE_TRANSPARENT    0
#define PV_MODE_PRIVATE_PROVEN 1
#define PV_MODE_PRIVATE        2
#define PV_MODE_ENCRYPTED      3

typedef struct { pv_hash_t hash; int is_left; } pv_proof_node_t;
typedef struct { pv_hash_t state_before, state_after, step_inputs; } pv_step_witness_t;

typedef struct {
    pv_hash_t chain_tip, merkle_root, code_hash;
    uint64_t step_count;
    uint8_t privacy;
    pv_hash_t blinding_commitment;
    int has_blinding;
} pv_proof_t;

typedef struct {
    pv_hash_t leaf, root, code_hash;
    uint64_t leaf_index;
    pv_proof_node_t *siblings;
    size_t sibling_count;
} pv_merkle_proof_t;

typedef struct {
    int revealed;
    size_t index;
    uint32_t token_id;
    pv_hash_t leaf_hash;
} pv_disclosed_token_t;

typedef struct {
    pv_disclosed_token_t *tokens;
    size_t token_count;
    pv_merkle_proof_t *proofs;
    size_t proof_count;
    pv_hash_t output_root;
    size_t total_tokens;
    pv_proof_t execution_proof;
} pv_disclosure_t;

typedef struct pv_ivc_s pv_ivc_t;

/* Hash functions (SHA-256 via OpenSSL EVP) */
void pv_hash_data(const uint8_t *in, size_t len, pv_hash_t out);
void pv_hash_leaf(const uint8_t *in, size_t len, pv_hash_t out);
void pv_hash_combine(const pv_hash_t left, const pv_hash_t right, pv_hash_t out);
void pv_hash_transition(const pv_hash_t prev, const pv_hash_t input, const pv_hash_t claimed, pv_hash_t out);
void pv_hash_chain_step(const pv_hash_t tip, const pv_hash_t state, pv_hash_t out);
void pv_hash_blinding(const uint8_t *in, size_t len, pv_hash_t out);
int  pv_hash_eq(const pv_hash_t a, const pv_hash_t b);

/* Merkle */
pv_merkle_proof_t *pv_merkle_build_and_prove(const pv_hash_t *leaves, size_t n,
                                              uint64_t leaf_index, const pv_hash_t code_hash);
int pv_merkle_verify(const pv_merkle_proof_t *proof);
void pv_merkle_proof_free(pv_merkle_proof_t *proof);

/* IVC */
pv_ivc_t *pv_ivc_new(const pv_hash_t code_hash, uint8_t privacy);
int pv_ivc_fold_step(pv_ivc_t *ivc, const pv_step_witness_t *witness);
pv_proof_t *pv_ivc_finalize(pv_ivc_t *ivc); /* frees the ivc */
void pv_proof_free(pv_proof_t *proof);

/* Disclosure */
pv_disclosure_t *pv_disclosure_create(const uint32_t *tokens, size_t n,
                                       const pv_proof_t *proof,
                                       const size_t *indices, size_t num_indices);
int pv_disclosure_verify(const pv_disclosure_t *d);
void pv_disclosure_free(pv_disclosure_t *d);

/* JSON */
char *pv_proof_to_json(const pv_proof_t *proof);
pv_proof_t *pv_proof_from_wire_json(const char *json_str);
char *pv_proof_to_wire_json(const pv_proof_t *proof);

extern const pv_hash_t PV_ZERO_HASH;

#endif /* POLY_VERIFIED_H */
