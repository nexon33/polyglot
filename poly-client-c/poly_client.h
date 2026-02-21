#ifndef POLY_CLIENT_H
#define POLY_CLIENT_H

#include "../poly-verified-c/poly_verified.h"

typedef struct pc_client_s pc_client_t;

typedef struct {
    uint32_t *token_ids;
    size_t    count;
    pv_proof_t proof;
    int       verified;
} pc_verified_response_t;

/* Client lifecycle */
pc_client_t *pc_client_new(const char *model_id, int mode);
void         pc_client_free(pc_client_t *client);

/* Accessors */
const char *pc_client_model_id(const pc_client_t *client);
int         pc_client_mode(const pc_client_t *client);

/* Protocol */
char *pc_client_prepare_request_json(pc_client_t *client,
                                      const uint32_t *tokens, size_t n,
                                      uint32_t max_tokens, uint32_t temperature,
                                      uint64_t seed);

pc_verified_response_t *pc_client_process_response_json(pc_client_t *client,
                                                         const char *json);

/* Verified response */
int pc_verified_response_is_verified(const pc_verified_response_t *resp);

pv_disclosure_t *pc_verified_response_disclose(const pc_verified_response_t *resp,
                                                const size_t *indices, size_t n);

void pc_verified_response_free(pc_verified_response_t *resp);

#endif /* POLY_CLIENT_H */
