package polyclient

import (
	"encoding/json"
	"fmt"

	verified "poly-verified-go"
)

// PolyClient provides the thin client SDK for private verified inference.
type PolyClient struct {
	modelID    string
	mode       verified.Mode
	encryption verified.EncryptionBackend
	publicKey  []byte
	secretKey  []byte
}

// New creates a thin client targeting the given model and mode.
func New(modelID string, mode verified.Mode, enc verified.EncryptionBackend) *PolyClient {
	pk, sk := enc.Keygen()
	return &PolyClient{
		modelID:    modelID,
		mode:       mode,
		encryption: enc,
		publicKey:  pk,
		secretKey:  sk,
	}
}

// ModelID returns the target model identifier.
func (c *PolyClient) ModelID() string { return c.modelID }

// Mode returns the computation mode.
func (c *PolyClient) Mode() verified.Mode { return c.mode }

// PrepareRequest encrypts input tokens and builds an InferRequest.
func (c *PolyClient) PrepareRequest(tokenIDs []uint32, maxTokens, temperature uint32, seed uint64) *verified.InferRequest {
	ct := c.encryption.Encrypt(tokenIDs, c.publicKey)
	encryptedInput, _ := json.Marshal(json.RawMessage(ct))
	return &verified.InferRequest{
		ModelID:        c.modelID,
		Mode:           c.mode,
		EncryptedInput: encryptedInput,
		MaxTokens:      maxTokens,
		Temperature:    temperature,
		Seed:           seed,
	}
}

// VerifiedResponse wraps decrypted output tokens with their execution proof.
type VerifiedResponse struct {
	TokenIDs []uint32
	verified verified.Verified[[]uint32]
}

// Proof returns the execution proof.
func (r *VerifiedResponse) Proof() *verified.VerifiedProof { return r.verified.Proof() }

// IsVerified performs a structural validity check on the proof.
func (r *VerifiedResponse) IsVerified() bool { return r.verified.IsVerified() }

// Disclose creates a selective disclosure revealing only specified token positions.
func (r *VerifiedResponse) Disclose(indices []int) (*verified.Disclosure, error) {
	return verified.Disclose(&r.verified, indices)
}

// DiscloseRange creates a selective disclosure for a contiguous range [start, end).
func (r *VerifiedResponse) DiscloseRange(start, end int) (*verified.Disclosure, error) {
	return verified.DiscloseRange(&r.verified, start, end)
}

// ProcessResponse decrypts server response and wraps as VerifiedResponse.
func (c *PolyClient) ProcessResponse(resp *verified.InferResponse) (*VerifiedResponse, error) {
	var rawCT json.RawMessage
	if err := json.Unmarshal(resp.EncryptedOutput, &rawCT); err != nil {
		return nil, fmt.Errorf("parse encrypted output: %w", err)
	}
	tokenIDs := c.encryption.Decrypt(rawCT, c.secretKey)

	proof, err := verified.ParseWireProof(resp.Proof)
	if err != nil {
		return nil, fmt.Errorf("parse wire proof: %w", err)
	}

	v := verified.NewVerified(tokenIDs, *proof)
	return &VerifiedResponse{
		TokenIDs: tokenIDs,
		verified: v,
	}, nil
}
