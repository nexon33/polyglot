package verified

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type HexHash Hash

func (h HexHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

func (h *HexHash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return nil
}

func hashToHex(h Hash) string {
	return hex.EncodeToString(h[:])
}

type ProofJSON struct {
	Backend            string  `json:"backend"`
	ChainTip           string  `json:"chain_tip"`
	MerkleRoot         string  `json:"merkle_root"`
	StepCount          uint64  `json:"step_count"`
	CodeHash           string  `json:"code_hash"`
	PrivacyMode        string  `json:"privacy_mode"`
	BlindingCommitment *string `json:"blinding_commitment,omitempty"`
	QuantumResistant   bool    `json:"quantum_resistant"`
	Verified           bool    `json:"verified"`
}

func (p *VerifiedProof) ToJSON() *ProofJSON {
	pj := &ProofJSON{
		Backend:          BackendHashIvc.String(),
		ChainTip:         hex.EncodeToString(p.ChainTip[:]),
		MerkleRoot:       hex.EncodeToString(p.MerkleRoot[:]),
		StepCount:        p.StepCount,
		CodeHash:         hashToHex(p.PublicCodeHash()),
		PrivacyMode:      p.Privacy.String(),
		QuantumResistant: true,
		Verified:         p.Verify(),
	}

	if p.BlindingCommitment != nil {
		s := hex.EncodeToString(p.BlindingCommitment[:])
		pj.BlindingCommitment = &s
	}

	return pj
}

type VerificationResponse struct {
	Proof     *ProofJSON `json:"proof"`
	InputHash *string    `json:"input_hash,omitempty"`
	OutputHash *string   `json:"output_hash,omitempty"`
	ModelID   string     `json:"model_id"`
}

func NewVerificationResponse(proof *VerifiedProof, inputHash, outputHash Hash, modelID string) *VerificationResponse {
	vr := &VerificationResponse{
		Proof:   proof.ToJSON(),
		ModelID: modelID,
	}

	if !proof.Privacy.IsPrivate() || proof.Privacy == PrivateInputs {
		oh := hex.EncodeToString(outputHash[:])
		vr.OutputHash = &oh
	}
	if !proof.Privacy.IsPrivate() {
		ih := hex.EncodeToString(inputHash[:])
		vr.InputHash = &ih
	}

	return vr
}
