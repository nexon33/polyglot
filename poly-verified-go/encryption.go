package verified

import (
	"encoding/json"
	"fmt"
)

// Mode represents the polyglot encryption/privacy protocol mode.
// Matches Rust serde serialization: PascalCase strings.
type Mode int

const (
	ModeTransparent  Mode = iota // No encryption, full visibility
	ModePrivateProven            // Proven private — verifier sees proof but not inputs
	ModePrivate                  // Full privacy — verifier learns nothing except validity
	ModeEncrypted                // Homomorphic encryption — ciphertext pass-through
)

var modeNames = [...]string{"Transparent", "PrivateProven", "Private", "Encrypted"}

// String returns the PascalCase name matching Rust serde.
func (m Mode) String() string {
	if int(m) < len(modeNames) {
		return modeNames[m]
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// MarshalJSON encodes as a PascalCase JSON string.
func (m Mode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// UnmarshalJSON decodes from a PascalCase JSON string.
func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "Transparent":
		*m = ModeTransparent
	case "PrivateProven":
		*m = ModePrivateProven
	case "Private":
		*m = ModePrivate
	case "Encrypted":
		*m = ModeEncrypted
	default:
		return fmt.Errorf("unknown Mode %q", s)
	}
	return nil
}

// ToPrivacyMode maps a polyglot Mode to the existing PrivacyMode type.
func (m Mode) ToPrivacyMode() PrivacyMode {
	switch m {
	case ModeTransparent:
		return Transparent
	case ModePrivateProven:
		return PrivateInputs
	case ModePrivate, ModeEncrypted:
		return Private
	default:
		return Transparent
	}
}

// RequiresEncryption returns true only for ModeEncrypted.
func (m Mode) RequiresEncryption() bool {
	return m == ModeEncrypted
}

// InferRequest represents a poly-client inference request (client -> server).
// EncryptedInput carries opaque ciphertext — the proxy never inspects it.
type InferRequest struct {
	ModelID        string          `json:"model_id"`
	Mode           Mode            `json:"mode"`
	EncryptedInput json.RawMessage `json:"encrypted_input"`
	MaxTokens      uint32          `json:"max_tokens"`
	Temperature    uint32          `json:"temperature"`
	Seed           uint64          `json:"seed"`
}

// InferResponse represents a poly-inference server response (server -> client).
// EncryptedOutput and Proof carry opaque payloads — the proxy parses only
// the proof for Ed25519 signing, then passes everything through.
type InferResponse struct {
	EncryptedOutput json.RawMessage `json:"encrypted_output"`
	Proof           json.RawMessage `json:"proof"`
	ModelID         string          `json:"model_id"`
}

// ---------------------------------------------------------------------------
// Wire proof bridge: Rust serde <-> Go VerifiedProof
// ---------------------------------------------------------------------------

// ByteArray32 marshals a [32]byte as a JSON integer array [0,1,2,...,31],
// matching Rust's serde serialization of [u8; 32].
type ByteArray32 [32]byte

func (b ByteArray32) MarshalJSON() ([]byte, error) {
	ints := make([]int, 32)
	for i, v := range b {
		ints[i] = int(v)
	}
	return json.Marshal(ints)
}

func (b *ByteArray32) UnmarshalJSON(data []byte) error {
	var ints []int
	if err := json.Unmarshal(data, &ints); err != nil {
		return err
	}
	if len(ints) != 32 {
		return fmt.Errorf("expected 32 ints, got %d", len(ints))
	}
	for i, v := range ints {
		if v < 0 || v > 255 {
			return fmt.Errorf("byte %d out of range: %d", i, v)
		}
		b[i] = byte(v)
	}
	return nil
}

// wirePrivacyMode bridges PrivacyMode <-> PascalCase string for Rust serde.
type wirePrivacyMode PrivacyMode

func (w wirePrivacyMode) MarshalJSON() ([]byte, error) {
	switch PrivacyMode(w) {
	case Transparent:
		return json.Marshal("Transparent")
	case Private:
		return json.Marshal("Private")
	case PrivateInputs:
		return json.Marshal("PrivateInputs")
	default:
		return json.Marshal("Transparent")
	}
}

func (w *wirePrivacyMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "Transparent":
		*w = wirePrivacyMode(Transparent)
	case "Private":
		*w = wirePrivacyMode(Private)
	case "PrivateInputs":
		*w = wirePrivacyMode(PrivateInputs)
	default:
		return fmt.Errorf("unknown wire privacy mode %q", s)
	}
	return nil
}

// wireProofInner matches the inner struct of Rust's HashIvc proof serialization.
type wireProofInner struct {
	ChainTip           ByteArray32    `json:"chain_tip"`
	MerkleRoot         ByteArray32    `json:"merkle_root"`
	StepCount          uint64         `json:"step_count"`
	CodeHash           ByteArray32    `json:"code_hash"`
	PrivacyMode        wirePrivacyMode `json:"privacy_mode"`
	BlindingCommitment *ByteArray32   `json:"blinding_commitment,omitempty"`
}

// ParseWireProof extracts a VerifiedProof from Rust serde JSON.
// Expects envelope: {"HashIvc": { ... inner fields ... }}
func ParseWireProof(raw json.RawMessage) (*VerifiedProof, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse wire proof envelope: %w", err)
	}

	inner, ok := envelope["HashIvc"]
	if !ok {
		return nil, fmt.Errorf("wire proof missing HashIvc variant")
	}

	var w wireProofInner
	if err := json.Unmarshal(inner, &w); err != nil {
		return nil, fmt.Errorf("parse wire proof inner: %w", err)
	}

	proof := &VerifiedProof{
		ChainTip:   Hash(w.ChainTip),
		MerkleRoot: Hash(w.MerkleRoot),
		StepCount:  w.StepCount,
		CodeHash:   Hash(w.CodeHash),
		Privacy:    PrivacyMode(w.PrivacyMode),
	}
	if w.BlindingCommitment != nil {
		h := Hash(*w.BlindingCommitment)
		proof.BlindingCommitment = &h
	}

	return proof, nil
}

// MarshalWireProof converts a VerifiedProof back to Rust serde JSON.
// Produces: {"HashIvc": { ... inner fields ... }}
func MarshalWireProof(p *VerifiedProof) (json.RawMessage, error) {
	w := wireProofInner{
		ChainTip:    ByteArray32(p.ChainTip),
		MerkleRoot:  ByteArray32(p.MerkleRoot),
		StepCount:   p.StepCount,
		CodeHash:    ByteArray32(p.CodeHash),
		PrivacyMode: wirePrivacyMode(p.Privacy),
	}
	if p.BlindingCommitment != nil {
		bc := ByteArray32(*p.BlindingCommitment)
		w.BlindingCommitment = &bc
	}

	envelope := map[string]interface{}{"HashIvc": w}
	return json.Marshal(envelope)
}

// ---------------------------------------------------------------------------
// Encryption backend interface + mock implementation
// ---------------------------------------------------------------------------

// EncryptionBackend defines the interface for homomorphic encryption schemes.
type EncryptionBackend interface {
	Keygen() (publicKey, secretKey []byte)
	Encrypt(tokenIDs []uint32, pk []byte) []byte
	Decrypt(ciphertext []byte, sk []byte) []uint32
}

// MockEncryption provides a trivial encryption backend for testing.
// Produces deterministic keys and wraps tokens in plain JSON.
type MockEncryption struct{}

// MockCiphertext carries plaintext tokens — testing only.
type MockCiphertext struct {
	Tokens []uint32 `json:"tokens"`
}

// Keygen returns deterministic 32-byte keys: public=0xAA..., secret=0xBB...
func (MockEncryption) Keygen() (publicKey, secretKey []byte) {
	pk := make([]byte, 32)
	sk := make([]byte, 32)
	for i := range pk {
		pk[i] = 0xAA
		sk[i] = 0xBB
	}
	return pk, sk
}

// Encrypt wraps token IDs in MockCiphertext JSON. The pk argument goes unused
// in this mock — real backends would encrypt under the public key.
func (MockEncryption) Encrypt(tokenIDs []uint32, pk []byte) []byte {
	ct := MockCiphertext{Tokens: tokenIDs}
	data, _ := json.Marshal(ct)
	return data
}

// Decrypt unmarshals MockCiphertext JSON and returns the token IDs.
func (MockEncryption) Decrypt(ciphertext []byte, sk []byte) []uint32 {
	var ct MockCiphertext
	if err := json.Unmarshal(ciphertext, &ct); err != nil {
		return nil
	}
	return ct.Tokens
}
