package verified

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

// ServerIdentity holds the Ed25519 keypair used to sign proofs.
type ServerIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// LoadOrGenerateIdentity loads an Ed25519 private key from path, or generates
// one and saves it if the file doesn't exist.
func LoadOrGenerateIdentity(path string) (*ServerIdentity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		// Load existing key (raw 64-byte seed+key).
		if len(data) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid key file: expected 64 bytes")
		}
		priv := ed25519.PrivateKey(data)
		pub := priv.Public().(ed25519.PublicKey)
		return &ServerIdentity{PrivateKey: priv, PublicKey: pub}, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate new keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Save private key with restrictive permissions.
	if err := os.WriteFile(path, priv, 0600); err != nil {
		return nil, err
	}

	return &ServerIdentity{PrivateKey: priv, PublicKey: pub}, nil
}

// SignProof signs the deterministic content of a VerifiedProof.
// The signed message is: chain_tip(32) || merkle_root(32) || step_count(8) || code_hash(32) || privacy(1)
func (id *ServerIdentity) SignProof(proof *VerifiedProof) []byte {
	msg := proofSigningMessage(proof)
	return ed25519.Sign(id.PrivateKey, msg)
}

// VerifyProofSignature checks an Ed25519 signature against a proof.
func VerifyProofSignature(publicKey ed25519.PublicKey, proof *VerifiedProof, sig []byte) bool {
	msg := proofSigningMessage(proof)
	return ed25519.Verify(publicKey, msg, sig)
}

// PublicKeyHex returns the hex-encoded public key.
func (id *ServerIdentity) PublicKeyHex() string {
	return hex.EncodeToString(id.PublicKey)
}

// proofSigningMessage builds the canonical byte sequence for signing.
func proofSigningMessage(proof *VerifiedProof) []byte {
	msg := make([]byte, 0, 105) // 32+32+8+32+1
	msg = append(msg, proof.ChainTip[:]...)
	msg = append(msg, proof.MerkleRoot[:]...)
	var stepBytes [8]byte
	binary.LittleEndian.PutUint64(stepBytes[:], proof.StepCount)
	msg = append(msg, stepBytes[:]...)
	msg = append(msg, proof.CodeHash[:]...)
	msg = append(msg, byte(proof.Privacy))
	return msg
}

// SignedProofJSON extends ProofJSON with signing fields.
type SignedProofJSON struct {
	ProofJSON
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

// ToSignedJSON converts a proof to its signed JSON representation.
func (proof *VerifiedProof) ToSignedJSON(id *ServerIdentity) *SignedProofJSON {
	pj := proof.ToJSON()
	sig := id.SignProof(proof)
	return &SignedProofJSON{
		ProofJSON: *pj,
		Signature: hex.EncodeToString(sig),
		PublicKey: id.PublicKeyHex(),
	}
}

// SignedVerificationResponse extends VerificationResponse with signing.
type SignedVerificationResponse struct {
	Proof      *SignedProofJSON `json:"proof"`
	InputHash  *string         `json:"input_hash,omitempty"`
	OutputHash *string         `json:"output_hash,omitempty"`
	ModelID    string          `json:"model_id"`
	SessionID  string          `json:"session_id,omitempty"`
	TurnNumber uint64          `json:"turn_number,omitempty"`
}

// NewSignedVerificationResponse builds the signed verification response.
func NewSignedVerificationResponse(proof *VerifiedProof, inputHash, outputHash Hash, modelID string, id *ServerIdentity) *SignedVerificationResponse {
	svr := &SignedVerificationResponse{
		Proof:   proof.ToSignedJSON(id),
		ModelID: modelID,
	}

	// Only include hashes per privacy mode.
	if !proof.Privacy.IsPrivate() || proof.Privacy == PrivateInputs {
		oh := hex.EncodeToString(outputHash[:])
		svr.OutputHash = &oh
	}
	if !proof.Privacy.IsPrivate() {
		ih := hex.EncodeToString(inputHash[:])
		svr.InputHash = &ih
	}

	return svr
}

// MerkleProofJSON is the JSON representation of a Merkle inclusion proof.
type MerkleProofJSON struct {
	Leaf      string          `json:"leaf"`
	LeafIndex uint64          `json:"leaf_index"`
	Siblings  []ProofNodeJSON `json:"siblings"`
	Root      string          `json:"root"`
	CodeHash  string          `json:"code_hash"`
	Valid     bool            `json:"valid"`
}

// ProofNodeJSON is a single node in a Merkle proof path.
type ProofNodeJSON struct {
	Hash   string `json:"hash"`
	IsLeft bool   `json:"is_left"`
}

// MerkleProofToJSON converts a MerkleProof to JSON representation.
func MerkleProofToJSON(mp *MerkleProof) *MerkleProofJSON {
	siblings := make([]ProofNodeJSON, len(mp.Siblings))
	for i, s := range mp.Siblings {
		siblings[i] = ProofNodeJSON{
			Hash:   hex.EncodeToString(s.Hash[:]),
			IsLeft: s.IsLeft,
		}
	}
	return &MerkleProofJSON{
		Leaf:      hex.EncodeToString(mp.Leaf[:]),
		LeafIndex: mp.LeafIndex,
		Siblings:  siblings,
		Root:      hex.EncodeToString(mp.Root[:]),
		CodeHash:  hex.EncodeToString(mp.CodeHash[:]),
		Valid:     VerifyMerkleProof(mp),
	}
}

// MarshalJSON on SignedVerificationResponse for clean output.
func (svr *SignedVerificationResponse) MarshalJSON() ([]byte, error) {
	type Alias SignedVerificationResponse
	return json.Marshal((*Alias)(svr))
}
