package verified

// Hash is a 32-byte SHA-256 digest.
type Hash = [32]byte

// ZeroHash is 32 bytes of 0x00.
var ZeroHash Hash

// HashEq performs constant-time comparison of two hashes.
func HashEq(a, b Hash) bool {
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// PrivacyMode controls what information is revealed to the verifier.
type PrivacyMode uint8

const (
	// Transparent: verifier sees input hash, output hash, code hash.
	Transparent PrivacyMode = 0x00
	// Private: full ZK — verifier learns nothing except proof validity.
	Private PrivacyMode = 0x01
	// PrivateInputs: selective — verifier sees output but not inputs.
	PrivateInputs PrivacyMode = 0x02
)

// IsPrivate returns true if this mode hides any information from the verifier.
func (p PrivacyMode) IsPrivate() bool {
	return p != Transparent
}

// String returns the string name of the privacy mode.
func (p PrivacyMode) String() string {
	switch p {
	case Transparent:
		return "transparent"
	case Private:
		return "private"
	case PrivateInputs:
		return "private_inputs"
	default:
		return "unknown"
	}
}

// BackendID identifies which IVC backend produced a proof.
type BackendID uint8

const (
	BackendMock     BackendID = 0x00
	BackendHashIvc  BackendID = 0x01
	BackendNova     BackendID = 0x02
	BackendHyperNova BackendID = 0x03
)

// String returns the string name of the backend.
func (b BackendID) String() string {
	switch b {
	case BackendMock:
		return "Mock"
	case BackendHashIvc:
		return "HashIvc"
	case BackendNova:
		return "Nova"
	case BackendHyperNova:
		return "HyperNova"
	default:
		return "unknown"
	}
}

// StepWitness is witness data for a single computation step.
type StepWitness struct {
	StateBefore Hash
	StateAfter  Hash
	StepInputs  Hash
}

// VerifiedProof is a finalized proof of execution.
type VerifiedProof struct {
	ChainTip           Hash        `json:"chain_tip"`
	MerkleRoot         Hash        `json:"merkle_root"`
	StepCount          uint64      `json:"step_count"`
	CodeHash           Hash        `json:"code_hash"`
	Privacy            PrivacyMode `json:"privacy_mode"`
	BlindingCommitment *Hash       `json:"blinding_commitment,omitempty"`
}

// BackendID returns the backend that produced this proof.
func (p *VerifiedProof) BackendID() BackendID {
	return BackendHashIvc
}

// PublicCodeHash returns the code hash, respecting privacy mode.
// In Private mode, returns ZeroHash to hide code identity.
func (p *VerifiedProof) PublicCodeHash() Hash {
	if p.Privacy == Private {
		return ZeroHash
	}
	return p.CodeHash
}

// Verify performs structural validation of the proof.
func (p *VerifiedProof) Verify() bool {
	if p.StepCount == 0 {
		return false
	}
	if p.Privacy.IsPrivate() && p.BlindingCommitment == nil {
		return false
	}
	return true
}

// IsQuantumResistant returns true (HashIvc uses only SHA-256).
func (p *VerifiedProof) IsQuantumResistant() bool {
	return true
}

// ProofNode is a sibling in a Merkle proof path.
type ProofNode struct {
	Hash   Hash `json:"hash"`
	IsLeft bool `json:"is_left"`
}

// MerkleProof is an inclusion proof for a leaf in a Merkle tree.
type MerkleProof struct {
	Leaf      Hash        `json:"leaf"`
	LeafIndex uint64      `json:"leaf_index"`
	Siblings  []ProofNode `json:"siblings"`
	Root      Hash        `json:"root"`
	CodeHash  Hash        `json:"code_hash"`
}
