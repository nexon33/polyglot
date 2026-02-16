package verified

type Hash = [32]byte

var ZeroHash Hash

func HashEq(a, b Hash) bool {
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

type PrivacyMode uint8

const (
	Transparent   PrivacyMode = 0x00
	Private       PrivacyMode = 0x01
	PrivateInputs PrivacyMode = 0x02
)

func (p PrivacyMode) IsPrivate() bool {
	return p != Transparent
}

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

type BackendID uint8

const (
	BackendMock     BackendID = 0x00
	BackendHashIvc  BackendID = 0x01
	BackendNova     BackendID = 0x02
	BackendHyperNova BackendID = 0x03
)

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

type StepWitness struct {
	StateBefore Hash
	StateAfter  Hash
	StepInputs  Hash
}

type VerifiedProof struct {
	ChainTip           Hash        `json:"chain_tip"`
	MerkleRoot         Hash        `json:"merkle_root"`
	StepCount          uint64      `json:"step_count"`
	CodeHash           Hash        `json:"code_hash"`
	Privacy            PrivacyMode `json:"privacy_mode"`
	BlindingCommitment *Hash       `json:"blinding_commitment,omitempty"`
}

func (p *VerifiedProof) BackendID() BackendID {
	return BackendHashIvc
}

func (p *VerifiedProof) PublicCodeHash() Hash {
	if p.Privacy == Private {
		return ZeroHash
	}
	return p.CodeHash
}

func (p *VerifiedProof) Verify() bool {
	if p.StepCount == 0 {
		return false
	}
	if p.Privacy.IsPrivate() && p.BlindingCommitment == nil {
		return false
	}
	return true
}

func (p *VerifiedProof) IsQuantumResistant() bool {
	return true
}

type ProofNode struct {
	Hash   Hash `json:"hash"`
	IsLeft bool `json:"is_left"`
}

type MerkleProof struct {
	Leaf      Hash        `json:"leaf"`
	LeafIndex uint64      `json:"leaf_index"`
	Siblings  []ProofNode `json:"siblings"`
	Root      Hash        `json:"root"`
	CodeHash  Hash        `json:"code_hash"`
}
