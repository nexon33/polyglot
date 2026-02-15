package verified

import (
	"encoding/binary"
	"errors"
)

// HashIvcAccumulator is the running accumulator for Hash-IVC.
type HashIvcAccumulator struct {
	chain        *HashChainState
	checkpoints  []Hash
	codeHash     Hash
	privacyMode  PrivacyMode
	blindingHash Hash
}

// NewHashIvc creates a new Hash-IVC accumulator.
func NewHashIvc(codeHash Hash, privacy PrivacyMode) *HashIvcAccumulator {
	return &HashIvcAccumulator{
		chain:        NewHashChain(),
		checkpoints:  nil,
		codeHash:     codeHash,
		privacyMode:  privacy,
		blindingHash: ZeroHash,
	}
}

// FoldStep folds a computation step into the accumulator.
func (a *HashIvcAccumulator) FoldStep(witness StepWitness) error {
	transition := HashTransition(witness.StateBefore, witness.StepInputs, witness.StateAfter)
	a.chain.Append(transition)
	a.checkpoints = append(a.checkpoints, transition)

	// When privacy is enabled, generate and accumulate a blinding factor.
	if a.privacyMode.IsPrivate() {
		var stepCounter [8]byte
		binary.LittleEndian.PutUint64(stepCounter[:], a.chain.Length)

		blindingInput := make([]byte, 32+8)
		copy(blindingInput[:32], transition[:])
		copy(blindingInput[32:], stepCounter[:])

		blinding := HashBlinding(blindingInput)
		a.blindingHash = HashCombine(a.blindingHash, blinding)
	}

	return nil
}

// Finalize produces the final VerifiedProof from the accumulated state.
func (a *HashIvcAccumulator) Finalize() (*VerifiedProof, error) {
	if len(a.checkpoints) == 0 {
		return nil, errors.New("empty commitment: no steps folded")
	}

	tree := BuildMerkleTree(a.checkpoints)

	var blindingCommitment *Hash
	if a.privacyMode.IsPrivate() {
		bc := a.blindingHash
		blindingCommitment = &bc
	}

	return &VerifiedProof{
		ChainTip:           a.chain.Tip,
		MerkleRoot:         tree.Root,
		StepCount:          a.chain.Length,
		CodeHash:           a.codeHash,
		Privacy:            a.privacyMode,
		BlindingCommitment: blindingCommitment,
	}, nil
}
