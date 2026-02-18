package verified

import "encoding/binary"

// DisclosedToken represents a single token position in a disclosure.
type DisclosedToken struct {
	Index    int
	Revealed bool
	TokenID  uint32 // valid when Revealed == true
	LeafHash Hash   // valid when Revealed == false
}

// Disclosure holds a selective disclosure of verified output tokens.
// Different audiences receive different Disclosure instances from the same proof.
type Disclosure struct {
	Tokens         []DisclosedToken
	Proofs         []MerkleProof
	OutputRoot     Hash
	TotalTokens    int
	ExecutionProof VerifiedProof
}

// tokenLeaf hashes a token ID into a Merkle leaf.
func tokenLeaf(tokenID uint32) Hash {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], tokenID)
	return HashLeaf(buf[:])
}

// CreateDisclosure builds a selective disclosure from a verified token sequence.
// indices specifies which token positions to reveal; the rest get redacted.
func CreateDisclosure(v *Verified[[]uint32], indices []int) (*Disclosure, error) {
	tokens := v.Value()
	totalTokens := len(tokens)

	// Validate indices
	for _, idx := range indices {
		if idx < 0 || idx >= totalTokens {
			return nil, NewIndexOutOfBoundsError(idx, totalTokens)
		}
	}

	// Build reveal set for O(1) lookup
	revealSet := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		revealSet[idx] = struct{}{}
	}

	// Build Merkle leaves from ALL tokens
	leaves := make([]Hash, totalTokens)
	for i, t := range tokens {
		leaves[i] = tokenLeaf(t)
	}

	// Build Merkle tree
	tree := BuildMerkleTree(leaves)

	// Get code hash from execution proof
	codeHash := v.Proof().CodeHash

	// Build disclosed tokens and proofs for revealed tokens
	disclosed := make([]DisclosedToken, totalTokens)
	var proofs []MerkleProof

	for i := 0; i < totalTokens; i++ {
		if _, ok := revealSet[i]; ok {
			disclosed[i] = DisclosedToken{
				Index:    i,
				Revealed: true,
				TokenID:  tokens[i],
			}
			mp, err := tree.GenerateProof(uint64(i), codeHash)
			if err != nil {
				return nil, err
			}
			proofs = append(proofs, *mp)
		} else {
			disclosed[i] = DisclosedToken{
				Index:    i,
				Revealed: false,
				LeafHash: leaves[i],
			}
		}
	}

	return &Disclosure{
		Tokens:         disclosed,
		Proofs:         proofs,
		OutputRoot:     tree.Root,
		TotalTokens:    totalTokens,
		ExecutionProof: *v.Proof(),
	}, nil
}

// CreateDisclosureRange builds a disclosure for a contiguous range [start, end).
func CreateDisclosureRange(v *Verified[[]uint32], start, end int) (*Disclosure, error) {
	indices := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		indices = append(indices, i)
	}
	return CreateDisclosure(v, indices)
}

// VerifyDisclosure checks a disclosure for integrity.
// It verifies sequential indices, Merkle proofs, leaf hashes, and the execution proof.
func VerifyDisclosure(d *Disclosure) bool {
	// Token count must match
	if len(d.Tokens) != d.TotalTokens {
		return false
	}

	// Sequential indices — no gaps, no reordering
	for i, token := range d.Tokens {
		if token.Index != i {
			return false
		}
	}

	// Verify each revealed token against its Merkle proof
	proofIdx := 0
	for _, token := range d.Tokens {
		if token.Revealed {
			if proofIdx >= len(d.Proofs) {
				return false
			}
			proof := &d.Proofs[proofIdx]

			// Leaf must match the token
			expectedLeaf := tokenLeaf(token.TokenID)
			if expectedLeaf != proof.Leaf {
				return false
			}

			// Merkle proof must verify
			if !VerifyMerkleProof(proof) {
				return false
			}

			// Proof root must match disclosure root
			if proof.Root != d.OutputRoot {
				return false
			}

			proofIdx++
		} else {
			// Redacted positions must have a real commitment
			if token.LeafHash == ZeroHash {
				return false
			}
		}
	}

	// All proofs consumed
	if proofIdx != len(d.Proofs) {
		return false
	}

	// Execution proof structural check
	return d.ExecutionProof.StepCount > 0
}
