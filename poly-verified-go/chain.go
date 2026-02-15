package verified

// HashChainState is a sequential hash chain providing tamper-evident, order-dependent commitment.
type HashChainState struct {
	Tip    Hash
	Length uint64
}

// NewHashChain creates a new hash chain with ZeroHash tip and length 0.
func NewHashChain() *HashChainState {
	return &HashChainState{
		Tip:    ZeroHash,
		Length: 0,
	}
}

// Append extends the chain: tip = HashChainStep(tip, stateHash), length++.
func (c *HashChainState) Append(stateHash Hash) {
	c.Tip = HashChainStep(c.Tip, stateHash)
	c.Length++
}
