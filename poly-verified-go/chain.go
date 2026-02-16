package verified

type HashChainState struct {
	Tip    Hash
	Length uint64
}

func NewHashChain() *HashChainState {
	return &HashChainState{
		Tip:    ZeroHash,
		Length: 0,
	}
}

func (c *HashChainState) Append(stateHash Hash) {
	c.Tip = HashChainStep(c.Tip, stateHash)
	c.Length++
}
