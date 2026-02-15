package verified

import "crypto/sha256"

func HashData(input []byte) Hash {
	return sha256.Sum256(input)
}

func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func HashCombine(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x03})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func HashTransition(prev, input, claimed Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(prev[:])
	h.Write(input[:])
	h.Write(claimed[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func HashChainStep(tip, stateHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(tip[:])
	h.Write(stateHash[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func HashBlinding(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x04})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}
