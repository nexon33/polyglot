package verified

import "crypto/sha256"

// HashData computes SHA-256 of arbitrary input bytes (no domain prefix).
func HashData(input []byte) Hash {
	return sha256.Sum256(input)
}

// HashLeaf computes a domain-separated leaf hash: SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashCombine computes a domain-separated interior node hash: SHA-256(0x03 || left || right).
// NOT commutative: HashCombine(a, b) != HashCombine(b, a).
func HashCombine(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x03})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashTransition computes a domain-separated transition hash: SHA-256(0x01 || prev || input || claimed).
// Total input: 97 bytes (1 + 32 + 32 + 32).
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

// HashChainStep computes a domain-separated chain step: SHA-256(0x02 || tip || stateHash).
// Total input: 65 bytes (1 + 32 + 32).
func HashChainStep(tip, stateHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(tip[:])
	h.Write(stateHash[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashBlinding computes a domain-separated blinding factor: SHA-256(0x04 || data).
// Used for privacy-mode blinding commitments.
func HashBlinding(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x04})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}
