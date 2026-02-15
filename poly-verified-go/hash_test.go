package verified

import (
	"encoding/hex"
	"testing"
)

func hexToHash(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	var h Hash
	copy(h[:], b)
	return h
}

// Appendix B.1: hash_data test vectors (byte-compatible with Rust)
func TestHashDataEmpty(t *testing.T) {
	result := HashData([]byte{})
	expected := hexToHash(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if result != expected {
		t.Fatalf("hash_data empty: got %x, want %x", result, expected)
	}
}

func TestHashData0x00(t *testing.T) {
	result := HashData([]byte{0x00})
	expected := hexToHash(t, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
	if result != expected {
		t.Fatalf("hash_data 0x00: got %x, want %x", result, expected)
	}
}

func TestHashData0x01(t *testing.T) {
	result := HashData([]byte{0x01})
	expected := hexToHash(t, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
	if result != expected {
		t.Fatalf("hash_data 0x01: got %x, want %x", result, expected)
	}
}

func TestHashDataMultiByte(t *testing.T) {
	result := HashData([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	expected := hexToHash(t, "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0")
	if result != expected {
		t.Fatalf("hash_data multi: got %x, want %x", result, expected)
	}
}

// Appendix B.2: hash_combine test vectors
func TestHashCombineZeros(t *testing.T) {
	var left, right Hash
	result := HashCombine(left, right)
	expected := hexToHash(t, "dc48a742ae32cfd66352372d6120ed14d6629fc166246b05ff8b03e23804701f")
	if result != expected {
		t.Fatalf("hash_combine zeros: got %x, want %x", result, expected)
	}
}

func TestHashCombineNotCommutative(t *testing.T) {
	var left, right Hash
	for i := range left {
		left[i] = 0x01
	}
	for i := range right {
		right[i] = 0x02
	}
	r1 := HashCombine(left, right)
	r2 := HashCombine(right, left)
	if r1 == r2 {
		t.Fatal("hash_combine should not be commutative")
	}
}

// Domain separation: hash_data vs hash_leaf on same input must differ
func TestDomainSeparation(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = 0xAB
	}
	h1 := HashData(data[:])
	h2 := HashLeaf(data[:])
	if h1 == h2 {
		t.Fatal("hash_data and hash_leaf must differ for same input")
	}
}

func TestDomainSeparationCombineVsData(t *testing.T) {
	var left, right Hash
	combined := HashCombine(left, right)
	var rawInput [64]byte
	copy(rawInput[:32], left[:])
	copy(rawInput[32:], right[:])
	raw := HashData(rawInput[:])
	if combined == raw {
		t.Fatal("hash_combine must differ from hash_data on same 64-byte input")
	}
}

// HashEq constant-time comparison
func TestHashEqIdentical(t *testing.T) {
	a := HashData([]byte("test"))
	b := HashData([]byte("test"))
	if !HashEq(a, b) {
		t.Fatal("identical hashes should be equal")
	}
}

func TestHashEqDifferent(t *testing.T) {
	a := HashData([]byte("test1"))
	b := HashData([]byte("test2"))
	if HashEq(a, b) {
		t.Fatal("different hashes should not be equal")
	}
}
