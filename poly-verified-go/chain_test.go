package verified

import "testing"

func TestChainInitialState(t *testing.T) {
	chain := NewHashChain()
	if chain.Tip != ZeroHash {
		t.Fatal("initial tip should be ZeroHash")
	}
	if chain.Length != 0 {
		t.Fatal("initial length should be 0")
	}
}

func TestChainAppendOne(t *testing.T) {
	chain := NewHashChain()
	h0 := HashData([]byte{0x00})
	chain.Append(h0)

	if chain.Length != 1 {
		t.Fatalf("length should be 1, got %d", chain.Length)
	}
	expected := HashChainStep(ZeroHash, h0)
	if chain.Tip != expected {
		t.Fatalf("tip mismatch: got %x, want %x", chain.Tip, expected)
	}
}

func TestChainAppendTwo(t *testing.T) {
	chain := NewHashChain()
	h0 := HashData([]byte{0x00})
	h1 := HashData([]byte{0x01})
	chain.Append(h0)
	chain.Append(h1)

	if chain.Length != 2 {
		t.Fatalf("length should be 2, got %d", chain.Length)
	}
	tip1 := HashChainStep(ZeroHash, h0)
	tip2 := HashChainStep(tip1, h1)
	if chain.Tip != tip2 {
		t.Fatalf("tip mismatch: got %x, want %x", chain.Tip, tip2)
	}
}

func TestChainOrderDependent(t *testing.T) {
	h0 := HashData([]byte{0x00})
	h1 := HashData([]byte{0x01})

	chainA := NewHashChain()
	chainA.Append(h0)
	chainA.Append(h1)

	chainB := NewHashChain()
	chainB.Append(h1)
	chainB.Append(h0)

	if chainA.Tip == chainB.Tip {
		t.Fatal("different order must produce different chain tips")
	}
}
