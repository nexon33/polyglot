package verified

import "testing"

func TestVerifiedConstruction(t *testing.T) {
	proof := VerifiedProof{
		ChainTip:   Hash{0x01},
		MerkleRoot: Hash{0x02},
		StepCount:  1,
		CodeHash:   Hash{0x03},
		Privacy:    Transparent,
	}
	v := NewVerified(42, proof)
	if v.Value() != 42 {
		t.Fatalf("value = %d, want 42", v.Value())
	}
}

func TestVerifiedProofAccess(t *testing.T) {
	proof := VerifiedProof{
		ChainTip:  Hash{0x01},
		StepCount: 5,
		Privacy:   Transparent,
	}
	v := NewVerified("hello", proof)
	if v.Proof().StepCount != 5 {
		t.Fatalf("step_count = %d, want 5", v.Proof().StepCount)
	}
}

func TestVerifiedIsVerified(t *testing.T) {
	proof := VerifiedProof{StepCount: 1, Privacy: Transparent}
	v := NewVerified([]byte{1, 2, 3}, proof)
	if !v.IsVerified() {
		t.Fatal("should verify with step_count > 0")
	}
}

func TestVerifiedNotVerifiedZeroSteps(t *testing.T) {
	proof := VerifiedProof{StepCount: 0, Privacy: Transparent}
	v := NewVerified(0, proof)
	if v.IsVerified() {
		t.Fatal("should not verify with step_count == 0")
	}
}

func TestVerifiedPrivacyMode(t *testing.T) {
	proof := VerifiedProof{StepCount: 1, Privacy: Private}
	bc := Hash{0xFF}
	proof.BlindingCommitment = &bc
	v := NewVerified(0, proof)
	if v.PrivacyMode() != Private {
		t.Fatalf("privacy = %v, want Private", v.PrivacyMode())
	}
	if !v.IsPrivate() {
		t.Fatal("should report private")
	}
}

func TestVerifiedTransparentNotPrivate(t *testing.T) {
	proof := VerifiedProof{StepCount: 1, Privacy: Transparent}
	v := NewVerified(0, proof)
	if v.IsPrivate() {
		t.Fatal("transparent should not report private")
	}
}

func TestVerifiedSliceType(t *testing.T) {
	proof := VerifiedProof{
		ChainTip:   Hash{0x01},
		MerkleRoot: Hash{0x02},
		StepCount:  1,
		CodeHash:   Hash{0x03},
		Privacy:    Transparent,
	}
	tokens := []uint32{100, 200, 300}
	v := NewVerified(tokens, proof)
	if len(v.Value()) != 3 {
		t.Fatalf("len = %d, want 3", len(v.Value()))
	}
	if v.Value()[1] != 200 {
		t.Fatalf("token[1] = %d, want 200", v.Value()[1])
	}
}
