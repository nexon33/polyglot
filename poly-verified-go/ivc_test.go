package verified

import "testing"

func TestHashIvcRoundtrip(t *testing.T) {
	codeHash := HashData([]byte("test_function"))

	acc := NewHashIvc(codeHash, Transparent)

	for i := uint8(0); i < 3; i++ {
		witness := StepWitness{
			StateBefore: HashData([]byte{i}),
			StateAfter:  HashData([]byte{i + 1}),
			StepInputs:  HashData([]byte{i, i}),
		}
		if err := acc.FoldStep(witness); err != nil {
			t.Fatalf("fold step %d: %v", i, err)
		}
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	if !proof.Verify() {
		t.Fatal("proof verification failed")
	}
}

func TestHashIvcEmptyFails(t *testing.T) {
	codeHash := HashData([]byte("test_function"))
	acc := NewHashIvc(codeHash, Transparent)

	_, err := acc.Finalize()
	if err == nil {
		t.Fatal("finalize should fail on empty accumulator")
	}
}

func TestHashIvcProofStructure(t *testing.T) {
	codeHash := HashData([]byte("my_verified_fn"))

	acc := NewHashIvc(codeHash, Transparent)
	witness := StepWitness{
		StateBefore: HashData([]byte("before")),
		StateAfter:  HashData([]byte("after")),
		StepInputs:  HashData([]byte("inputs")),
	}
	if err := acc.FoldStep(witness); err != nil {
		t.Fatal(err)
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	if proof.StepCount != 1 {
		t.Fatalf("expected step_count 1, got %d", proof.StepCount)
	}
	if proof.CodeHash != codeHash {
		t.Fatal("code_hash mismatch")
	}
	if proof.Privacy != Transparent {
		t.Fatal("expected Transparent privacy")
	}
	if proof.BlindingCommitment != nil {
		t.Fatal("blinding should be nil for Transparent")
	}
}

func TestHashIvcDeterministic(t *testing.T) {
	codeHash := HashData([]byte("determinism_test"))

	var proofs [2]*VerifiedProof
	for run := 0; run < 2; run++ {
		acc := NewHashIvc(codeHash, Transparent)
		for i := uint8(0); i < 5; i++ {
			witness := StepWitness{
				StateBefore: HashData([]byte{i}),
				StateAfter:  HashData([]byte{i + 1}),
				StepInputs:  HashData([]byte{i * 2}),
			}
			acc.FoldStep(witness)
		}
		p, _ := acc.Finalize()
		proofs[run] = p
	}

	if proofs[0].ChainTip != proofs[1].ChainTip {
		t.Fatal("chain_tip not deterministic")
	}
	if proofs[0].MerkleRoot != proofs[1].MerkleRoot {
		t.Fatal("merkle_root not deterministic")
	}
	if proofs[0].StepCount != proofs[1].StepCount {
		t.Fatal("step_count not deterministic")
	}
}

func TestHashIvcPrivacyModes(t *testing.T) {
	tests := []struct {
		name     string
		mode     PrivacyMode
		hasBlind bool
		hideCode bool
	}{
		{"Private", Private, true, true},
		{"PrivateInputs", PrivateInputs, true, false},
		{"Transparent", Transparent, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codeHash := HashData([]byte(tt.name + "_fn"))
			acc := NewHashIvc(codeHash, tt.mode)
			acc.FoldStep(StepWitness{
				StateBefore: HashData([]byte("before")),
				StateAfter:  HashData([]byte("after")),
				StepInputs:  HashData([]byte("inputs")),
			})
			proof, err := acc.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			if proof.Privacy != tt.mode {
				t.Fatalf("expected %v privacy", tt.mode)
			}
			if tt.hasBlind && proof.BlindingCommitment == nil {
				t.Fatal("blinding should be present")
			}
			if !tt.hasBlind && proof.BlindingCommitment != nil {
				t.Fatal("blinding should be nil")
			}
			if tt.hasBlind && proof.BlindingCommitment != nil && *proof.BlindingCommitment == ZeroHash {
				t.Fatal("blinding should not be zero")
			}
			if tt.hideCode && proof.PublicCodeHash() != ZeroHash {
				t.Fatal("should hide code_hash")
			}
			if !tt.hideCode && proof.PublicCodeHash() != codeHash {
				t.Fatal("code_hash should match")
			}
			if !proof.Verify() {
				t.Fatal("proof verification failed")
			}
		})
	}
}

func TestHashIvcVerifyRejectsZeroSteps(t *testing.T) {
	proof := &VerifiedProof{
		StepCount: 0,
		Privacy:   Transparent,
	}
	if proof.Verify() {
		t.Fatal("should reject zero steps")
	}
}

func TestHashIvcVerifyRejectsMissingBlinding(t *testing.T) {
	proof := &VerifiedProof{
		StepCount:          1,
		Privacy:            Private,
		BlindingCommitment: nil,
	}
	if proof.Verify() {
		t.Fatal("should reject Private mode without blinding")
	}
}
