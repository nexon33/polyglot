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

func TestHashIvcPrivateModeBlinding(t *testing.T) {
	codeHash := HashData([]byte("private_fn"))

	acc := NewHashIvc(codeHash, Private)
	witness := StepWitness{
		StateBefore: HashData([]byte("before")),
		StateAfter:  HashData([]byte("after")),
		StepInputs:  HashData([]byte("inputs")),
	}
	acc.FoldStep(witness)

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	if proof.Privacy != Private {
		t.Fatal("expected Private privacy")
	}
	if proof.BlindingCommitment == nil {
		t.Fatal("blinding should be present in Private mode")
	}
	if *proof.BlindingCommitment == ZeroHash {
		t.Fatal("blinding should not be zero")
	}

	// Full private: PublicCodeHash() should return ZeroHash
	if proof.PublicCodeHash() != ZeroHash {
		t.Fatal("Private mode should hide code_hash")
	}

	if !proof.Verify() {
		t.Fatal("proof verification failed")
	}
}

func TestHashIvcPrivateInputsMode(t *testing.T) {
	codeHash := HashData([]byte("selective_fn"))

	acc := NewHashIvc(codeHash, PrivateInputs)
	witness := StepWitness{
		StateBefore: HashData([]byte("before")),
		StateAfter:  HashData([]byte("after")),
		StepInputs:  HashData([]byte("inputs")),
	}
	acc.FoldStep(witness)

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	if proof.Privacy != PrivateInputs {
		t.Fatal("expected PrivateInputs privacy")
	}
	if proof.BlindingCommitment == nil {
		t.Fatal("blinding should be present")
	}
	// PrivateInputs: code_hash is still visible
	if proof.CodeHash != codeHash {
		t.Fatal("code_hash should match for PrivateInputs")
	}
	if proof.PublicCodeHash() != codeHash {
		t.Fatal("PublicCodeHash should return real code_hash for PrivateInputs")
	}
}

func TestHashIvcTransparentNoBlinding(t *testing.T) {
	codeHash := HashData([]byte("transparent_fn"))

	acc := NewHashIvc(codeHash, Transparent)
	witness := StepWitness{
		StateBefore: HashData([]byte("before")),
		StateAfter:  HashData([]byte("after")),
		StepInputs:  HashData([]byte("inputs")),
	}
	acc.FoldStep(witness)

	proof, _ := acc.Finalize()

	if proof.Privacy != Transparent {
		t.Fatal("expected Transparent")
	}
	if proof.BlindingCommitment != nil {
		t.Fatal("blinding should be nil for Transparent")
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
