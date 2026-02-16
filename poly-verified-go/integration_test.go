package verified

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestFullPipelineTransparent(t *testing.T) {
	codeHash := HashData([]byte("transparent_pipeline"))
	acc := NewHashIvc(codeHash, Transparent)

	for i := uint8(0); i < 3; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: HashData([]byte{i}),
			StateAfter:  HashData([]byte{i + 1}),
			StepInputs:  HashData([]byte{i, i}),
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("proof should verify")
	}
	if proof.StepCount != 3 {
		t.Fatalf("step_count = %d, want 3", proof.StepCount)
	}
	if proof.ChainTip == ZeroHash {
		t.Fatal("chain_tip should not be zero")
	}
	if proof.MerkleRoot == ZeroHash {
		t.Fatal("merkle_root should not be zero")
	}
	if proof.PublicCodeHash() != codeHash {
		t.Fatal("code_hash should match for transparent")
	}

	// Rebuild merkle tree from same steps, verify root matches
	var checkpoints []Hash
	for i := uint8(0); i < 3; i++ {
		checkpoints = append(checkpoints, HashTransition(
			HashData([]byte{i}),
			HashData([]byte{i, i}),
			HashData([]byte{i + 1}),
		))
	}
	tree := BuildMerkleTree(checkpoints)
	if tree.Root != proof.MerkleRoot {
		t.Fatal("independently computed merkle root should match proof")
	}

	// Verify merkle proofs for each step
	for i := uint64(0); i < 3; i++ {
		mp, err := tree.GenerateProof(i, codeHash)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if !VerifyMerkleProof(mp) {
			t.Fatalf("merkle proof failed for step %d", i)
		}
	}
}

func TestFullPipelinePrivate(t *testing.T) {
	codeHash := HashData([]byte("private_pipeline"))
	acc := NewHashIvc(codeHash, Private)

	for i := uint8(0); i < 3; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: HashData([]byte{i}),
			StateAfter:  HashData([]byte{i + 1}),
			StepInputs:  HashData([]byte{i, i}),
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("proof should verify")
	}
	if proof.BlindingCommitment == nil {
		t.Fatal("blinding should be present")
	}
	if *proof.BlindingCommitment == ZeroHash {
		t.Fatal("blinding should not be zero")
	}
	if proof.PublicCodeHash() != ZeroHash {
		t.Fatal("private mode should hide code_hash")
	}

	pj := proof.ToJSON()
	if pj.PrivacyMode != "private" {
		t.Fatalf("privacy_mode = %q, want private", pj.PrivacyMode)
	}
	if pj.BlindingCommitment == nil {
		t.Fatal("JSON blinding should be present")
	}
}

func TestFullPipelineSignedJSON(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrGenerateIdentity(filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatal(err)
	}

	codeHash := HashData([]byte("signed_pipeline"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("in")),
		StateAfter:  HashData([]byte("out")),
		StepInputs:  codeHash,
	})
	proof, _ := acc.Finalize()

	spj := proof.ToSignedJSON(id)
	if spj.Signature == "" {
		t.Fatal("signature should not be empty")
	}
	if spj.PublicKey != id.PublicKeyHex() {
		t.Fatal("public_key mismatch")
	}

	// Verify signature from hex
	sigBytes, err := hex.DecodeString(spj.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProofSignature(id.PublicKey, proof, sigBytes) {
		t.Fatal("signature should verify")
	}

	// Verify JSON marshaling works
	data, err := json.Marshal(spj)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("JSON output should not be empty")
	}
}

func TestFullPipelineVerificationResponse(t *testing.T) {
	codeHash := HashData([]byte("vr_pipeline"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("before")),
		StateAfter:  HashData([]byte("after")),
		StepInputs:  HashData([]byte("inputs")),
	})
	proof, _ := acc.Finalize()

	inputHash := HashData([]byte("user_input"))
	outputHash := HashData([]byte("model_output"))

	vr := NewVerificationResponse(proof, inputHash, outputHash, "test-model-v1")

	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["model_id"] != "test-model-v1" {
		t.Fatal("model_id mismatch")
	}
	if parsed["input_hash"] == nil {
		t.Fatal("input_hash should be present for transparent")
	}
	if parsed["output_hash"] == nil {
		t.Fatal("output_hash should be present for transparent")
	}

	proofObj, ok := parsed["proof"].(map[string]interface{})
	if !ok {
		t.Fatal("proof should be an object")
	}
	if proofObj["backend"] != "HashIvc" {
		t.Fatalf("backend = %v, want HashIvc", proofObj["backend"])
	}
	if proofObj["verified"] != true {
		t.Fatal("verified should be true")
	}
}

func TestFullPipelineMerkleProofJSON(t *testing.T) {
	codeHash := HashData([]byte("merkle_json_pipeline"))
	acc := NewHashIvc(codeHash, Transparent)

	for i := uint8(0); i < 4; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: HashData([]byte{i}),
			StateAfter:  HashData([]byte{i + 1}),
			StepInputs:  HashData([]byte{i * 3}),
		})
	}
	proof, _ := acc.Finalize()

	// Build tree from same transitions
	var checkpoints []Hash
	for i := uint8(0); i < 4; i++ {
		checkpoints = append(checkpoints, HashTransition(
			HashData([]byte{i}),
			HashData([]byte{i * 3}),
			HashData([]byte{i + 1}),
		))
	}
	tree := BuildMerkleTree(checkpoints)

	if tree.Root != proof.MerkleRoot {
		t.Fatal("tree root should match proof merkle_root")
	}

	mp, err := tree.GenerateProof(2, codeHash)
	if err != nil {
		t.Fatal(err)
	}

	mpj := MerkleProofToJSON(mp)
	if !mpj.Valid {
		t.Fatal("merkle proof should be valid")
	}
	if mpj.LeafIndex != 2 {
		t.Fatalf("leaf_index = %d, want 2", mpj.LeafIndex)
	}

	data, err := json.Marshal(mpj)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["valid"] != true {
		t.Fatal("valid should be true in JSON")
	}
	if len(mpj.Siblings) == 0 {
		t.Fatal("should have siblings")
	}
	for _, s := range mpj.Siblings {
		if len(s.Hash) != 64 {
			t.Fatalf("sibling hash hex length = %d, want 64", len(s.Hash))
		}
	}
}
