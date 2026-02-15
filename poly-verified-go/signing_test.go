package verified

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateIdentity(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// Generate new key.
	id1, err := LoadOrGenerateIdentity(keyPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(id1.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("expected %d byte public key, got %d", ed25519.PublicKeySize, len(id1.PublicKey))
	}

	// Load existing key — should get the same keypair.
	id2, err := LoadOrGenerateIdentity(keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if id1.PublicKeyHex() != id2.PublicKeyHex() {
		t.Fatal("loaded key should match generated key")
	}
}

func TestSignAndVerifyProof(t *testing.T) {
	dir := t.TempDir()
	id, _ := LoadOrGenerateIdentity(filepath.Join(dir, "test.key"))

	codeHash := HashData([]byte("test-model"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("input")),
		StateAfter:  HashData([]byte("output")),
		StepInputs:  codeHash,
	})
	proof, _ := acc.Finalize()

	sig := id.SignProof(proof)

	if !VerifyProofSignature(id.PublicKey, proof, sig) {
		t.Fatal("valid signature should verify")
	}

	// Tamper with proof — signature should fail.
	proof.StepCount = 999
	if VerifyProofSignature(id.PublicKey, proof, sig) {
		t.Fatal("tampered proof should fail verification")
	}
}

func TestSignatureDeterministic(t *testing.T) {
	dir := t.TempDir()
	id, _ := LoadOrGenerateIdentity(filepath.Join(dir, "test.key"))

	codeHash := HashData([]byte("determinism"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("a")),
		StateAfter:  HashData([]byte("b")),
		StepInputs:  codeHash,
	})
	proof, _ := acc.Finalize()

	sig1 := id.SignProof(proof)
	sig2 := id.SignProof(proof)

	// Ed25519 is deterministic.
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Fatal("Ed25519 signatures should be deterministic")
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	id1, _ := LoadOrGenerateIdentity(filepath.Join(dir, "key1"))
	id2, _ := LoadOrGenerateIdentity(filepath.Join(dir, "key2"))

	proof := &VerifiedProof{
		StepCount: 1,
		Privacy:   Transparent,
		CodeHash:  HashData([]byte("test")),
	}

	sig := id1.SignProof(proof)

	if VerifyProofSignature(id2.PublicKey, proof, sig) {
		t.Fatal("wrong key should fail verification")
	}
}

func TestToSignedJSON(t *testing.T) {
	dir := t.TempDir()
	id, _ := LoadOrGenerateIdentity(filepath.Join(dir, "test.key"))

	codeHash := HashData([]byte("model"))
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
	if spj.PublicKey == "" {
		t.Fatal("public_key should not be empty")
	}
	if spj.PublicKey != id.PublicKeyHex() {
		t.Fatal("public_key mismatch")
	}

	// Verify the hex signature is valid.
	sigBytes, err := hex.DecodeString(spj.Signature)
	if err != nil {
		t.Fatalf("invalid hex signature: %v", err)
	}
	if !VerifyProofSignature(id.PublicKey, proof, sigBytes) {
		t.Fatal("signature from ToSignedJSON should verify")
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	LoadOrGenerateIdentity(keyPath)

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}
}

func TestInvalidKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")

	os.WriteFile(keyPath, []byte("too short"), 0600)

	_, err := LoadOrGenerateIdentity(keyPath)
	if err == nil {
		t.Fatal("should reject invalid key file")
	}
}

func TestMerkleProofToJSON(t *testing.T) {
	leaves := make([]Hash, 4)
	for i := range leaves {
		leaves[i] = HashData([]byte{byte(i)})
	}
	tree := BuildMerkleTree(leaves)
	codeHash := HashData([]byte("test"))

	mp, err := tree.GenerateProof(1, codeHash)
	if err != nil {
		t.Fatal(err)
	}

	mpj := MerkleProofToJSON(mp)
	if !mpj.Valid {
		t.Fatal("merkle proof should be valid")
	}
	if mpj.LeafIndex != 1 {
		t.Fatalf("expected leaf_index 1, got %d", mpj.LeafIndex)
	}
	if len(mpj.Siblings) == 0 {
		t.Fatal("should have siblings")
	}
}
