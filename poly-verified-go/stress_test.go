package verified

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func randomHash() Hash {
	var h Hash
	rand.Read(h[:])
	return h
}

// --- Stress tests: verify correctness at scale ---

func TestStressIVC100Steps(t *testing.T) {
	codeHash := HashData([]byte("stress-model-100"))
	acc := NewHashIvc(codeHash, Transparent)

	for i := 0; i < 100; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: randomHash(),
			StateAfter:  randomHash(),
			StepInputs:  codeHash,
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("100-step proof should verify")
	}
	if proof.StepCount != 100 {
		t.Fatalf("step_count = %d, want 100", proof.StepCount)
	}
	if proof.ChainTip == ZeroHash {
		t.Fatal("chain_tip should not be zero after 100 steps")
	}
}

func TestStressIVC1000Steps(t *testing.T) {
	codeHash := HashData([]byte("stress-model-1000"))
	acc := NewHashIvc(codeHash, Transparent)

	for i := 0; i < 1000; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: randomHash(),
			StateAfter:  randomHash(),
			StepInputs:  codeHash,
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("1000-step proof should verify")
	}
	if proof.StepCount != 1000 {
		t.Fatalf("step_count = %d, want 1000", proof.StepCount)
	}
}

func TestStressIVCPrivateMode1000(t *testing.T) {
	codeHash := HashData([]byte("stress-private-1000"))
	acc := NewHashIvc(codeHash, Private)

	for i := 0; i < 1000; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: randomHash(),
			StateAfter:  randomHash(),
			StepInputs:  codeHash,
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("1000-step private proof should verify")
	}
	if proof.BlindingCommitment == nil {
		t.Fatal("private mode should have blinding commitment")
	}
	publicCodeHash := proof.PublicCodeHash()
	if publicCodeHash != ZeroHash {
		t.Fatal("private mode should hide code_hash")
	}
}

func TestStressMerkleTree1024Leaves(t *testing.T) {
	leaves := make([]Hash, 1024)
	for i := range leaves {
		leaves[i] = randomHash()
	}

	tree := BuildMerkleTree(leaves)
	if tree.Root == ZeroHash {
		t.Fatal("root should not be zero for 1024 leaves")
	}

	// Verify proof at every 100th leaf.
	for _, idx := range []int{0, 100, 500, 999, 1023} {
		codeHash := HashData([]byte("merkle-stress"))
		mp, err := tree.GenerateProof(uint64(idx), codeHash)
		if err != nil {
			t.Fatalf("GenerateProof(%d): %v", idx, err)
		}
		if !VerifyMerkleProof(mp) {
			t.Fatalf("merkle proof at index %d should verify", idx)
		}
	}
}

func TestStressMerkleTreeOddLeaves(t *testing.T) {
	for _, n := range []int{1, 3, 7, 15, 31, 63, 127, 255} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := make([]Hash, n)
			for i := range leaves {
				leaves[i] = randomHash()
			}
			tree := BuildMerkleTree(leaves)
			codeHash := HashData([]byte("odd-test"))

			// Verify first and last leaf.
			for _, idx := range []int{0, n - 1} {
				mp, err := tree.GenerateProof(uint64(idx), codeHash)
				if err != nil {
					t.Fatalf("GenerateProof(%d): %v", idx, err)
				}
				if !VerifyMerkleProof(mp) {
					t.Fatalf("proof at %d should verify", idx)
				}
			}
		})
	}
}

func TestStressHashDeterminism(t *testing.T) {
	// Same input must always produce same output across 10k iterations.
	input := []byte("determinism-check")
	expected := HashData(input)
	for i := 0; i < 10000; i++ {
		got := HashData(input)
		if got != expected {
			t.Fatalf("iteration %d: hash changed", i)
		}
	}
}

func TestStressChainUniqueness(t *testing.T) {
	// 1000 sequential chain steps must all produce unique tips.
	chain := NewHashChain()
	seen := make(map[Hash]bool, 1000)

	for i := 0; i < 1000; i++ {
		chain.Append(randomHash())
		if seen[chain.Tip] {
			t.Fatalf("duplicate chain tip at step %d", i)
		}
		seen[chain.Tip] = true
	}
}

func TestStressFullPipelineWithSigning(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrGenerateIdentity(dir + "/key")
	if err != nil {
		t.Fatal(err)
	}

	codeHash := HashData([]byte("signing-stress"))
	acc := NewHashIvc(codeHash, Transparent)

	for i := 0; i < 50; i++ {
		acc.FoldStep(StepWitness{
			StateBefore: randomHash(),
			StateAfter:  randomHash(),
			StepInputs:  codeHash,
		})
	}

	proof, err := acc.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	// Sign and verify 100 times to ensure no state corruption.
	for i := 0; i < 100; i++ {
		sig := id.SignProof(proof)
		if !VerifyProofSignature(id.PublicKey, proof, sig) {
			t.Fatalf("signature verification failed at iteration %d", i)
		}
	}
}

func TestStressCollisionResistance(t *testing.T) {
	// All 6 hash functions on the same 32-byte input must produce distinct outputs.
	var data [32]byte
	for i := range data {
		data[i] = 0xAB
	}

	results := make(map[string]string)
	hashes := map[string]Hash{
		"HashData":      HashData(data[:]),
		"HashLeaf":      HashLeaf(data[:]),
		"HashBlinding":  HashBlinding(data[:]),
		"HashChainStep": HashChainStep(Hash(data), Hash(data)),
	}

	var a, b Hash
	copy(a[:], data[:])
	for i := range b {
		b[i] = 0xCD
	}
	hashes["HashCombine"] = HashCombine(a, b)
	hashes["HashTransition"] = HashTransition(a, b, a)

	for name, h := range hashes {
		hexStr := hex.EncodeToString(h[:])
		if prev, ok := results[hexStr]; ok {
			t.Fatalf("collision: %s == %s (both produce %s)", name, prev, hexStr)
		}
		results[hexStr] = name
	}
}

// --- Benchmarks ---

func BenchmarkHashData(b *testing.B) {
	input := make([]byte, 1024)
	rand.Read(input)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashData(input)
	}
}

func BenchmarkHashLeaf(b *testing.B) {
	input := make([]byte, 1024)
	rand.Read(input)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashLeaf(input)
	}
}

func BenchmarkHashCombine(b *testing.B) {
	left, right := randomHash(), randomHash()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashCombine(left, right)
	}
}

func BenchmarkHashTransition(b *testing.B) {
	a, c, d := randomHash(), randomHash(), randomHash()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashTransition(a, c, d)
	}
}

func BenchmarkHashChainStep(b *testing.B) {
	tip, state := randomHash(), randomHash()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashChainStep(tip, state)
	}
}

func BenchmarkIVCFold(b *testing.B) {
	codeHash := HashData([]byte("bench-model"))
	acc := NewHashIvc(codeHash, Transparent)
	witness := StepWitness{
		StateBefore: randomHash(),
		StateAfter:  randomHash(),
		StepInputs:  codeHash,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc.FoldStep(witness)
	}
}

func BenchmarkIVCFoldPrivate(b *testing.B) {
	codeHash := HashData([]byte("bench-private"))
	acc := NewHashIvc(codeHash, Private)
	witness := StepWitness{
		StateBefore: randomHash(),
		StateAfter:  randomHash(),
		StepInputs:  codeHash,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc.FoldStep(witness)
	}
}

func BenchmarkMerkleTree1024(b *testing.B) {
	leaves := make([]Hash, 1024)
	for i := range leaves {
		leaves[i] = randomHash()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildMerkleTree(leaves)
	}
}

func BenchmarkMerkleProof1024(b *testing.B) {
	leaves := make([]Hash, 1024)
	for i := range leaves {
		leaves[i] = randomHash()
	}
	tree := BuildMerkleTree(leaves)
	codeHash := HashData([]byte("bench"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.GenerateProof(uint64(i%1024), codeHash)
	}
}

func BenchmarkSignProof(b *testing.B) {
	dir := b.TempDir()
	id, _ := LoadOrGenerateIdentity(dir + "/key")
	codeHash := HashData([]byte("bench"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: randomHash(),
		StateAfter:  randomHash(),
		StepInputs:  codeHash,
	})
	proof, _ := acc.Finalize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id.SignProof(proof)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	dir := b.TempDir()
	id, _ := LoadOrGenerateIdentity(dir + "/key")
	codeHash := HashData([]byte("bench"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: randomHash(),
		StateAfter:  randomHash(),
		StepInputs:  codeHash,
	})
	proof, _ := acc.Finalize()
	sig := id.SignProof(proof)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyProofSignature(id.PublicKey, proof, sig)
	}
}

func BenchmarkFullPipeline(b *testing.B) {
	dir := b.TempDir()
	id, _ := LoadOrGenerateIdentity(dir + "/key")
	codeHash := HashData([]byte("bench-pipeline"))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		acc := NewHashIvc(codeHash, Transparent)
		acc.FoldStep(StepWitness{
			StateBefore: HashData([]byte("input")),
			StateAfter:  HashData([]byte("output")),
			StepInputs:  codeHash,
		})
		proof, _ := acc.Finalize()
		id.SignProof(proof)
	}
}
