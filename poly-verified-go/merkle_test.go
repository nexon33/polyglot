package verified

import "testing"

func make4Leaves() []Hash {
	return []Hash{
		HashData([]byte{0x00}),
		HashData([]byte{0x01}),
		HashData([]byte{0x02}),
		HashData([]byte{0x03}),
	}
}

func TestBuild4Leaves(t *testing.T) {
	leaves := make4Leaves()
	tree := BuildMerkleTree(leaves)

	if len(tree.Layers) != 3 {
		t.Fatalf("expected 3 layers, got %d", len(tree.Layers))
	}
	if len(tree.Layers[0]) != 4 {
		t.Fatalf("expected 4 leaves, got %d", len(tree.Layers[0]))
	}
	if len(tree.Layers[1]) != 2 {
		t.Fatalf("expected 2 interior nodes, got %d", len(tree.Layers[1]))
	}
	if len(tree.Layers[2]) != 1 {
		t.Fatalf("expected 1 root, got %d", len(tree.Layers[2]))
	}

	// Verify interior nodes
	node0 := HashCombine(leaves[0], leaves[1])
	node1 := HashCombine(leaves[2], leaves[3])
	if tree.Layers[1][0] != node0 {
		t.Fatal("interior node 0 mismatch")
	}
	if tree.Layers[1][1] != node1 {
		t.Fatal("interior node 1 mismatch")
	}

	// Verify root
	root := HashCombine(node0, node1)
	if tree.Root != root {
		t.Fatal("root mismatch")
	}
}

func TestProofIndex2(t *testing.T) {
	leaves := make4Leaves()
	tree := BuildMerkleTree(leaves)
	proof, err := tree.GenerateProof(2, ZeroHash)
	if err != nil {
		t.Fatal(err)
	}

	if proof.Leaf != leaves[2] {
		t.Fatal("leaf mismatch")
	}
	if proof.LeafIndex != 2 {
		t.Fatal("leaf index mismatch")
	}
	if len(proof.Siblings) != 2 {
		t.Fatalf("expected 2 siblings, got %d", len(proof.Siblings))
	}

	// Sibling 0: leaf_3, is_left=false (index 2 is even)
	if proof.Siblings[0].Hash != leaves[3] {
		t.Fatal("sibling 0 hash mismatch")
	}
	if proof.Siblings[0].IsLeft {
		t.Fatal("sibling 0 should not be left")
	}

	// Sibling 1: node_0, is_left=true (index 1 is odd)
	node0 := HashCombine(leaves[0], leaves[1])
	if proof.Siblings[1].Hash != node0 {
		t.Fatal("sibling 1 hash mismatch")
	}
	if !proof.Siblings[1].IsLeft {
		t.Fatal("sibling 1 should be left")
	}

	if !VerifyMerkleProof(proof) {
		t.Fatal("proof verification failed")
	}
}

func TestProofAllIndices(t *testing.T) {
	leaves := make4Leaves()
	tree := BuildMerkleTree(leaves)

	for i := uint64(0); i < 4; i++ {
		proof, err := tree.GenerateProof(i, ZeroHash)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if !VerifyMerkleProof(proof) {
			t.Fatalf("proof failed for index %d", i)
		}
	}
}

func TestSingleLeaf(t *testing.T) {
	leaf := HashData([]byte{0x42})
	tree := BuildMerkleTree([]Hash{leaf})

	if len(tree.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(tree.Layers))
	}
	if tree.Root != leaf {
		t.Fatal("root should equal the single leaf")
	}

	proof, err := tree.GenerateProof(0, ZeroHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Siblings) != 0 {
		t.Fatalf("expected 0 siblings, got %d", len(proof.Siblings))
	}
	if !VerifyMerkleProof(proof) {
		t.Fatal("single leaf proof failed")
	}
}

func Test3LeavesOdd(t *testing.T) {
	leaves := []Hash{
		HashData([]byte{0x00}),
		HashData([]byte{0x01}),
		HashData([]byte{0x02}),
	}
	tree := BuildMerkleTree(leaves)

	// Layer 1: hash(l0,l1), hash(l2,l2)
	if len(tree.Layers[1]) != 2 {
		t.Fatalf("expected 2 interior nodes, got %d", len(tree.Layers[1]))
	}
	expectedDup := HashCombine(leaves[2], leaves[2])
	if tree.Layers[1][1] != expectedDup {
		t.Fatal("odd element should be duplicated")
	}

	for i := uint64(0); i < 3; i++ {
		proof, err := tree.GenerateProof(i, ZeroHash)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if !VerifyMerkleProof(proof) {
			t.Fatalf("proof failed for index %d", i)
		}
	}
}

func TestEmpty(t *testing.T) {
	tree := BuildMerkleTree([]Hash{})
	if tree.Root != ZeroHash {
		t.Fatal("empty tree root should be ZeroHash")
	}
}

func TestCorruptedProofFails(t *testing.T) {
	leaves := make4Leaves()
	tree := BuildMerkleTree(leaves)
	proof, _ := tree.GenerateProof(2, ZeroHash)

	// Corrupt a sibling hash
	proof.Siblings[0].Hash[0] ^= 0xFF
	if VerifyMerkleProof(proof) {
		t.Fatal("corrupted proof should fail verification")
	}
}

func TestOutOfBounds(t *testing.T) {
	leaves := make4Leaves()
	tree := BuildMerkleTree(leaves)
	_, err := tree.GenerateProof(4, ZeroHash)
	if err == nil {
		t.Fatal("should error on out-of-bounds index")
	}
}
