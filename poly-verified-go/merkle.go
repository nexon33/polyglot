package verified

import "fmt"

type MerkleTree struct {
	Layers [][]Hash
	Root   Hash
}

func BuildMerkleTree(leaves []Hash) *MerkleTree {
	if len(leaves) == 0 {
		return &MerkleTree{
			Layers: [][]Hash{{}},
			Root:   ZeroHash,
		}
	}

	current := make([]Hash, len(leaves))
	copy(current, leaves)
	layers := [][]Hash{current}

	for len(current) > 1 {
		nextLen := (len(current) + 1) / 2
		next := make([]Hash, 0, nextLen)

		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, HashCombine(current[i], current[i+1]))
			} else {
				next = append(next, HashCombine(current[i], current[i]))
			}
		}

		cp := make([]Hash, len(next))
		copy(cp, next)
		layers = append(layers, cp)
		current = next
	}

	return &MerkleTree{
		Layers: layers,
		Root:   current[0],
	}
}

func (t *MerkleTree) GenerateProof(leafIndex uint64, codeHash Hash) (*MerkleProof, error) {
	idx := int(leafIndex)
	leaves := t.Layers[0]

	if len(leaves) == 0 || idx >= len(leaves) {
		return nil, fmt.Errorf("index out of bounds: %d >= %d", leafIndex, len(leaves))
	}

	var siblings []ProofNode
	currentIndex := idx

	for _, layer := range t.Layers[:len(t.Layers)-1] {
		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		var siblingHash Hash
		if siblingIndex < len(layer) {
			siblingHash = layer[siblingIndex]
		} else {
				siblingHash = layer[currentIndex]
		}

		isLeft := currentIndex%2 == 1

		siblings = append(siblings, ProofNode{
			Hash:   siblingHash,
			IsLeft: isLeft,
		})

		currentIndex /= 2
	}

	return &MerkleProof{
		Leaf:      leaves[idx],
		LeafIndex: leafIndex,
		Siblings:  siblings,
		Root:      t.Root,
		CodeHash:  codeHash,
	}, nil
}

func VerifyMerkleProof(proof *MerkleProof) bool {
	current := proof.Leaf

	for _, node := range proof.Siblings {
		if node.IsLeft {
			current = HashCombine(node.Hash, current)
		} else {
			current = HashCombine(current, node.Hash)
		}
	}

	return current == proof.Root
}
