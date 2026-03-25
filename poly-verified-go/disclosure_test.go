package verified

import "testing"

func mockHashIvcProof() VerifiedProof {
	return VerifiedProof{
		ChainTip:   Hash{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		MerkleRoot: Hash{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		StepCount:  1,
		CodeHash:   Hash{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
		Privacy:    Transparent,
	}
}

func sampleTokens() []uint32 {
	return []uint32{100, 200, 300, 400, 500, 600, 700, 800}
}

func makeVerified(tokens []uint32) Verified[[]uint32] {
	return NewVerified(tokens, mockHashIvcProof())
}

func TestCreateAndVerifyDisclosure(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{2, 5})
	if err != nil {
		t.Fatal(err)
	}

	if d.TotalTokens != 8 {
		t.Fatalf("total_tokens = %d, want 8", d.TotalTokens)
	}
	if len(d.Tokens) != 8 {
		t.Fatalf("tokens len = %d, want 8", len(d.Tokens))
	}
	if len(d.Proofs) != 2 {
		t.Fatalf("proofs len = %d, want 2", len(d.Proofs))
	}

	// Tokens 2 and 5 revealed
	if !d.Tokens[2].Revealed || d.Tokens[2].TokenID != 300 {
		t.Fatal("token 2 should reveal 300")
	}
	if !d.Tokens[5].Revealed || d.Tokens[5].TokenID != 600 {
		t.Fatal("token 5 should reveal 600")
	}

	// Others redacted
	for _, i := range []int{0, 1, 3, 4, 6, 7} {
		if d.Tokens[i].Revealed {
			t.Fatalf("token %d should be redacted", i)
		}
		if d.Tokens[i].LeafHash == ZeroHash {
			t.Fatalf("token %d should have non-zero leaf hash", i)
		}
	}

	if !VerifyDisclosure(d) {
		t.Fatal("disclosure should verify")
	}
}

func TestDisclosureRange(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosureRange(&v, 1, 4)
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Proofs) != 3 {
		t.Fatalf("proofs len = %d, want 3", len(d.Proofs))
	}

	for i := 1; i < 4; i++ {
		if !d.Tokens[i].Revealed {
			t.Fatalf("token %d should be revealed", i)
		}
	}
	for _, i := range []int{0, 4, 5, 6, 7} {
		if d.Tokens[i].Revealed {
			t.Fatalf("token %d should be redacted", i)
		}
	}

	if !VerifyDisclosure(d) {
		t.Fatal("disclosure range should verify")
	}
}

func TestDifferentAudiencesSameProof(t *testing.T) {
	v := makeVerified(sampleTokens())

	pharmacist, err := CreateDisclosure(&v, []int{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	insurer, err := CreateDisclosure(&v, []int{5})
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyDisclosure(pharmacist) {
		t.Fatal("pharmacist disclosure should verify")
	}
	if !VerifyDisclosure(insurer) {
		t.Fatal("insurer disclosure should verify")
	}

	// Same output root
	if pharmacist.OutputRoot != insurer.OutputRoot {
		t.Fatal("output roots should match")
	}

	if len(pharmacist.Proofs) != 3 {
		t.Fatalf("pharmacist proofs = %d, want 3", len(pharmacist.Proofs))
	}
	if len(insurer.Proofs) != 1 {
		t.Fatalf("insurer proofs = %d, want 1", len(insurer.Proofs))
	}
}

func TestFullReveal(t *testing.T) {
	v := makeVerified(sampleTokens())
	indices := make([]int, 8)
	for i := range indices {
		indices[i] = i
	}
	d, err := CreateDisclosure(&v, indices)
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Proofs) != 8 {
		t.Fatalf("proofs len = %d, want 8", len(d.Proofs))
	}
	for _, tok := range d.Tokens {
		if !tok.Revealed {
			t.Fatal("all tokens should be revealed")
		}
	}
	if !VerifyDisclosure(d) {
		t.Fatal("full reveal should verify")
	}
}

func TestFullyPrivateEmptyIndices(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{})
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Proofs) != 0 {
		t.Fatalf("proofs len = %d, want 0", len(d.Proofs))
	}
	for _, tok := range d.Tokens {
		if tok.Revealed {
			t.Fatal("all tokens should be redacted")
		}
	}
	if !VerifyDisclosure(d) {
		t.Fatal("empty disclosure should verify")
	}
}

func TestOutOfBoundsIndex(t *testing.T) {
	v := makeVerified(sampleTokens())
	_, err := CreateDisclosure(&v, []int{8})
	if err == nil {
		t.Fatal("should error on out-of-bounds index")
	}
}

func TestOutOfBoundsRange(t *testing.T) {
	v := makeVerified(sampleTokens())
	_, err := CreateDisclosureRange(&v, 6, 10)
	if err == nil {
		t.Fatal("should error on out-of-bounds range")
	}
}

func TestSingleToken(t *testing.T) {
	v := makeVerified([]uint32{42})
	d, err := CreateDisclosure(&v, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	if d.TotalTokens != 1 {
		t.Fatalf("total_tokens = %d, want 1", d.TotalTokens)
	}
	if len(d.Proofs) != 1 {
		t.Fatalf("proofs = %d, want 1", len(d.Proofs))
	}
	if !VerifyDisclosure(d) {
		t.Fatal("single token disclosure should verify")
	}
}

func TestSingleTokenRedacted(t *testing.T) {
	v := makeVerified([]uint32{42})
	d, err := CreateDisclosure(&v, []int{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Proofs) != 0 {
		t.Fatalf("proofs = %d, want 0", len(d.Proofs))
	}
	if !VerifyDisclosure(d) {
		t.Fatal("redacted single token should verify")
	}
}

func TestDuplicateIndices(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{2, 2, 5})
	if err != nil {
		t.Fatal(err)
	}
	// Duplicates get deduplicated by the set
	if len(d.Proofs) != 2 {
		t.Fatalf("proofs = %d, want 2", len(d.Proofs))
	}
	if !VerifyDisclosure(d) {
		t.Fatal("duplicate indices disclosure should verify")
	}
}

func TestVerifyWrongTokenFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{2})
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with revealed token value
	d.Tokens[2].TokenID = 9999

	if VerifyDisclosure(d) {
		t.Fatal("tampered token should fail verification")
	}
}

func TestVerifyCorruptedMerkleProofFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{2})
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Proofs[0].Siblings) > 0 {
		d.Proofs[0].Siblings[0].Hash[0] ^= 0xFF
	}

	if VerifyDisclosure(d) {
		t.Fatal("corrupted merkle proof should fail verification")
	}
}

func TestVerifyWrongOutputRootFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{2})
	if err != nil {
		t.Fatal(err)
	}

	d.OutputRoot = Hash{0xFF}

	if VerifyDisclosure(d) {
		t.Fatal("wrong output root should fail verification")
	}
}

func TestVerifyReorderedTokensFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{})
	if err != nil {
		t.Fatal(err)
	}

	// Swap positions 0 and 1
	d.Tokens[0], d.Tokens[1] = d.Tokens[1], d.Tokens[0]

	if VerifyDisclosure(d) {
		t.Fatal("reordered tokens should fail verification")
	}
}

func TestVerifyMissingTokenFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{})
	if err != nil {
		t.Fatal(err)
	}

	d.Tokens = d.Tokens[:len(d.Tokens)-1]

	if VerifyDisclosure(d) {
		t.Fatal("missing token should fail verification")
	}
}

func TestVerifyZeroLeafHashFails(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := CreateDisclosure(&v, []int{})
	if err != nil {
		t.Fatal(err)
	}

	d.Tokens[3].LeafHash = ZeroHash

	if VerifyDisclosure(d) {
		t.Fatal("zero leaf hash should fail verification")
	}
}

func TestDiscloseTopLevelFunction(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := Disclose(&v, []int{0, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Proofs) != 2 {
		t.Fatalf("proofs = %d, want 2", len(d.Proofs))
	}
	if !VerifyDisclosure(d) {
		t.Fatal("Disclose should produce valid disclosure")
	}
}

func TestDiscloseRangeTopLevelFunction(t *testing.T) {
	v := makeVerified(sampleTokens())
	d, err := DiscloseRange(&v, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Proofs) != 2 {
		t.Fatalf("proofs = %d, want 2", len(d.Proofs))
	}
	if !VerifyDisclosure(d) {
		t.Fatal("DiscloseRange should produce valid disclosure")
	}
}
