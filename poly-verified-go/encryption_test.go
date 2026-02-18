package verified

import (
	"encoding/json"
	"testing"
)

func TestModeString(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeTransparent, "Transparent"},
		{ModePrivateProven, "PrivateProven"},
		{ModePrivate, "Private"},
		{ModeEncrypted, "Encrypted"},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(tc.mode), got, tc.want)
		}
	}
}

func TestModeJSON(t *testing.T) {
	for _, m := range []Mode{ModeTransparent, ModePrivateProven, ModePrivate, ModeEncrypted} {
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal Mode %v: %v", m, err)
		}

		var got Mode
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal Mode from %s: %v", data, err)
		}
		if got != m {
			t.Errorf("roundtrip Mode: got %v, want %v", got, m)
		}
	}
}

func TestModeToPrivacyMode(t *testing.T) {
	cases := []struct {
		mode Mode
		want PrivacyMode
	}{
		{ModeTransparent, Transparent},
		{ModePrivateProven, PrivateInputs},
		{ModePrivate, Private},
		{ModeEncrypted, Private},
	}
	for _, tc := range cases {
		if got := tc.mode.ToPrivacyMode(); got != tc.want {
			t.Errorf("Mode(%d).ToPrivacyMode() = %v, want %v", int(tc.mode), got, tc.want)
		}
	}
}

func TestModeRequiresEncryption(t *testing.T) {
	for _, m := range []Mode{ModeTransparent, ModePrivateProven, ModePrivate} {
		if m.RequiresEncryption() {
			t.Errorf("Mode %v should not require encryption", m)
		}
	}
	if !ModeEncrypted.RequiresEncryption() {
		t.Error("ModeEncrypted should require encryption")
	}
}

func TestInferRequestJSON(t *testing.T) {
	req := InferRequest{
		ModelID:        "hermes-3",
		Mode:           ModeEncrypted,
		EncryptedInput: json.RawMessage(`{"ciphertext":[1,2,3]}`),
		MaxTokens:      128,
		Temperature:    70,
		Seed:           42,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal InferRequest: %v", err)
	}

	var got InferRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal InferRequest: %v", err)
	}

	if got.ModelID != req.ModelID {
		t.Errorf("ModelID = %q, want %q", got.ModelID, req.ModelID)
	}
	if got.Mode != req.Mode {
		t.Errorf("Mode = %v, want %v", got.Mode, req.Mode)
	}
	if string(got.EncryptedInput) != string(req.EncryptedInput) {
		t.Errorf("EncryptedInput = %s, want %s", got.EncryptedInput, req.EncryptedInput)
	}
	if got.MaxTokens != req.MaxTokens {
		t.Errorf("MaxTokens = %d, want %d", got.MaxTokens, req.MaxTokens)
	}
	if got.Temperature != req.Temperature {
		t.Errorf("Temperature = %d, want %d", got.Temperature, req.Temperature)
	}
	if got.Seed != req.Seed {
		t.Errorf("Seed = %d, want %d", got.Seed, req.Seed)
	}
}

func TestInferResponseJSON(t *testing.T) {
	resp := InferResponse{
		EncryptedOutput: json.RawMessage(`{"result":[4,5,6]}`),
		Proof:           json.RawMessage(`{"HashIvc":{"chain_tip":[0]}}`),
		ModelID:         "hermes-3",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal InferResponse: %v", err)
	}

	var got InferResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal InferResponse: %v", err)
	}

	if got.ModelID != resp.ModelID {
		t.Errorf("ModelID = %q, want %q", got.ModelID, resp.ModelID)
	}
	if string(got.EncryptedOutput) != string(resp.EncryptedOutput) {
		t.Errorf("EncryptedOutput = %s, want %s", got.EncryptedOutput, resp.EncryptedOutput)
	}
	if string(got.Proof) != string(resp.Proof) {
		t.Errorf("Proof = %s, want %s", got.Proof, resp.Proof)
	}
}

func TestParseWireProof(t *testing.T) {
	// Build a wire proof with integer-array hashes, matching Rust serde output.
	chainTip := make([]int, 32)
	for i := range chainTip {
		chainTip[i] = i
	}
	merkleRoot := make([]int, 32)
	for i := range merkleRoot {
		merkleRoot[i] = 31 - i
	}
	codeHash := make([]int, 32)
	for i := range codeHash {
		codeHash[i] = i * 2 % 256
	}

	wire := map[string]interface{}{
		"HashIvc": map[string]interface{}{
			"chain_tip":    chainTip,
			"merkle_root":  merkleRoot,
			"step_count":   3,
			"code_hash":    codeHash,
			"privacy_mode": "Transparent",
		},
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire proof: %v", err)
	}

	proof, err := ParseWireProof(raw)
	if err != nil {
		t.Fatalf("ParseWireProof: %v", err)
	}

	if proof.StepCount != 3 {
		t.Errorf("StepCount = %d, want 3", proof.StepCount)
	}
	if proof.Privacy != Transparent {
		t.Errorf("Privacy = %v, want Transparent", proof.Privacy)
	}
	// Verify chain_tip bytes match.
	for i := 0; i < 32; i++ {
		if proof.ChainTip[i] != byte(i) {
			t.Errorf("ChainTip[%d] = %d, want %d", i, proof.ChainTip[i], i)
			break
		}
	}
	if proof.BlindingCommitment != nil {
		t.Error("BlindingCommitment should be nil for Transparent")
	}
}

func TestParseWireProofWithBlinding(t *testing.T) {
	blinding := make([]int, 32)
	for i := range blinding {
		blinding[i] = 0xFF
	}
	wire := map[string]interface{}{
		"HashIvc": map[string]interface{}{
			"chain_tip":            make([]int, 32),
			"merkle_root":         make([]int, 32),
			"step_count":          1,
			"code_hash":           make([]int, 32),
			"privacy_mode":        "Private",
			"blinding_commitment": blinding,
		},
	}
	raw, _ := json.Marshal(wire)

	proof, err := ParseWireProof(raw)
	if err != nil {
		t.Fatalf("ParseWireProof: %v", err)
	}
	if proof.Privacy != Private {
		t.Errorf("Privacy = %v, want Private", proof.Privacy)
	}
	if proof.BlindingCommitment == nil {
		t.Fatal("BlindingCommitment should not be nil for Private")
	}
	for i := 0; i < 32; i++ {
		if proof.BlindingCommitment[i] != 0xFF {
			t.Errorf("BlindingCommitment[%d] = %d, want 255", i, proof.BlindingCommitment[i])
			break
		}
	}
}

func TestMarshalWireProof(t *testing.T) {
	// Build a proof, marshal to wire, parse back, compare.
	original := &VerifiedProof{
		StepCount: 5,
		Privacy:   PrivateInputs,
	}
	for i := 0; i < 32; i++ {
		original.ChainTip[i] = byte(i)
		original.MerkleRoot[i] = byte(31 - i)
		original.CodeHash[i] = byte(i * 3 % 256)
	}

	raw, err := MarshalWireProof(original)
	if err != nil {
		t.Fatalf("MarshalWireProof: %v", err)
	}

	roundtrip, err := ParseWireProof(raw)
	if err != nil {
		t.Fatalf("ParseWireProof after marshal: %v", err)
	}

	if roundtrip.StepCount != original.StepCount {
		t.Errorf("StepCount = %d, want %d", roundtrip.StepCount, original.StepCount)
	}
	if roundtrip.Privacy != original.Privacy {
		t.Errorf("Privacy = %v, want %v", roundtrip.Privacy, original.Privacy)
	}
	if roundtrip.ChainTip != original.ChainTip {
		t.Error("ChainTip mismatch after roundtrip")
	}
	if roundtrip.MerkleRoot != original.MerkleRoot {
		t.Error("MerkleRoot mismatch after roundtrip")
	}
	if roundtrip.CodeHash != original.CodeHash {
		t.Error("CodeHash mismatch after roundtrip")
	}
}

func TestMockEncryptionRoundtrip(t *testing.T) {
	var enc MockEncryption
	pk, sk := enc.Keygen()

	if len(pk) != 32 || len(sk) != 32 {
		t.Fatalf("key lengths: pk=%d, sk=%d, want 32 each", len(pk), len(sk))
	}

	tokens := []uint32{100, 200, 300, 42}
	ciphertext := enc.Encrypt(tokens, pk)
	recovered := enc.Decrypt(ciphertext, sk)

	if len(recovered) != len(tokens) {
		t.Fatalf("recovered %d tokens, want %d", len(recovered), len(tokens))
	}
	for i, v := range recovered {
		if v != tokens[i] {
			t.Errorf("recovered[%d] = %d, want %d", i, v, tokens[i])
		}
	}
}

func TestMockCiphertextJSON(t *testing.T) {
	ct := MockCiphertext{Tokens: []uint32{1, 2, 3}}
	data, err := json.Marshal(ct)
	if err != nil {
		t.Fatalf("marshal MockCiphertext: %v", err)
	}

	var got MockCiphertext
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal MockCiphertext: %v", err)
	}

	if len(got.Tokens) != 3 || got.Tokens[0] != 1 || got.Tokens[1] != 2 || got.Tokens[2] != 3 {
		t.Errorf("roundtrip MockCiphertext = %v, want [1,2,3]", got.Tokens)
	}
}
