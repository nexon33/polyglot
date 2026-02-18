package polyclient

import (
	"encoding/json"
	"testing"

	verified "poly-verified-go"
)

func mockWireProof() json.RawMessage {
	proof := &verified.VerifiedProof{
		ChainTip:   [32]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		MerkleRoot: [32]byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		StepCount:  1,
		CodeHash:   [32]byte{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
		Privacy:    verified.Transparent,
	}
	raw, _ := verified.MarshalWireProof(proof)
	return raw
}

func mockServerResponse(tokenIDs []uint32) *verified.InferResponse {
	ct := verified.MockCiphertext{Tokens: tokenIDs}
	encOut, _ := json.Marshal(ct)
	return &verified.InferResponse{
		EncryptedOutput: encOut,
		Proof:           mockWireProof(),
		ModelID:         "Qwen/Qwen3-0.6B",
	}
}

func TestClientCreation(t *testing.T) {
	client := New("Qwen/Qwen3-0.6B", verified.ModeEncrypted, verified.MockEncryption{})
	if client.ModelID() != "Qwen/Qwen3-0.6B" {
		t.Fatalf("model_id = %q", client.ModelID())
	}
	if client.Mode() != verified.ModeEncrypted {
		t.Fatalf("mode = %v", client.Mode())
	}
}

func TestPrepareRequest(t *testing.T) {
	client := New("test-model", verified.ModePrivateProven, verified.MockEncryption{})
	req := client.PrepareRequest([]uint32{100, 200, 300}, 50, 700, 42)

	if req.ModelID != "test-model" {
		t.Fatalf("model_id = %q", req.ModelID)
	}
	if req.Mode != verified.ModePrivateProven {
		t.Fatalf("mode = %v", req.Mode)
	}
	if req.MaxTokens != 50 {
		t.Fatalf("max_tokens = %d", req.MaxTokens)
	}
	if req.Temperature != 700 {
		t.Fatalf("temperature = %d", req.Temperature)
	}
	if req.Seed != 42 {
		t.Fatalf("seed = %d", req.Seed)
	}

	// Encrypted input should deserialize back to original tokens
	var raw json.RawMessage
	if err := json.Unmarshal(req.EncryptedInput, &raw); err != nil {
		t.Fatal(err)
	}
	var ct verified.MockCiphertext
	if err := json.Unmarshal(raw, &ct); err != nil {
		t.Fatal(err)
	}
	if len(ct.Tokens) != 3 || ct.Tokens[0] != 100 || ct.Tokens[1] != 200 || ct.Tokens[2] != 300 {
		t.Fatalf("tokens = %v", ct.Tokens)
	}
}

func TestProcessResponse(t *testing.T) {
	client := New("test-model", verified.ModeTransparent, verified.MockEncryption{})
	outputTokens := []uint32{100, 200, 300, 400, 500}
	resp := mockServerResponse(outputTokens)

	vr, err := client.ProcessResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	if len(vr.TokenIDs) != 5 {
		t.Fatalf("token count = %d, want 5", len(vr.TokenIDs))
	}
	for i, expected := range outputTokens {
		if vr.TokenIDs[i] != expected {
			t.Fatalf("token[%d] = %d, want %d", i, vr.TokenIDs[i], expected)
		}
	}
	if !vr.IsVerified() {
		t.Fatal("response should verify")
	}
}

func TestFullProtocolFlow(t *testing.T) {
	modes := []verified.Mode{
		verified.ModeTransparent,
		verified.ModePrivateProven,
		verified.ModePrivate,
		verified.ModeEncrypted,
	}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			client := New("Qwen/Qwen3-0.6B", mode, verified.MockEncryption{})
			inputTokens := []uint32{1, 2, 3, 4, 5}
			req := client.PrepareRequest(inputTokens, 50, 700, 42)

			// "Server" processes: decrypt input, append generated tokens
			var raw json.RawMessage
			if err := json.Unmarshal(req.EncryptedInput, &raw); err != nil {
				t.Fatal(err)
			}
			var ct verified.MockCiphertext
			if err := json.Unmarshal(raw, &ct); err != nil {
				t.Fatal(err)
			}
			output := append(ct.Tokens, 10, 20, 30, 40, 50)
			resp := mockServerResponse(output)

			vr, err := client.ProcessResponse(resp)
			if err != nil {
				t.Fatal(err)
			}
			if len(vr.TokenIDs) != 10 {
				t.Fatalf("output tokens = %d, want 10", len(vr.TokenIDs))
			}
			if !vr.IsVerified() {
				t.Fatal("response should verify")
			}
		})
	}
}

func TestSelectiveDisclosureFromResponse(t *testing.T) {
	client := New("test-model", verified.ModePrivateProven, verified.MockEncryption{})
	outputTokens := []uint32{100, 200, 300, 400, 500, 600, 700, 800}
	resp := mockServerResponse(outputTokens)
	vr, err := client.ProcessResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	// Pharmacist sees tokens 1..4
	pharmacist, err := vr.Disclose([]int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.VerifyDisclosure(pharmacist) {
		t.Fatal("pharmacist disclosure should verify")
	}
	if len(pharmacist.Proofs) != 3 {
		t.Fatalf("pharmacist proofs = %d, want 3", len(pharmacist.Proofs))
	}

	// Insurer sees token 6
	insurer, err := vr.Disclose([]int{6})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.VerifyDisclosure(insurer) {
		t.Fatal("insurer disclosure should verify")
	}
	if len(insurer.Proofs) != 1 {
		t.Fatalf("insurer proofs = %d, want 1", len(insurer.Proofs))
	}

	// Same output root
	if pharmacist.OutputRoot != insurer.OutputRoot {
		t.Fatal("output roots should match")
	}
}

func TestDisclosureRangeFromResponse(t *testing.T) {
	client := New("test-model", verified.ModePrivate, verified.MockEncryption{})
	outputTokens := []uint32{10, 20, 30, 40, 50}
	resp := mockServerResponse(outputTokens)
	vr, err := client.ProcessResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	d, err := vr.DiscloseRange(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.VerifyDisclosure(d) {
		t.Fatal("range disclosure should verify")
	}
	if len(d.Proofs) != 2 {
		t.Fatalf("proofs = %d, want 2", len(d.Proofs))
	}
}

func TestEmptyResponse(t *testing.T) {
	client := New("test-model", verified.ModeTransparent, verified.MockEncryption{})
	resp := mockServerResponse([]uint32{})
	vr, err := client.ProcessResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(vr.TokenIDs) != 0 {
		t.Fatalf("expected empty tokens, got %d", len(vr.TokenIDs))
	}
}

func TestLargeInput(t *testing.T) {
	client := New("test-model", verified.ModeEncrypted, verified.MockEncryption{})
	tokens := make([]uint32, 10000)
	for i := range tokens {
		tokens[i] = uint32(i)
	}
	req := client.PrepareRequest(tokens, 100, 700, 42)

	var raw json.RawMessage
	if err := json.Unmarshal(req.EncryptedInput, &raw); err != nil {
		t.Fatal(err)
	}
	var ct verified.MockCiphertext
	if err := json.Unmarshal(raw, &ct); err != nil {
		t.Fatal(err)
	}
	if len(ct.Tokens) != 10000 {
		t.Fatalf("token count = %d, want 10000", len(ct.Tokens))
	}
}

func TestModePropagatesInRequest(t *testing.T) {
	modes := []verified.Mode{
		verified.ModeTransparent,
		verified.ModePrivateProven,
		verified.ModePrivate,
		verified.ModeEncrypted,
	}
	for _, mode := range modes {
		client := New("model", mode, verified.MockEncryption{})
		req := client.PrepareRequest([]uint32{1}, 10, 700, 42)
		if req.Mode != mode {
			t.Fatalf("mode = %v, want %v", req.Mode, mode)
		}
	}
}

func TestSerializationRoundtrip(t *testing.T) {
	client := New("test-model", verified.ModeEncrypted, verified.MockEncryption{})
	req := client.PrepareRequest([]uint32{100, 200, 300}, 50, 700, 42)

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	var req2 verified.InferRequest
	if err := json.Unmarshal(data, &req2); err != nil {
		t.Fatal(err)
	}

	if req.ModelID != req2.ModelID {
		t.Fatal("model_id mismatch after roundtrip")
	}
	if req.Mode != req2.Mode {
		t.Fatal("mode mismatch after roundtrip")
	}
	if req.MaxTokens != req2.MaxTokens {
		t.Fatal("max_tokens mismatch after roundtrip")
	}
}
