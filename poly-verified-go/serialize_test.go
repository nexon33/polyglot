package verified

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHexHashMarshalJSON(t *testing.T) {
	var h HexHash
	for i := range h {
		h[i] = byte(i)
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
		t.Fatalf("expected quoted string, got %s", s)
	}
	inner := s[1 : len(s)-1]
	if len(inner) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(inner))
	}
}

func TestHexHashUnmarshalJSON(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var h HexHash
		input := `"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`
		if err := json.Unmarshal([]byte(input), &h); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 32; i++ {
			if h[i] != byte(i) {
				t.Fatalf("byte %d: got %d, want %d", i, h[i], i)
			}
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		var h HexHash
		input := `"0001020304"`
		if err := json.Unmarshal([]byte(input), &h); err == nil {
			t.Fatal("should reject wrong-length hex")
		}
	})
}

func TestHexHashRoundtrip(t *testing.T) {
	var original HexHash
	for i := range original {
		original[i] = byte(0xAB ^ i)
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HexHash
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if original != decoded {
		t.Fatal("roundtrip mismatch")
	}
}

func TestToJSON(t *testing.T) {
	codeHash := HashData([]byte("test_code"))
	acc := NewHashIvc(codeHash, Transparent)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("s0")),
		StateAfter:  HashData([]byte("s1")),
		StepInputs:  HashData([]byte("i0")),
	})
	proof, _ := acc.Finalize()

	pj := proof.ToJSON()

	if pj.Backend != "HashIvc" {
		t.Fatalf("backend = %q, want HashIvc", pj.Backend)
	}
	if pj.StepCount != 1 {
		t.Fatalf("step_count = %d, want 1", pj.StepCount)
	}
	if pj.PrivacyMode != "transparent" {
		t.Fatalf("privacy_mode = %q, want transparent", pj.PrivacyMode)
	}
	if !pj.QuantumResistant {
		t.Fatal("quantum_resistant should be true")
	}
	if !pj.Verified {
		t.Fatal("verified should be true")
	}
	if pj.BlindingCommitment != nil {
		t.Fatal("blinding should be nil for transparent")
	}
	if len(pj.ChainTip) != 64 {
		t.Fatalf("chain_tip hex length = %d, want 64", len(pj.ChainTip))
	}
	if len(pj.MerkleRoot) != 64 {
		t.Fatalf("merkle_root hex length = %d, want 64", len(pj.MerkleRoot))
	}
	if len(pj.CodeHash) != 64 {
		t.Fatalf("code_hash hex length = %d, want 64", len(pj.CodeHash))
	}
}

func TestToJSONPrivateMode(t *testing.T) {
	codeHash := HashData([]byte("private_code"))
	acc := NewHashIvc(codeHash, Private)
	acc.FoldStep(StepWitness{
		StateBefore: HashData([]byte("s0")),
		StateAfter:  HashData([]byte("s1")),
		StepInputs:  HashData([]byte("i0")),
	})
	proof, _ := acc.Finalize()

	pj := proof.ToJSON()

	if pj.PrivacyMode != "private" {
		t.Fatalf("privacy_mode = %q, want private", pj.PrivacyMode)
	}
	zeroHex := strings.Repeat("0", 64)
	if pj.CodeHash != zeroHex {
		t.Fatalf("code_hash should be all zeros in private mode, got %s", pj.CodeHash)
	}
	if pj.BlindingCommitment == nil {
		t.Fatal("blinding should be present for private mode")
	}
	if len(*pj.BlindingCommitment) != 64 {
		t.Fatalf("blinding hex length = %d, want 64", len(*pj.BlindingCommitment))
	}
}

func TestNewVerificationResponse(t *testing.T) {
	inputHash := HashData([]byte("input"))
	outputHash := HashData([]byte("output"))

	t.Run("transparent", func(t *testing.T) {
		proof := &VerifiedProof{StepCount: 1, Privacy: Transparent}
		vr := NewVerificationResponse(proof, inputHash, outputHash, "model-v1")
		if vr.InputHash == nil {
			t.Fatal("transparent should include input_hash")
		}
		if vr.OutputHash == nil {
			t.Fatal("transparent should include output_hash")
		}
		if vr.ModelID != "model-v1" {
			t.Fatalf("model_id = %q, want model-v1", vr.ModelID)
		}
	})

	t.Run("private", func(t *testing.T) {
		bc := HashData([]byte("bc"))
		proof := &VerifiedProof{StepCount: 1, Privacy: Private, BlindingCommitment: &bc}
		vr := NewVerificationResponse(proof, inputHash, outputHash, "model-v1")
		if vr.InputHash != nil {
			t.Fatal("private should hide input_hash")
		}
		if vr.OutputHash != nil {
			t.Fatal("private should hide output_hash")
		}
	})

	t.Run("private_inputs", func(t *testing.T) {
		bc := HashData([]byte("bc"))
		proof := &VerifiedProof{StepCount: 1, Privacy: PrivateInputs, BlindingCommitment: &bc}
		vr := NewVerificationResponse(proof, inputHash, outputHash, "model-v1")
		if vr.InputHash != nil {
			t.Fatal("private_inputs should hide input_hash")
		}
		if vr.OutputHash == nil {
			t.Fatal("private_inputs should expose output_hash")
		}
	})
}

func TestHashToHex(t *testing.T) {
	var h Hash
	for i := range h {
		h[i] = byte(i)
	}
	got := hashToHex(h)
	want := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if got != want {
		t.Fatalf("hashToHex = %q, want %q", got, want)
	}
}
