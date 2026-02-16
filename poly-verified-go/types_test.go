package verified

import "testing"

func TestPrivacyModeIsPrivate(t *testing.T) {
	tests := []struct {
		mode PrivacyMode
		want bool
	}{
		{Transparent, false},
		{Private, true},
		{PrivateInputs, true},
	}
	for _, tt := range tests {
		if got := tt.mode.IsPrivate(); got != tt.want {
			t.Fatalf("%v.IsPrivate() = %v, want %v", tt.mode, got, tt.want)
		}
	}
}

func TestPrivacyModeString(t *testing.T) {
	tests := []struct {
		mode PrivacyMode
		want string
	}{
		{Transparent, "transparent"},
		{Private, "private"},
		{PrivateInputs, "private_inputs"},
		{PrivacyMode(0xFF), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Fatalf("PrivacyMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestBackendIDString(t *testing.T) {
	tests := []struct {
		id   BackendID
		want string
	}{
		{BackendMock, "Mock"},
		{BackendHashIvc, "HashIvc"},
		{BackendNova, "Nova"},
		{BackendHyperNova, "HyperNova"},
		{BackendID(0xFF), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.id.String(); got != tt.want {
			t.Fatalf("BackendID(%d).String() = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestVerifiedProofBackendID(t *testing.T) {
	proof := &VerifiedProof{}
	if got := proof.BackendID(); got != BackendHashIvc {
		t.Fatalf("BackendID() = %v, want BackendHashIvc", got)
	}
}

func TestVerifiedProofIsQuantumResistant(t *testing.T) {
	proof := &VerifiedProof{}
	if !proof.IsQuantumResistant() {
		t.Fatal("IsQuantumResistant() should return true")
	}
}

func TestPublicCodeHashPrivacyBehavior(t *testing.T) {
	codeHash := HashData([]byte("my_code"))

	transparent := &VerifiedProof{CodeHash: codeHash, Privacy: Transparent}
	if transparent.PublicCodeHash() != codeHash {
		t.Fatal("Transparent should expose real code hash")
	}

	privateInputs := &VerifiedProof{CodeHash: codeHash, Privacy: PrivateInputs}
	if privateInputs.PublicCodeHash() != codeHash {
		t.Fatal("PrivateInputs should expose real code hash")
	}

	private := &VerifiedProof{CodeHash: codeHash, Privacy: Private}
	if private.PublicCodeHash() != ZeroHash {
		t.Fatal("Private should return ZeroHash")
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	t.Run("zero steps rejected", func(t *testing.T) {
		p := &VerifiedProof{StepCount: 0, Privacy: Transparent}
		if p.Verify() {
			t.Fatal("should reject zero steps")
		}
	})

	t.Run("private without blinding rejected", func(t *testing.T) {
		p := &VerifiedProof{StepCount: 1, Privacy: Private, BlindingCommitment: nil}
		if p.Verify() {
			t.Fatal("should reject Private without blinding")
		}
	})

	t.Run("transparent valid", func(t *testing.T) {
		p := &VerifiedProof{StepCount: 1, Privacy: Transparent}
		if !p.Verify() {
			t.Fatal("transparent with steps should verify")
		}
	})

	t.Run("private with blinding valid", func(t *testing.T) {
		bc := HashData([]byte("blinding"))
		p := &VerifiedProof{StepCount: 1, Privacy: Private, BlindingCommitment: &bc}
		if !p.Verify() {
			t.Fatal("private with blinding should verify")
		}
	})

	t.Run("private_inputs with blinding valid", func(t *testing.T) {
		bc := HashData([]byte("blinding"))
		p := &VerifiedProof{StepCount: 1, Privacy: PrivateInputs, BlindingCommitment: &bc}
		if !p.Verify() {
			t.Fatal("private_inputs with blinding should verify")
		}
	})
}
