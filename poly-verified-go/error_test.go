package verified

import "testing"

func TestProofErrorFormatting(t *testing.T) {
	e := &ProofError{Kind: "invalid proof", Detail: "step count zero"}
	if e.Error() != "invalid proof: step count zero" {
		t.Fatalf("got %q", e.Error())
	}
}

func TestProofErrorNoDetail(t *testing.T) {
	if ErrEmptyCommitment.Error() != "empty commitment" {
		t.Fatalf("got %q", ErrEmptyCommitment.Error())
	}
}

func TestIndexOutOfBoundsError(t *testing.T) {
	e := NewIndexOutOfBoundsError(8, 5)
	if e.Error() != "index out of bounds: 8 >= 5" {
		t.Fatalf("got %q", e.Error())
	}
}

func TestSentinelErrors(t *testing.T) {
	sentinels := []*ProofError{
		ErrInvalidProof,
		ErrMerkleVerificationFailed,
		ErrRootMismatch,
		ErrIndexOutOfBounds,
		ErrEmptyCommitment,
		ErrIvcFoldError,
		ErrSignatureVerificationFailed,
	}
	for _, s := range sentinels {
		if s.Error() == "" {
			t.Fatalf("sentinel error should have non-empty message")
		}
	}
}
