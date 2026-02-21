package verified

import "fmt"

// ProofError represents proof system errors.
type ProofError struct {
	Kind   string
	Detail string
}

func (e *ProofError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Kind, e.Detail)
	}
	return e.Kind
}

// Sentinel errors matching Rust ProofSystemError variants.
var (
	ErrInvalidProof              = &ProofError{Kind: "invalid proof"}
	ErrMerkleVerificationFailed  = &ProofError{Kind: "merkle proof verification failed"}
	ErrRootMismatch              = &ProofError{Kind: "root mismatch: proof root does not match commitment root"}
	ErrIndexOutOfBounds          = &ProofError{Kind: "index out of bounds"}
	ErrEmptyCommitment           = &ProofError{Kind: "empty commitment"}
	ErrIvcFoldError              = &ProofError{Kind: "IVC fold error"}
	ErrSignatureVerificationFailed = &ProofError{Kind: "signature verification failed"}
)

// NewIndexOutOfBoundsError returns an index-out-of-bounds error with details.
func NewIndexOutOfBoundsError(index, length int) *ProofError {
	return &ProofError{
		Kind:   "index out of bounds",
		Detail: fmt.Sprintf("%d >= %d", index, length),
	}
}
