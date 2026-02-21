package verified

// Verified wraps a value with a cryptographic proof of correct computation.
// The generic parameter T holds the computed result; the proof attests
// that a genuine execution produced it.
type Verified[T any] struct {
	value T
	proof VerifiedProof
}

// NewVerified constructs a Verified wrapper.
func NewVerified[T any](value T, proof VerifiedProof) Verified[T] {
	return Verified[T]{value: value, proof: proof}
}

// Value returns the inner value by reference.
func (v *Verified[T]) Value() T {
	return v.value
}

// Proof returns the execution proof.
func (v *Verified[T]) Proof() *VerifiedProof {
	return &v.proof
}

// IsVerified performs a structural validity check on the proof.
func (v *Verified[T]) IsVerified() bool {
	return v.proof.Verify()
}

// PrivacyMode returns the privacy mode of the proof.
func (v *Verified[T]) PrivacyMode() PrivacyMode {
	return v.proof.Privacy
}

// IsPrivate returns true when the proof hides information from the verifier.
func (v *Verified[T]) IsPrivate() bool {
	return v.proof.Privacy.IsPrivate()
}

// Disclose creates a selective disclosure revealing only specified token positions.
// Top-level function because Go generics disallow method type parameters.
func Disclose(v *Verified[[]uint32], indices []int) (*Disclosure, error) {
	return CreateDisclosure(v, indices)
}

// DiscloseRange creates a selective disclosure for a contiguous range.
func DiscloseRange(v *Verified[[]uint32], start, end int) (*Disclosure, error) {
	return CreateDisclosureRange(v, start, end)
}
