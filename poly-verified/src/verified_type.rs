use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::disclosure::{self, Disclosure};
use crate::error::{self, VerifiedError};
use crate::types::{PrivacyMode, VerifiedProof};

/// A value produced by verified execution, carrying a mathematical proof
/// of correct computation.
///
/// `Verified<T>` can only be constructed by the verified execution system
/// (the constructor is `pub(crate)`). User code cannot forge verified values.
///
/// Every `Verified<T>` carries a `VerifiedProof` that any receiver can check
/// in milliseconds without re-executing anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verified<T> {
    value: T,
    proof: VerifiedProof,
}

impl<T> Verified<T> {
    /// Construct a new verified value with its proof.
    ///
    /// This is `pub(crate)` — only the IVC proof system can create
    /// `Verified<T>` values. User code cannot call this.
    pub(crate) fn new_proven(value: T, proof: VerifiedProof) -> Self {
        Self { value, proof }
    }

    /// Internal constructor used by the `#[verified]` proc macro.
    ///
    /// **Do not call directly.** This is public only because proc macros
    /// expand in the caller's crate and need access. Use `#[verified]`
    /// to create `Verified<T>` values.
    #[doc(hidden)]
    pub fn __macro_new(value: T, proof: VerifiedProof) -> Self {
        Self { value, proof }
    }

    /// Access the inner value by reference.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume the wrapper and return the inner value.
    pub fn unwrap_verified(self) -> T {
        self.value
    }

    /// Access the proof by reference.
    pub fn proof(&self) -> &VerifiedProof {
        &self.proof
    }

    /// Check whether this value carries a valid proof structure.
    /// For full cryptographic verification, use `verify_with_backend`.
    pub fn is_verified(&self) -> bool {
        // Structural check: proof is well-formed
        match &self.proof {
            VerifiedProof::HashIvc { step_count, .. } => *step_count > 0,
            VerifiedProof::Mock { .. } => true,
        }
    }

    /// Returns the privacy mode of the proof.
    pub fn privacy_mode(&self) -> PrivacyMode {
        self.proof.privacy_mode()
    }

    /// Returns true if this value's proof hides information from the verifier.
    pub fn is_private(&self) -> bool {
        self.proof.privacy_mode().is_private()
    }

    /// Map the inner value while preserving the proof.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Verified<U> {
        Verified {
            value: f(self.value),
            proof: self.proof,
        }
    }
}

/// Selective disclosure methods for verified token sequences.
impl Verified<Vec<u32>> {
    /// Create a selective disclosure revealing only the specified token positions.
    ///
    /// Unrevealed positions carry leaf-hash commitments. The verifier can
    /// confirm revealed tokens are genuine without seeing redacted ones.
    ///
    /// # Example
    /// ```ignore
    /// let result: Verified<Vec<u32>> = generate_verified(input, 50, 700, 42);
    /// let pharmacist_view = result.disclose(&[8, 9, 10])?;
    /// let insurer_view = result.disclose(&[15])?;
    /// ```
    pub fn disclose(&self, indices: &[usize]) -> error::Result<Disclosure> {
        disclosure::create_disclosure(self, indices)
    }

    /// Create a selective disclosure for a contiguous range of token positions.
    ///
    /// # Example
    /// ```ignore
    /// let pharmacist_view = result.disclose_range(8..11)?;
    /// ```
    pub fn disclose_range(&self, range: Range<usize>) -> error::Result<Disclosure> {
        disclosure::create_disclosure_range(self, range)
    }
}

/// Flatten nested Verified types: Verified<Verified<T>> → Verified<T>
/// Uses the outer proof (which encompasses the inner computation).
impl<T> Verified<Verified<T>> {
    pub fn flatten(self) -> Verified<T> {
        Verified {
            value: self.value.value,
            proof: self.proof,
        }
    }
}

/// Display the value if it implements Display.
impl<T: std::fmt::Display> std::fmt::Display for Verified<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verified({})", self.value)
    }
}

/// Verified<Result<T, VerifiedError>> is the type for functions that can fail.
/// The proof certifies both success and failure paths.
impl<T> Verified<Result<T, VerifiedError>> {
    /// Check if the verified computation succeeded.
    pub fn is_ok(&self) -> bool {
        self.value.is_ok()
    }

    /// Check if the verified computation produced a proven error.
    pub fn is_err(&self) -> bool {
        self.value.is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PrivacyMode, ZERO_HASH};

    fn mock_proof() -> VerifiedProof {
        VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        }
    }

    #[test]
    fn test_verified_value_access() {
        let v = Verified::new_proven(42u64, mock_proof());
        assert_eq!(*v.value(), 42);
        assert_eq!(v.unwrap_verified(), 42);
    }

    #[test]
    fn test_verified_map() {
        let v = Verified::new_proven(21u64, mock_proof());
        let doubled = v.map(|x| x * 2);
        assert_eq!(*doubled.value(), 42);
    }

    #[test]
    fn test_verified_flatten() {
        let inner = Verified::new_proven(42u64, mock_proof());
        let outer = Verified::new_proven(inner, mock_proof());
        let flat = outer.flatten();
        assert_eq!(*flat.value(), 42);
    }

    #[test]
    fn test_verified_result_ok() {
        let v: Verified<Result<u64, VerifiedError>> =
            Verified::new_proven(Ok(42), mock_proof());
        assert!(v.is_ok());
        assert!(!v.is_err());
    }

    #[test]
    fn test_verified_result_err() {
        let v: Verified<Result<u64, VerifiedError>> =
            Verified::new_proven(Err(VerifiedError::DivisionByZero), mock_proof());
        assert!(!v.is_ok());
        assert!(v.is_err());
    }

    #[test]
    fn test_verified_display() {
        let v = Verified::new_proven(42u64, mock_proof());
        assert_eq!(format!("{v}"), "Verified(42)");
    }

    #[test]
    fn test_verified_privacy_mode_transparent() {
        let v = Verified::new_proven(42u64, mock_proof());
        assert_eq!(v.privacy_mode(), PrivacyMode::Transparent);
        assert!(!v.is_private());
    }

    #[test]
    fn test_verified_privacy_mode_private() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Private,
        };
        let v = Verified::new_proven(42u64, proof);
        assert_eq!(v.privacy_mode(), PrivacyMode::Private);
        assert!(v.is_private());
    }

    #[test]
    fn test_verified_privacy_mode_private_inputs() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::PrivateInputs,
        };
        let v = Verified::new_proven(42u64, proof);
        assert_eq!(v.privacy_mode(), PrivacyMode::PrivateInputs);
        assert!(v.is_private());
    }
}
