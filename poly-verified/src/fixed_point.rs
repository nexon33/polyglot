use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

use serde::{Deserialize, Serialize};

/// Deterministic fixed-point arithmetic using 128-bit integers.
///
/// `FixedPoint` uses `i128` internally with 48 fractional bits by default.
/// All operations are integer arithmetic — deterministic across all platforms.
/// No floating point is used anywhere.
///
/// # Example
/// ```
/// use poly_verified::fixed_point::FixedPoint;
///
/// let a = FixedPoint::from_int(3);
/// let b = FixedPoint::from_int(7);
/// let result = a * b;
/// assert_eq!(result.to_i64(), 21);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FixedPoint {
    raw: i128,
}

/// Number of fractional bits (Q80.48 format).
const FRAC_BITS: u32 = 48;
const SCALE: i128 = 1i128 << FRAC_BITS;

impl FixedPoint {
    /// The internal scale factor (2^48).
    pub const SCALE: i128 = SCALE;

    /// Zero.
    pub const ZERO: Self = Self { raw: 0 };

    /// One.
    pub const ONE: Self = Self { raw: SCALE };

    /// Create from an integer value.
    pub fn from_int(v: i64) -> Self {
        Self {
            raw: (v as i128) * SCALE,
        }
    }

    /// Create from a raw internal representation.
    pub fn from_raw(raw: i128) -> Self {
        Self { raw }
    }

    /// Create from a decimal: `from_decimal(150, 2)` = 1.50
    pub fn from_decimal(value: i64, decimal_places: u32) -> Self {
        let divisor = 10i128.pow(decimal_places);
        Self {
            raw: (value as i128) * SCALE / divisor,
        }
    }

    /// Get the raw internal representation.
    pub fn raw(&self) -> i128 {
        self.raw
    }

    /// Convert to i64, truncating the fractional part.
    pub fn to_i64(&self) -> i64 {
        (self.raw / SCALE) as i64
    }

    /// Convert to u64, saturating at 0 and u64::MAX.
    pub fn to_u64_saturating(&self) -> u64 {
        let int = self.raw / SCALE;
        if int < 0 {
            0
        } else if int > u64::MAX as i128 {
            u64::MAX
        } else {
            int as u64
        }
    }

    /// Saturating addition: clamps at i128 bounds instead of panicking.
    pub fn saturating_add(self, rhs: Self) -> Self {
        Self {
            raw: self.raw.saturating_add(rhs.raw),
        }
    }

    /// Saturating subtraction.
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self {
            raw: self.raw.saturating_sub(rhs.raw),
        }
    }

    /// Checked multiplication: returns None on overflow.
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        // Use wider arithmetic to detect overflow
        // (i128 * i128) / SCALE
        // We need to check for overflow before division
        let product = self.raw.checked_mul(rhs.raw)?;
        Some(Self {
            raw: product / SCALE,
        })
    }

    /// Checked division: returns None on division by zero.
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.raw == 0 {
            return None;
        }
        let numerator = self.raw.checked_mul(SCALE)?;
        Some(Self {
            raw: numerator / rhs.raw,
        })
    }

    /// Absolute value. Saturates at i128::MAX for i128::MIN (no panic).
    pub fn abs(self) -> Self {
        Self {
            raw: self.raw.saturating_abs(),
        }
    }

    /// Approximate e^x using Taylor series expansion.
    /// `terms` controls precision (more terms = more accurate).
    pub fn exp_approx(self, terms: u32) -> Self {
        let mut result = Self::ONE;
        let mut term = Self::ONE;

        for i in 1..=terms {
            term = match term.checked_mul(self) {
                Some(t) => match t.checked_div(Self::from_int(i as i64)) {
                    Some(d) => d,
                    None => break,
                },
                None => break,
            };
            result = result.saturating_add(term);
        }

        result
    }
}

impl Add for FixedPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            raw: self.raw.saturating_add(rhs.raw),
        }
    }
}

impl Sub for FixedPoint {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            raw: self.raw.saturating_sub(rhs.raw),
        }
    }
}

impl Mul for FixedPoint {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        // Use checked_mul to detect overflow; saturate on failure.
        match self.raw.checked_mul(rhs.raw) {
            Some(product) => Self {
                raw: product / SCALE,
            },
            None => {
                // Determine sign of result and saturate.
                let positive = (self.raw >= 0) == (rhs.raw >= 0);
                Self {
                    raw: if positive { i128::MAX } else { i128::MIN },
                }
            }
        }
    }
}

impl Div for FixedPoint {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        assert!(rhs.raw != 0, "division by zero");
        // Use checked_mul to prevent overflow in numerator scaling.
        match self.raw.checked_mul(SCALE) {
            Some(numerator) => Self {
                raw: numerator / rhs.raw,
            },
            None => {
                // Numerator overflow: saturate based on sign.
                let positive = (self.raw >= 0) == (rhs.raw >= 0);
                Self {
                    raw: if positive { i128::MAX } else { i128::MIN },
                }
            }
        }
    }
}

impl Neg for FixedPoint {
    type Output = Self;
    fn neg(self) -> Self {
        // Saturate instead of panicking on i128::MIN.
        Self {
            raw: self.raw.saturating_neg(),
        }
    }
}

impl fmt::Debug for FixedPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let int_part = self.raw / SCALE;
        let frac_part = ((self.raw % SCALE).abs() * 1_000_000) / SCALE;
        write!(f, "FixedPoint({int_part}.{frac_part:06})")
    }
}

impl fmt::Display for FixedPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let int_part = self.raw / SCALE;
        let frac_part = ((self.raw % SCALE).abs() * 1_000_000) / SCALE;
        if frac_part == 0 {
            write!(f, "{int_part}")
        } else {
            write!(f, "{int_part}.{frac_part:06}")
        }
    }
}

impl From<i64> for FixedPoint {
    fn from(v: i64) -> Self {
        Self::from_int(v)
    }
}

impl From<u64> for FixedPoint {
    fn from(v: u64) -> Self {
        Self {
            raw: (v as i128) * SCALE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = FixedPoint::from_int(3);
        let b = FixedPoint::from_int(7);

        assert_eq!((a + b).to_i64(), 10);
        assert_eq!((b - a).to_i64(), 4);
        assert_eq!((a * b).to_i64(), 21);
        assert_eq!((b / a).to_i64(), 2); // 7/3 = 2 (truncated)
    }

    #[test]
    fn test_from_decimal() {
        let half = FixedPoint::from_decimal(50, 2); // 0.50
        let result = half * FixedPoint::from_int(100);
        assert_eq!(result.to_i64(), 50);
    }

    #[test]
    fn test_saturating_add() {
        let big = FixedPoint::from_raw(i128::MAX - 1);
        let one = FixedPoint::from_int(1);
        let result = big.saturating_add(one);
        assert_eq!(result.raw(), i128::MAX);
    }

    #[test]
    fn test_checked_div_zero() {
        let a = FixedPoint::from_int(42);
        let zero = FixedPoint::ZERO;
        assert!(a.checked_div(zero).is_none());
    }

    #[test]
    fn test_negation() {
        let a = FixedPoint::from_int(5);
        assert_eq!((-a).to_i64(), -5);
    }

    #[test]
    fn test_to_u64_saturating() {
        let neg = FixedPoint::from_int(-5);
        assert_eq!(neg.to_u64_saturating(), 0);

        let pos = FixedPoint::from_int(42);
        assert_eq!(pos.to_u64_saturating(), 42);
    }

    #[test]
    fn test_exp_approx() {
        // e^1 ≈ 2.718...
        let e = FixedPoint::ONE.exp_approx(20);
        let result = e.to_i64();
        assert_eq!(result, 2); // truncated integer part
        // More precise check: raw value should be close to 2.718 * SCALE
        let expected_min = FixedPoint::from_decimal(271, 2).raw();
        let expected_max = FixedPoint::from_decimal(272, 2).raw();
        assert!(e.raw() >= expected_min && e.raw() <= expected_max);
    }

    #[test]
    fn test_determinism() {
        // Same inputs must always produce same outputs
        for i in 0..100 {
            let a = FixedPoint::from_int(i);
            let b = FixedPoint::from_int(i + 1);
            let r1 = a * b + a;
            let r2 = a * b + a;
            assert_eq!(r1, r2);
        }
    }

    #[test]
    fn test_display() {
        let v = FixedPoint::from_int(42);
        assert_eq!(format!("{v}"), "42");
    }
}
