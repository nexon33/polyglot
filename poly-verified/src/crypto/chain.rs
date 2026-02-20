use crate::crypto::hash::hash_chain_step;
use crate::types::{Hash, ZERO_HASH};

/// Sequential hash chain providing tamper-evident, order-dependent commitment.
#[derive(Clone, Debug)]
pub struct HashChain {
    pub tip: Hash,
    pub length: u64,
}

impl HashChain {
    pub fn new() -> Self {
        Self {
            tip: ZERO_HASH,
            length: 0,
        }
    }

    /// Append a state hash: tip := hash_chain_step(tip, state_hash).
    ///
    /// [V11-03 FIX] Uses checked_add to prevent u64 overflow. Panics on
    /// overflow rather than silently wrapping to 0, which would break
    /// the step_count == checkpoints.len() invariant in proof verification.
    pub fn append(&mut self, state_hash: &Hash) {
        self.tip = hash_chain_step(&self.tip, state_hash);
        self.length = self
            .length
            .checked_add(1)
            .expect("HashChain: length overflow (exceeded u64::MAX steps)");
    }
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;

    // Appendix B.3: hash chain test vectors
    // Note: spec B.3 uses hash_combine (pre-domain-separation). Our implementation
    // uses hash_chain_step (domain-separated). The test verifies internal consistency.
    #[test]
    fn test_chain_initial_state() {
        let chain = HashChain::new();
        assert_eq!(chain.tip, ZERO_HASH);
        assert_eq!(chain.length, 0);
    }

    #[test]
    fn test_chain_append_one() {
        let mut chain = HashChain::new();
        let h0 = hash_data(&[0x00]);
        chain.append(&h0);

        assert_eq!(chain.length, 1);
        // tip_1 = hash_chain_step(ZERO_HASH, hash_data([0x00]))
        let expected = hash_chain_step(&ZERO_HASH, &h0);
        assert_eq!(chain.tip, expected);
    }

    #[test]
    fn test_chain_append_two() {
        let mut chain = HashChain::new();
        let h0 = hash_data(&[0x00]);
        let h1 = hash_data(&[0x01]);
        chain.append(&h0);
        chain.append(&h1);

        assert_eq!(chain.length, 2);
        let tip1 = hash_chain_step(&ZERO_HASH, &h0);
        let tip2 = hash_chain_step(&tip1, &h1);
        assert_eq!(chain.tip, tip2);
    }

    #[test]
    fn test_chain_order_dependent() {
        let h0 = hash_data(&[0x00]);
        let h1 = hash_data(&[0x01]);

        let mut chain_a = HashChain::new();
        chain_a.append(&h0);
        chain_a.append(&h1);

        let mut chain_b = HashChain::new();
        chain_b.append(&h1);
        chain_b.append(&h0);

        assert_ne!(chain_a.tip, chain_b.tip);
    }
}
