use poly_verified::crypto::merkle::MerkleTree;
use poly_verified::types::{Hash, ZERO_HASH};
use serde::{Deserialize, Serialize};

use crate::error::{ChainError, Result};
use crate::primitives::*;
use crate::transaction::Transaction;

/// Block header — fixed-size summary of a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: BlockHeight,
    pub timestamp: Timestamp,
    pub prev_block_hash: Hash,
    pub state_root: Hash,
    /// Merkle root of transaction hashes in this block.
    pub transactions_root: Hash,
    pub tx_count: u32,
}

impl BlockHeader {
    /// Domain-separated hash of this block header.
    pub fn block_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_BLOCK, &self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(116);
        buf.extend_from_slice(&self.height.to_le_bytes());         // 8
        buf.extend_from_slice(&self.timestamp.to_le_bytes());      // 8
        buf.extend_from_slice(&self.prev_block_hash);               // 32
        buf.extend_from_slice(&self.state_root);                    // 32
        buf.extend_from_slice(&self.transactions_root);             // 32
        buf.extend_from_slice(&self.tx_count.to_le_bytes());       // 4
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 116 {
            return Err(ChainError::InvalidEncoding(
                "block header too short".into(),
            ));
        }
        // R9: Reject trailing garbage bytes. A header must be exactly 116 bytes.
        // Without this check, an attacker could append arbitrary data to a valid
        // header, creating non-canonical serializations that hash differently but
        // decode to the same logical header.
        if data.len() > 116 {
            return Err(ChainError::InvalidEncoding(
                format!("block header too long: {} bytes (expected 116)", data.len()),
            ));
        }
        let height = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let timestamp = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut prev_block_hash = [0u8; 32];
        prev_block_hash.copy_from_slice(&data[16..48]);
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&data[48..80]);
        let mut transactions_root = [0u8; 32];
        transactions_root.copy_from_slice(&data[80..112]);
        let tx_count = u32::from_le_bytes(data[112..116].try_into().unwrap());
        Ok(Self {
            height,
            timestamp,
            prev_block_hash,
            state_root,
            transactions_root,
            tx_count,
        })
    }
}

/// A full block: header + transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Build the Merkle root from the transactions in this block.
    pub fn compute_transactions_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return ZERO_HASH;
        }
        let leaves: Vec<Hash> = self.transactions.iter().map(|tx| tx.tx_hash()).collect();
        let tree = MerkleTree::build(&leaves);
        tree.root
    }

    /// Verify that the header's transactions_root matches the actual transactions.
    pub fn verify_transactions_root(&self) -> bool {
        self.header.transactions_root == self.compute_transactions_root()
    }

    /// Create the genesis block (height 0, no transactions).
    pub fn genesis(state_root: Hash, timestamp: Timestamp) -> Self {
        let header = BlockHeader {
            height: 0,
            timestamp,
            prev_block_hash: ZERO_HASH,
            state_root,
            transactions_root: ZERO_HASH,
            tx_count: 0,
        };
        Block {
            header,
            transactions: vec![],
        }
    }

    /// Create a new block on top of a parent block.
    ///
    /// Panics if the parent block height is `u64::MAX` (overflow).
    /// Prefer `try_new` for fallible construction.
    pub fn new(
        parent: &BlockHeader,
        transactions: Vec<Transaction>,
        state_root: Hash,
        timestamp: Timestamp,
    ) -> Self {
        Self::try_new(parent, transactions, state_root, timestamp)
            .expect("block height overflow")
    }

    /// R8: Validate a block against its expected parent.
    ///
    /// Checks:
    /// 1. Height is exactly parent.height + 1 (no gaps, no rewrites)
    /// 2. prev_block_hash matches the parent's actual block hash
    /// 3. Timestamp is >= parent timestamp (monotonically non-decreasing)
    /// 4. tx_count matches the actual number of transactions
    /// 5. transactions_root matches the computed Merkle root
    pub fn validate_against_parent(&self, parent: &BlockHeader) -> Result<()> {
        // 1. Height continuity
        let expected_height = parent.height.checked_add(1).ok_or(ChainError::BlockHeightOverflow)?;
        if self.header.height != expected_height {
            return Err(ChainError::InvalidEncoding(format!(
                "block height gap: expected {}, got {}",
                expected_height, self.header.height,
            )));
        }

        // 2. Parent hash chain integrity
        let expected_parent_hash = parent.block_hash();
        if self.header.prev_block_hash != expected_parent_hash {
            return Err(ChainError::InvalidEncoding(format!(
                "parent hash mismatch: expected {}, got {}",
                hex_encode(&expected_parent_hash[..4]),
                hex_encode(&self.header.prev_block_hash[..4]),
            )));
        }

        // 3. Timestamp ordering (must be non-decreasing)
        if self.header.timestamp < parent.timestamp {
            return Err(ChainError::InvalidTimestamp);
        }

        // 4. tx_count consistency
        let actual_count: u32 = self.transactions.len().try_into().map_err(|_| {
            ChainError::InvalidEncoding(format!("too many transactions: {}", self.transactions.len()))
        })?;
        if self.header.tx_count != actual_count {
            return Err(ChainError::InvalidEncoding(format!(
                "tx_count mismatch: header says {}, actual {}",
                self.header.tx_count, actual_count,
            )));
        }

        // 5. Transactions root integrity
        if !self.verify_transactions_root() {
            return Err(ChainError::InvalidEncoding(
                "transactions_root does not match computed Merkle root".into(),
            ));
        }

        Ok(())
    }

    /// Fallible block construction -- returns an error on block height overflow.
    pub fn try_new(
        parent: &BlockHeader,
        transactions: Vec<Transaction>,
        state_root: Hash,
        timestamp: Timestamp,
    ) -> Result<Self> {
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or(ChainError::BlockHeightOverflow)?;

        let tx_count: u32 = transactions.len().try_into()
            .map_err(|_| ChainError::InvalidEncoding(
                format!("too many transactions in block: {}", transactions.len())
            ))?;
        let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.tx_hash()).collect();
        let transactions_root = if leaves.is_empty() {
            ZERO_HASH
        } else {
            MerkleTree::build(&leaves).root
        };

        let header = BlockHeader {
            height: new_height,
            timestamp,
            prev_block_hash: parent.block_hash(),
            state_root,
            transactions_root,
            tx_count,
        };

        Ok(Block {
            header,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_block() {
        let genesis = Block::genesis([0xAA; 32], 1000);
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_block_hash, ZERO_HASH);
        assert_eq!(genesis.header.tx_count, 0);
        assert!(genesis.verify_transactions_root());
    }

    #[test]
    fn block_hash_deterministic() {
        let genesis = Block::genesis([0xAA; 32], 1000);
        let h1 = genesis.header.block_hash();
        let h2 = genesis.header.block_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, ZERO_HASH);
    }

    #[test]
    fn block_header_roundtrip() {
        let genesis = Block::genesis([0xAA; 32], 1000);
        let bytes = genesis.header.to_bytes();
        let decoded = BlockHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.height, genesis.header.height);
        assert_eq!(decoded.timestamp, genesis.header.timestamp);
        assert_eq!(decoded.state_root, genesis.header.state_root);
        assert_eq!(decoded.block_hash(), genesis.header.block_hash());
    }

    #[test]
    fn child_block_links_to_parent() {
        let genesis = Block::genesis([0xAA; 32], 1000);
        let child = Block::new(&genesis.header, vec![], [0xBB; 32], 2000);
        assert_eq!(child.header.height, 1);
        assert_eq!(child.header.prev_block_hash, genesis.header.block_hash());
        assert!(child.verify_transactions_root());
    }
}
