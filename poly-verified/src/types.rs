use serde::{Deserialize, Serialize};

use crate::error::{ProofSystemError, Result};

/// Serde helper for [u8; 64] arrays (signatures).
mod serde_byte64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &[u8; 64],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        bytes.to_vec().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// The zero hash: 32 bytes of 0x00.
pub const ZERO_HASH: Hash = [0u8; 32];

/// Constant-time comparison for two hashes (prevents timing side-channels).
pub fn hash_eq(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Commitment (104 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment {
    pub root: Hash,
    pub total_checkpoints: u64,
    pub chain_tip: Hash,
    pub code_hash: Hash,
}

impl Commitment {
    pub const SIZE: usize = 104;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.root);
        buf[32..40].copy_from_slice(&self.total_checkpoints.to_le_bytes());
        buf[40..72].copy_from_slice(&self.chain_tip);
        buf[72..104].copy_from_slice(&self.code_hash);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "commitment: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[0..32]);
        let total_checkpoints = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let mut chain_tip = [0u8; 32];
        chain_tip.copy_from_slice(&data[40..72]);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&data[72..104]);
        Ok(Self {
            root,
            total_checkpoints,
            chain_tip,
            code_hash,
        })
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        hash_eq(&self.root, &other.root)
            && self.total_checkpoints == other.total_checkpoints
            && hash_eq(&self.chain_tip, &other.chain_tip)
            && hash_eq(&self.code_hash, &other.code_hash)
    }
}

impl Eq for Commitment {}

// ---------------------------------------------------------------------------
// SignedCommitment (200 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommitment {
    pub commitment: Commitment,
    #[serde(with = "serde_byte64")]
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl SignedCommitment {
    pub const SIZE: usize = 200;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..104].copy_from_slice(&self.commitment.to_bytes());
        buf[104..168].copy_from_slice(&self.signature);
        buf[168..200].copy_from_slice(&self.public_key);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "signed commitment: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let commitment = Commitment::from_bytes(&data[0..104])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[104..168]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[168..200]);
        Ok(Self {
            commitment,
            signature,
            public_key,
        })
    }
}

// ---------------------------------------------------------------------------
// ProofNode (33 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: Hash,
    /// `true` means this sibling is on the LEFT: hash_combine(sibling, current).
    pub is_left: bool,
}

impl ProofNode {
    pub const SIZE: usize = 33;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.hash);
        buf[32] = if self.is_left { 0x01 } else { 0x00 };
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "proof node: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[0..32]);
        let is_left = match data[32] {
            0x00 => false,
            0x01 => true,
            v => {
                return Err(ProofSystemError::InvalidEncoding(format!(
                    "proof node is_left: expected 0x00 or 0x01, got 0x{v:02x}"
                )))
            }
        };
        Ok(Self { hash, is_left })
    }
}

// ---------------------------------------------------------------------------
// MerkleProof (variable: 108 + 33*N bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub leaf_index: u64,
    pub siblings: Vec<ProofNode>,
    pub root: Hash,
    pub code_hash: Hash,
}

impl MerkleProof {
    pub fn byte_size(&self) -> usize {
        108 + 33 * self.siblings.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let sibling_count = self.siblings.len() as u32;
        let size = 108 + 33 * self.siblings.len();
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(&self.leaf);
        buf.extend_from_slice(&self.leaf_index.to_le_bytes());
        buf.extend_from_slice(&sibling_count.to_be_bytes());
        for node in &self.siblings {
            buf.extend_from_slice(&node.to_bytes());
        }
        buf.extend_from_slice(&self.root);
        buf.extend_from_slice(&self.code_hash);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 108 {
            return Err(ProofSystemError::InvalidEncoding(
                "merkle proof: too short".to_string(),
            ));
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&data[0..32]);
        let leaf_index = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let sibling_count = u32::from_be_bytes(data[40..44].try_into().unwrap()) as usize;

        let expected_size = 108 + 33 * sibling_count;
        if data.len() < expected_size {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "merkle proof: expected {} bytes, got {}",
                expected_size,
                data.len()
            )));
        }

        let mut siblings = Vec::with_capacity(sibling_count);
        for i in 0..sibling_count {
            let offset = 44 + 33 * i;
            siblings.push(ProofNode::from_bytes(&data[offset..offset + 33])?);
        }

        let tail_offset = 44 + 33 * sibling_count;
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[tail_offset..tail_offset + 32]);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&data[tail_offset + 32..tail_offset + 64]);

        Ok(Self {
            leaf,
            leaf_index,
            siblings,
            root,
            code_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// CodeAttestation (136 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeAttestation {
    pub node_id: [u8; 32],
    pub code_hash: Hash,
    pub circuit_id: u64,
    #[serde(with = "serde_byte64")]
    pub signature: [u8; 64],
}

impl CodeAttestation {
    pub const SIZE: usize = 136;

    /// The 72-byte message that is signed: node_id || code_hash || circuit_id_LE.
    pub fn sign_message(&self) -> [u8; 72] {
        let mut msg = [0u8; 72];
        msg[0..32].copy_from_slice(&self.node_id);
        msg[32..64].copy_from_slice(&self.code_hash);
        msg[64..72].copy_from_slice(&self.circuit_id.to_le_bytes());
        msg
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.node_id);
        buf[32..64].copy_from_slice(&self.code_hash);
        buf[64..72].copy_from_slice(&self.circuit_id.to_le_bytes());
        buf[72..136].copy_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "code attestation: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&data[0..32]);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&data[32..64]);
        let circuit_id = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[72..136]);
        Ok(Self {
            node_id,
            code_hash,
            circuit_id,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// IVC Backend Identifier
// ---------------------------------------------------------------------------

/// Identifies which IVC backend produced a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BackendId {
    Mock = 0x00,
    HashIvc = 0x01,
    Nova = 0x02,
    HyperNova = 0x03,
}

impl BackendId {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Mock),
            0x01 => Ok(Self::HashIvc),
            0x02 => Ok(Self::Nova),
            0x03 => Ok(Self::HyperNova),
            _ => Err(ProofSystemError::InvalidEncoding(format!(
                "unknown backend id: 0x{v:02x}"
            ))),
        }
    }

    pub fn is_quantum_resistant(&self) -> bool {
        matches!(self, Self::HashIvc)
    }
}

// ---------------------------------------------------------------------------
// Privacy Mode
// ---------------------------------------------------------------------------

/// Privacy mode for verified execution proofs.
///
/// Controls what information is revealed to the verifier:
/// - `Transparent`: verifier sees input hash, output hash, code hash (default)
/// - `Private`: full ZK — verifier learns nothing except proof validity
/// - `PrivateInputs`: selective disclosure — verifier sees output but not inputs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrivacyMode {
    /// Transparent: verifier sees input hash, output hash, code hash.
    Transparent = 0x00,
    /// Full ZK: verifier learns nothing except proof validity.
    Private = 0x01,
    /// Selective: verifier sees output but not inputs.
    PrivateInputs = 0x02,
}

impl PrivacyMode {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Transparent),
            0x01 => Ok(Self::Private),
            0x02 => Ok(Self::PrivateInputs),
            _ => Err(ProofSystemError::InvalidEncoding(format!(
                "unknown privacy mode: 0x{v:02x}"
            ))),
        }
    }

    /// Returns true if this mode hides any information from the verifier.
    pub fn is_private(&self) -> bool {
        !matches!(self, Self::Transparent)
    }

    /// Returns true if inputs are hidden from the verifier.
    pub fn hides_inputs(&self) -> bool {
        matches!(self, Self::Private | Self::PrivateInputs)
    }

    /// Returns true if outputs are hidden from the verifier.
    pub fn hides_outputs(&self) -> bool {
        matches!(self, Self::Private)
    }
}

impl Default for PrivacyMode {
    fn default() -> Self {
        Self::Transparent
    }
}

// ---------------------------------------------------------------------------
// VerifiedProof — the proof attached to Verified<T>
// ---------------------------------------------------------------------------

/// A finalized proof of correct execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VerifiedProof {
    /// Hash-chain IVC proof (quantum resistant).
    HashIvc {
        chain_tip: Hash,
        merkle_root: Hash,
        step_count: u64,
        code_hash: Hash,
        privacy_mode: PrivacyMode,
        /// H(blinding_factors) — present when privacy_mode != Transparent.
        blinding_commitment: Option<Hash>,
        /// Step transition hashes — verifier reconstructs chain and Merkle tree from these.
        checkpoints: Vec<Hash>,
        /// Committed input hash (for I/O binding).
        input_hash: Hash,
        /// Committed output hash (for I/O binding).
        output_hash: Hash,
    },
    /// Mock proof for testing.
    Mock {
        input_hash: Hash,
        output_hash: Hash,
        privacy_mode: PrivacyMode,
    },
}

impl VerifiedProof {
    pub fn backend_id(&self) -> BackendId {
        match self {
            Self::HashIvc { .. } => BackendId::HashIvc,
            Self::Mock { .. } => BackendId::Mock,
        }
    }

    pub fn code_hash(&self) -> Hash {
        match self {
            Self::HashIvc {
                code_hash,
                privacy_mode,
                ..
            } => {
                // In full Private mode, don't leak the code identity
                if *privacy_mode == PrivacyMode::Private {
                    ZERO_HASH
                } else {
                    *code_hash
                }
            }
            Self::Mock { .. } => ZERO_HASH,
        }
    }

    /// Returns the privacy mode of this proof.
    pub fn privacy_mode(&self) -> PrivacyMode {
        match self {
            Self::HashIvc { privacy_mode, .. } => *privacy_mode,
            Self::Mock { privacy_mode, .. } => *privacy_mode,
        }
    }
}

// ---------------------------------------------------------------------------
// StepWitness — data for a single IVC fold step
// ---------------------------------------------------------------------------

/// Witness data for a single computation step.
#[derive(Clone, Debug)]
pub struct StepWitness {
    pub state_before: Hash,
    pub state_after: Hash,
    pub step_inputs: Hash,
}
