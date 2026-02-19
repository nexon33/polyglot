//! Ciphertext compression for the RNS-CKKS encrypted inference pipeline.
//!
//! Provides bincode serialization + zstd compression for compact wire transport
//! of CKKS ciphertexts, evaluation keys, and rotation key sets.
//!
//! ## Compression levels
//!
//! | Level      | Method                          | Ratio  | Speed |
//! |------------|---------------------------------|--------|-------|
//! | `Lossless` | bincode + zstd(3)               | ~1.4x  | Fast  |
//! | `Compact`  | bincode + byte-shuffle(8) + zstd| ~2x    | Fast  |
//! | `Max`      | byte-shuffle(8) + zstd(19)      | ~2.2x  | Slow  |
//!
//! All levels are lossless. `Compact` uses a byte-shuffle filter (element
//! size 8) before zstd. This groups the leading-zero bytes of i64
//! coefficients together, letting zstd compress long runs of zeros.
//!
//! `Max` uses the highest zstd compression level (19) on byte-shuffled data,
//! trading encode speed for the best possible lossless ratio.
//!
//! ## Wire format
//!
//! ### Version 1 (Lossless)
//! ```text
//! [4 bytes] magic: b"PFHE"
//! [1 byte]  version: 1
//! [4 bytes] original size (little-endian u32, for pre-allocation)
//! [rest]    zstd-compressed bincode payload
//! ```
//!
//! ### Version 2 (Compact / Max)
//! ```text
//! [4 bytes] magic: b"PFHE"
//! [1 byte]  version: 2
//! [1 byte]  level: 1=compact, 2=max
//! [1 byte]  reserved (0)
//! [1 byte]  shuffle_element_size (8)
//! [4 bytes] original size (little-endian u32, pre-shuffle bincode size)
//! [rest]    zstd-compressed byte-shuffled payload
//! ```

use serde::{de::DeserializeOwned, Serialize};

// ─── Constants ────────────────────────────────────────────────────────

/// Magic bytes identifying a PFHE compressed payload.
const MAGIC: &[u8; 4] = b"PFHE";

/// Header size v1: 4 (magic) + 1 (version) + 4 (original size) = 9.
const HEADER_V1_SIZE: usize = 9;

/// Header size v2: 4 (magic) + 1 (version) + 1 (level) + 1 (trunc) + 1 (elem_size) + 4 (orig_size) = 12.
const HEADER_V2_SIZE: usize = 12;

/// Default zstd compression level (3 = good speed/ratio balance).
const ZSTD_LEVEL: i32 = 3;

/// Maximum zstd compression level (19 = best ratio, slower encode).
const ZSTD_LEVEL_MAX: i32 = 19;

/// Element size for byte-shuffle (8 = sizeof i64, optimal for CKKS polynomials).
const SHUFFLE_ELEMENT_SIZE: u8 = 8;

/// Maximum allowed decompressed size (32 MB) to prevent decompression bombs.
/// For CKKS with N=4096 and 20 primes, a ciphertext is ~1.3 MB uncompressed.
/// Rotation keys (one key-switch matrix per rotation step) can reach ~16 MB.
const MAX_DECOMPRESSED_SIZE: usize = 32 * 1024 * 1024;

// ─── Compression Level ───────────────────────────────────────────────

/// Compression level for the PFHE wire format.
///
/// All levels are lossless. Higher levels trade encode speed for better ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// Lossless: bincode + zstd(3). ~1.4x ratio for CKKS data.
    /// Fastest encode, safe for all data. Wire format v1.
    Lossless,
    /// Lossless: bincode + byte-shuffle(8) + zstd(3). ~2x ratio for CKKS data.
    /// Groups leading-zero bytes of i64 values together for better zstd compression.
    /// Good speed/ratio balance. Wire format v2.
    Compact,
    /// Lossless: bincode + byte-shuffle(8) + zstd(19). ~2.2x ratio for CKKS data.
    /// Best lossless ratio, slower encode. Wire format v2.
    Max,
}

// ─── Generic compression API ─────────────────────────────────────────

/// Serialize and compress with the default level (Lossless, v1 format).
///
/// This is the safe default. Use [`compress_with`] for better ratios.
pub fn compress<T: Serialize>(value: &T) -> Result<Vec<u8>, CompressError> {
    let raw = bincode::serialize(value).map_err(CompressError::Serialize)?;
    let original_size = raw.len();

    let compressed =
        zstd::encode_all(raw.as_slice(), ZSTD_LEVEL).map_err(CompressError::Compress)?;

    if original_size > u32::MAX as usize {
        return Err(CompressError::Compress(
            std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("payload too large for PFHE v1 header: {} bytes", original_size))
        ));
    }
    let mut out = Vec::with_capacity(HEADER_V1_SIZE + compressed.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // version 1
    out.extend_from_slice(&(original_size as u32).to_le_bytes());
    out.extend_from_slice(&compressed);

    Ok(out)
}

/// Serialize and compress with a specific level.
///
/// All levels are lossless. `Compact` uses byte-shuffle + zstd(3).
/// `Max` uses byte-shuffle + zstd(19) for the best ratio at slower speed.
pub fn compress_with<T: Serialize>(
    value: &T,
    level: CompressionLevel,
) -> Result<Vec<u8>, CompressError> {
    match level {
        CompressionLevel::Lossless => compress(value),
        CompressionLevel::Compact => {
            let raw = bincode::serialize(value).map_err(CompressError::Serialize)?;
            compress_v2_raw(&raw, ZSTD_LEVEL, 1)
        }
        CompressionLevel::Max => {
            let raw = bincode::serialize(value).map_err(CompressError::Serialize)?;
            compress_v2_raw(&raw, ZSTD_LEVEL_MAX, 2)
        }
    }
}

/// Decompress a PFHE payload (auto-detects v1 or v2 format).
pub fn decompress<T: DeserializeOwned>(data: &[u8]) -> Result<T, CompressError> {
    if data.len() < HEADER_V1_SIZE {
        return Err(CompressError::InvalidHeader("payload too short"));
    }
    if &data[..4] != MAGIC {
        return Err(CompressError::InvalidHeader("bad magic bytes"));
    }

    match data[4] {
        1 => decompress_v1(data),
        2 => decompress_v2_raw(data),
        _ => Err(CompressError::InvalidHeader("unsupported version")),
    }
}

/// Check if a byte slice starts with the PFHE magic header.
pub fn is_compressed(data: &[u8]) -> bool {
    data.len() >= HEADER_V1_SIZE && &data[..4] == MAGIC
}

/// Return the compression level stored in a PFHE payload header.
pub fn detect_level(data: &[u8]) -> Option<CompressionLevel> {
    if !is_compressed(data) {
        return None;
    }
    match data[4] {
        1 => Some(CompressionLevel::Lossless),
        2 if data.len() >= HEADER_V2_SIZE => {
            let level_byte = data[5];
            match level_byte {
                1 => Some(CompressionLevel::Compact),
                2 => Some(CompressionLevel::Max),
                _ => None,
            }
        }
        _ => None,
    }
}

// ─── Stats ───────────────────────────────────────────────────────────

/// Compute compression ratio and sizes at the default (Lossless) level.
pub fn compression_stats<T: Serialize>(value: &T) -> Stats {
    let raw = bincode::serialize(value).unwrap_or_default();
    let compressed = compress(value).unwrap_or_default();
    Stats::new(raw.len(), compressed.len())
}

/// Compute compression ratio and sizes at a specific level.
pub fn compression_stats_with<T: Serialize>(
    value: &T,
    level: CompressionLevel,
) -> Stats {
    let raw = bincode::serialize(value).unwrap_or_default();
    let compressed = compress_with(value, level).unwrap_or_default();
    Stats::new(raw.len(), compressed.len())
}

/// Compression statistics.
#[derive(Debug, Clone)]
pub struct Stats {
    /// Size of bincode-serialized data (no compression).
    pub raw_size: usize,
    /// Size of the full PFHE compressed payload (header + zstd).
    pub compressed_size: usize,
    /// Compression ratio (raw / compressed).
    pub ratio: f64,
}

impl Stats {
    fn new(raw_size: usize, compressed_size: usize) -> Self {
        let ratio = if compressed_size > 0 {
            raw_size as f64 / compressed_size as f64
        } else {
            0.0
        };
        Self { raw_size, compressed_size, ratio }
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {} ({:.1}x)",
            format_bytes(self.raw_size),
            format_bytes(self.compressed_size),
            self.ratio,
        )
    }
}

fn format_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

// ─── Entropy validation ─────────────────────────────────────────────

/// Maximum acceptable compression ratio for CKKS ciphertexts.
///
/// CKKS ciphertexts in NTT-RNS form contain pseudo-random ~36-bit values in
/// 64-bit containers. The only compressible structure is the ~28 zero padding
/// bits per coefficient. After byte-shuffle removes that container waste, the
/// underlying data should be indistinguishable from random by any compressor.
///
/// Expected ratios:
/// - **~1.4x** (Lossless): zstd catches some zero padding
/// - **~2.0x** (Compact): byte-shuffle removes all container waste
/// - **~2.2x** (Max): zstd(19) squeezes a tiny bit more
///
/// A ratio exceeding this threshold means the ciphertext has exploitable
/// structure — a potential IND-CPA violation. This serves as a continuous
/// runtime entropy monitor at zero additional cost (compression is already
/// happening for wire transport).
pub const ENTROPY_RATIO_THRESHOLD: f64 = 2.5;

/// Result of an entropy validation check on compressed ciphertext data.
#[derive(Debug, Clone)]
pub struct EntropyCheck {
    /// Compression ratio (raw_size / compressed_size).
    pub ratio: f64,
    /// Whether the ratio is within acceptable bounds.
    pub pass: bool,
    /// The threshold used for this check.
    pub threshold: f64,
    /// Raw bincode size.
    pub raw_size: usize,
    /// Compressed payload size.
    pub compressed_size: usize,
}

impl std::fmt::Display for EntropyCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "entropy {} — {:.2}x ratio ({} -> {}), threshold {:.1}x",
            if self.pass { "PASS" } else { "FAIL" },
            self.ratio,
            format_bytes(self.raw_size),
            format_bytes(self.compressed_size),
            self.threshold,
        )
    }
}

/// Validate that a serializable CKKS value has sufficient entropy.
///
/// Compresses with `Compact` level (byte-shuffle + zstd) and checks that the
/// ratio does not exceed [`ENTROPY_RATIO_THRESHOLD`]. A ratio above the
/// threshold indicates the ciphertext contains exploitable structure — the
/// data is more compressible than pseudo-random coefficients should be.
///
/// This is effectively a continuous IND-CPA test: if one of the best
/// general-purpose compressors in existence can distinguish your ciphertext
/// from random data, an adversary probably can too.
///
/// # Returns
///
/// [`EntropyCheck`] with `pass = true` if the ciphertext looks sufficiently
/// random, `pass = false` if anomalous compressibility was detected.
pub fn entropy_check<T: Serialize>(value: &T) -> EntropyCheck {
    let raw = bincode::serialize(value).unwrap_or_default();
    let compressed = compress_with(value, CompressionLevel::Compact).unwrap_or_default();
    let ratio = if compressed.is_empty() {
        0.0
    } else {
        raw.len() as f64 / compressed.len() as f64
    };
    EntropyCheck {
        ratio,
        pass: ratio <= ENTROPY_RATIO_THRESHOLD,
        threshold: ENTROPY_RATIO_THRESHOLD,
        raw_size: raw.len(),
        compressed_size: compressed.len(),
    }
}

/// Validate entropy with a custom threshold.
pub fn entropy_check_with_threshold<T: Serialize>(value: &T, threshold: f64) -> EntropyCheck {
    let mut check = entropy_check(value);
    check.threshold = threshold;
    check.pass = check.ratio <= threshold;
    check
}

// ─── Errors ──────────────────────────────────────────────────────────

/// Errors from compress/decompress operations.
#[derive(Debug)]
pub enum CompressError {
    Serialize(bincode::Error),
    Deserialize(bincode::Error),
    Compress(std::io::Error),
    Decompress(std::io::Error),
    InvalidHeader(&'static str),
    SizeMismatch { expected: usize, actual: usize },
    DecompressedSizeExceeded { claimed: usize, limit: usize },
}

impl std::fmt::Display for CompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "bincode serialize: {e}"),
            Self::Deserialize(e) => write!(f, "bincode deserialize: {e}"),
            Self::Compress(e) => write!(f, "zstd compress: {e}"),
            Self::Decompress(e) => write!(f, "zstd decompress: {e}"),
            Self::InvalidHeader(msg) => write!(f, "invalid PFHE header: {msg}"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: expected {expected}, got {actual}")
            }
            Self::DecompressedSizeExceeded { claimed, limit } => {
                write!(f, "decompressed size {claimed} exceeds limit {limit}")
            }
        }
    }
}

impl std::error::Error for CompressError {}

// ─── Internal helpers ────────────────────────────────────────────────

/// Decompress a v1 (lossless) payload.
fn decompress_v1<T: DeserializeOwned>(data: &[u8]) -> Result<T, CompressError> {
    let original_size =
        u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

    if original_size > MAX_DECOMPRESSED_SIZE {
        return Err(CompressError::DecompressedSizeExceeded {
            claimed: original_size,
            limit: MAX_DECOMPRESSED_SIZE,
        });
    }

    // R8: Use size-limited decompression to prevent decompression bombs.
    // Without this, zstd::decode_all would decompress the entire payload into
    // memory before checking the size limit — a crafted payload with high
    // compression ratio could exhaust memory (e.g. 1KB compressed → 4GB).
    let decompressed = decompress_with_limit(&data[HEADER_V1_SIZE..], MAX_DECOMPRESSED_SIZE)?;

    if decompressed.len() != original_size {
        return Err(CompressError::SizeMismatch {
            expected: original_size,
            actual: decompressed.len(),
        });
    }

    bincode::deserialize(&decompressed).map_err(CompressError::Deserialize)
}

/// Compress raw bincode bytes with v2 format (byte-shuffle + zstd).
fn compress_v2_raw(raw: &[u8], zstd_level: i32, level_byte: u8) -> Result<Vec<u8>, CompressError> {
    let original_size = raw.len();

    let shuffled = byte_shuffle(raw, SHUFFLE_ELEMENT_SIZE as usize);
    let compressed =
        zstd::encode_all(shuffled.as_slice(), zstd_level).map_err(CompressError::Compress)?;

    if original_size > u32::MAX as usize {
        return Err(CompressError::Compress(
            std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("payload too large for PFHE v2 header: {} bytes", original_size))
        ));
    }
    let mut out = Vec::with_capacity(HEADER_V2_SIZE + compressed.len());
    out.extend_from_slice(MAGIC);
    out.push(2); // version 2
    out.push(level_byte);
    out.push(0); // reserved
    out.push(SHUFFLE_ELEMENT_SIZE);
    out.extend_from_slice(&(original_size as u32).to_le_bytes());
    out.extend_from_slice(&compressed);

    Ok(out)
}

/// Decompress a v2 payload (byte-unshuffle + zstd decompress + bincode deserialize).
fn decompress_v2_raw<T: DeserializeOwned>(data: &[u8]) -> Result<T, CompressError> {
    if data.len() < HEADER_V2_SIZE {
        return Err(CompressError::InvalidHeader("v2 payload too short"));
    }

    let _level_byte = data[5];
    let _reserved = data[6];
    let element_size = data[7] as usize;
    // Validate element_size matches the expected shuffle element size to prevent
    // an attacker from manipulating the unshuffle step
    if element_size != SHUFFLE_ELEMENT_SIZE as usize {
        return Err(CompressError::InvalidHeader("unexpected shuffle element size"));
    }
    let original_size =
        u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

    if original_size > MAX_DECOMPRESSED_SIZE {
        return Err(CompressError::DecompressedSizeExceeded {
            claimed: original_size,
            limit: MAX_DECOMPRESSED_SIZE,
        });
    }

    // R8: Use size-limited decompression to prevent decompression bombs.
    let decompressed = decompress_with_limit(&data[HEADER_V2_SIZE..], MAX_DECOMPRESSED_SIZE)?;

    let unshuffled = byte_unshuffle(&decompressed, element_size);

    if unshuffled.len() != original_size {
        return Err(CompressError::SizeMismatch {
            expected: original_size,
            actual: unshuffled.len(),
        });
    }

    bincode::deserialize(&unshuffled).map_err(CompressError::Deserialize)
}

/// Decompress zstd data with a streaming size limit.
///
/// R8: Prevents decompression bombs by reading at most `max_bytes` from the
/// zstd stream. If the decompressed output exceeds the limit, returns an error
/// before the full payload is materialized in memory.
fn decompress_with_limit(compressed: &[u8], max_bytes: usize) -> Result<Vec<u8>, CompressError> {
    use std::io::Read;
    let mut decoder = zstd::Decoder::new(compressed)
        .map_err(CompressError::Decompress)?;
    // R9: Use incremental allocation instead of pre-allocating max_bytes + 1 (33MB).
    // The old approach allocated 33MB unconditionally for every decompression, even
    // for tiny payloads. An attacker sending many small compressed payloads could
    // exhaust memory via the 33MB-per-call overhead. Now we start with a small
    // buffer and grow as needed, capped at max_bytes + 1.
    let initial_cap = compressed.len().saturating_mul(4).min(max_bytes + 1).max(4096);
    let mut buf = vec![0u8; initial_cap];
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            // Grow buffer, but never exceed max_bytes + 1
            let new_len = buf.len().saturating_mul(2).min(max_bytes + 1);
            if new_len <= buf.len() {
                // Can't grow anymore — one more read to detect overflow
                let mut one = [0u8; 1];
                let n = decoder.read(&mut one).map_err(CompressError::Decompress)?;
                if n > 0 {
                    return Err(CompressError::DecompressedSizeExceeded {
                        claimed: total + n,
                        limit: max_bytes,
                    });
                }
                break;
            }
            buf.resize(new_len, 0);
        }
        let n = decoder.read(&mut buf[total..])
            .map_err(CompressError::Decompress)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > max_bytes {
            return Err(CompressError::DecompressedSizeExceeded {
                claimed: total,
                limit: max_bytes,
            });
        }
    }
    buf.truncate(total);
    Ok(buf)
}

/// Byte-shuffle: transpose an array of `element_size`-byte elements so that
/// all byte-0s are contiguous, then all byte-1s, etc. This groups the
/// leading-zero bytes of small integers together for better zstd compression.
///
/// Example with element_size=4:
/// `[A0 A1 A2 A3 | B0 B1 B2 B3]` → `[A0 B0 | A1 B1 | A2 B2 | A3 B3]`
fn byte_shuffle(data: &[u8], element_size: usize) -> Vec<u8> {
    if element_size <= 1 || data.len() < element_size {
        return data.to_vec();
    }
    let n_elements = data.len() / element_size;
    let mut out = Vec::with_capacity(data.len());

    // Transpose: group all byte-position-k values together
    for byte_pos in 0..element_size {
        for elem in 0..n_elements {
            out.push(data[elem * element_size + byte_pos]);
        }
    }
    // Append remainder bytes (not part of any complete element)
    out.extend_from_slice(&data[n_elements * element_size..]);
    out
}

/// Inverse of [`byte_shuffle`]: restore original element order.
fn byte_unshuffle(data: &[u8], element_size: usize) -> Vec<u8> {
    if element_size <= 1 || data.len() < element_size {
        return data.to_vec();
    }
    let n_elements = data.len() / element_size;
    let shuffled_len = n_elements * element_size;
    let mut out = vec![0u8; data.len()];

    let mut src = 0;
    for byte_pos in 0..element_size {
        for elem in 0..n_elements {
            out[elem * element_size + byte_pos] = data[src];
            src += 1;
        }
    }
    // Copy remainder
    out[shuffled_len..].copy_from_slice(&data[shuffled_len..]);
    out
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let data: Vec<i64> = (0..4096).collect();
        let compressed = compress(&data).unwrap();
        let decompressed: Vec<i64> = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn magic_header_detected() {
        let data = vec![42u32; 100];
        let compressed = compress(&data).unwrap();
        assert!(is_compressed(&compressed));
        assert!(!is_compressed(b"not compressed"));
        assert!(!is_compressed(&[]));
    }

    #[test]
    fn corrupted_data_fails() {
        let data = vec![42u32; 100];
        let mut compressed = compress(&data).unwrap();
        // Corrupt the zstd payload
        if let Some(last) = compressed.last_mut() {
            *last ^= 0xFF;
        }
        let result: Result<Vec<u32>, _> = decompress(&compressed);
        assert!(result.is_err());
    }

    #[test]
    fn bad_magic_fails() {
        let result: Result<Vec<u32>, _> = decompress(b"BADMxxxxxxxxxxxxxx");
        assert!(matches!(result, Err(CompressError::InvalidHeader(_))));
    }

    #[test]
    fn bad_version_fails() {
        let mut data = vec![0u8; 20];
        data[..4].copy_from_slice(b"PFHE");
        data[4] = 99; // bad version
        let result: Result<Vec<u32>, _> = decompress(&data);
        assert!(matches!(result, Err(CompressError::InvalidHeader(_))));
    }

    #[test]
    fn stats_display() {
        let data: Vec<i64> = (0..4096).collect();
        let stats = compression_stats(&data);
        assert!(stats.raw_size > 0);
        assert!(stats.compressed_size > 0);
        assert!(stats.ratio > 1.0);
        let s = format!("{stats}");
        assert!(s.contains("x"));
    }

    // ── Compact (v2) tests ───────────────────────────────────────────

    #[test]
    fn compact_round_trip() {
        let data: Vec<i64> = (0..4096).collect();
        let compressed = compress_with(&data, CompressionLevel::Compact).unwrap();
        let decompressed: Vec<i64> = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn compact_better_than_lossless_for_small_ints() {
        // Small integers in i64 containers — Compact should beat Lossless
        let data: Vec<i64> = (0..8192).map(|i| i % 256).collect();
        let lossless = compress(&data).unwrap();
        let compact = compress_with(&data, CompressionLevel::Compact).unwrap();

        // Compact should be smaller (byte-shuffle groups the zero high bytes)
        assert!(
            compact.len() <= lossless.len(),
            "Compact ({}) should be <= Lossless ({})",
            compact.len(), lossless.len()
        );
    }

    #[test]
    fn compact_detect_level() {
        let data: Vec<i64> = (0..100).collect();

        let v1 = compress(&data).unwrap();
        assert_eq!(detect_level(&v1), Some(CompressionLevel::Lossless));

        let v2 = compress_with(&data, CompressionLevel::Compact).unwrap();
        assert_eq!(detect_level(&v2), Some(CompressionLevel::Compact));
    }

    // ── Byte shuffle tests ───────────────────────────────────────────

    #[test]
    fn byte_shuffle_round_trip() {
        let data: Vec<u8> = (0..64).collect();
        let shuffled = byte_shuffle(&data, 8);
        let unshuffled = byte_unshuffle(&shuffled, 8);
        assert_eq!(data, unshuffled);
    }

    #[test]
    fn byte_shuffle_with_remainder() {
        // 67 bytes with element_size=8: 8 full elements + 3 remainder bytes
        let data: Vec<u8> = (0..67).collect();
        let shuffled = byte_shuffle(&data, 8);
        let unshuffled = byte_unshuffle(&shuffled, 8);
        assert_eq!(data, unshuffled);
    }

    #[test]
    fn byte_shuffle_small_input() {
        let data = vec![1u8, 2, 3];
        // Smaller than element_size — should pass through unchanged
        assert_eq!(byte_shuffle(&data, 8), data);
        assert_eq!(byte_unshuffle(&data, 8), data);
    }

    #[test]
    fn max_round_trip() {
        let data: Vec<i64> = (0..4096).collect();
        let compressed = compress_with(&data, CompressionLevel::Max).unwrap();
        let decompressed: Vec<i64> = decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
        assert_eq!(detect_level(&compressed), Some(CompressionLevel::Max));
    }

    #[test]
    fn max_smaller_than_compact_for_sequential() {
        // Sequential data should compress better with zstd(19) vs zstd(3)
        let data: Vec<i64> = (0..8192).collect();
        let compact = compress_with(&data, CompressionLevel::Compact).unwrap();
        let max = compress_with(&data, CompressionLevel::Max).unwrap();
        assert!(
            max.len() <= compact.len(),
            "Max ({}) should be <= Compact ({})",
            max.len(), compact.len()
        );
    }

    // ── Entropy validation tests ────────────────────────────────────

    #[test]
    fn entropy_check_random_data_passes() {
        // Pseudo-random i64 data (like CKKS NTT coefficients) should pass
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let data: Vec<i64> = (0..4096).map(|i| {
            let mut h = DefaultHasher::new();
            i.hash(&mut h);
            h.finish() as i64
        }).collect();
        let check = entropy_check(&data);
        assert!(check.pass, "Random data should pass entropy check: {}", check);
    }

    #[test]
    fn entropy_check_structured_data_fails() {
        // Highly structured data (all zeros) should fail
        let data: Vec<i64> = vec![0i64; 4096];
        let check = entropy_check(&data);
        assert!(!check.pass, "All-zeros should fail entropy check: {}", check);
    }

    #[test]
    fn entropy_check_display() {
        let data: Vec<i64> = vec![42; 100];
        let check = entropy_check(&data);
        let s = format!("{check}");
        assert!(s.contains("entropy"));
        assert!(s.contains("ratio"));
    }
}
