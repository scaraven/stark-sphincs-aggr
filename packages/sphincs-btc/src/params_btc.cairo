// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Bitcoin-optimized SPHINCS+ parameters based on Blockstream's paper.
//! Target signature size: ~3.4KB with STARK-provable verification.
//!
//! Key optimizations:
//! - WOTS+C: Eliminate checksum chains via grinding (w=256)
//! - FORS+C: Force last tree index 0, omit auth path
//! - Reduced hypertree: h=32, d=4

/// Hash output length in bytes (n parameter).
pub const SPX_N: usize = 16;

/// Hash output length in 32-bit words.
pub const SPX_HASH_LEN: usize = 4;

/// Total height of the hypertree.
pub const SPX_FULL_HEIGHT: usize = 32;

/// Number of hypertree layers (d parameter).
pub const SPX_D: usize = 4;

/// Height of each subtree: SPX_FULL_HEIGHT / SPX_D = 32 / 4 = 8.
pub const SPX_TREE_HEIGHT: usize = 8;

/// Number of leaves per subtree: 2^SPX_TREE_HEIGHT = 256.
pub const SPX_TREE_LEAVES: usize = 256;

/// FORS tree height (a parameter).
pub const SPX_FORS_HEIGHT: usize = 14;

/// FORS tree base offset: 2^SPX_FORS_HEIGHT = 16384.
pub const SPX_FORS_BASE_OFFSET: usize = 16384;

/// Number of FORS trees (k parameter).
pub const SPX_FORS_TREES: usize = 10;

/// FORS message hash size in bytes: ceil(k * a / 8) = ceil(10 * 14 / 8) = 18.
pub const SPX_FORS_MSG_BYTES: usize = 18;

/// FORS signature size (without FORS+C optimization).
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;

/// Hypertree address bit length: SPX_TREE_HEIGHT * (SPX_D - 1) = 8 * 3 = 24.
pub const SPX_TREE_BITS: usize = 24;

/// Hypertree address byte length: ceil(24 / 8) = 3.
pub const SPX_TREE_BYTES: usize = 3;

/// Bottom leaf index bit length: SPX_TREE_HEIGHT = 8.
pub const SPX_LEAF_BITS: usize = 8;

/// Bottom leaf index byte length: ceil(8 / 8) = 1.
pub const SPX_LEAF_BYTES: usize = 1;

/// Extended message digest length: SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES = 18 + 3 + 1 = 22.
pub const SPX_DGST_BYTES: usize = 22;

// === WOTS+C Parameters (w=256) ===

/// Winternitz parameter w. With w=256, each digit is 8 bits (one byte).
pub const SPX_WOTS_W: usize = 256;

/// Log base 2 of Winternitz parameter.
pub const SPX_WOTS_LOGW: usize = 8;

/// Number of base-w digits for n-byte message: n * 8 / log2(w) = 16 * 8 / 8 = 16.
pub const SPX_WOTS_LEN1: usize = 16;

/// Number of trailing zero chains to omit (tau parameter for WOTS+C).
/// These chains are not included in the signature.
pub const SPX_WOTS_C_OMIT: usize = 2;

/// Number of signed chains in WOTS+C: LEN1 - OMIT = 16 - 2 = 14.
pub const SPX_WOTS_C_LEN: usize = 14;

/// Target sum S_{w,n} for WOTS+C. The sum of all LEN1 base-w digits must equal this.
/// For w=256, n=16: optimal values are around 2040 (16 * 127.5).
/// This value determines grinding difficulty and security margin.
pub const SPX_WOTS_TARGET_SUM: u32 = 2040;

// === FORS+C Parameters ===

/// Number of FORS trees with full auth paths.
/// The last tree uses index 0 (forced by grinding), so its auth path is omitted.
pub const SPX_FORS_FULL_TREES: usize = 9;

/// FORS+C saves: 1 tree auth path = SPX_FORS_HEIGHT * SPX_N = 14 * 16 = 224 bytes.
pub const SPX_FORS_C_SAVINGS: usize = 224;
