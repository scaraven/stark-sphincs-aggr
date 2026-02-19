// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
// This describes a parameter set chosen from https://eprint.iacr.org/2025/2203.pdf

/// Hash output length in bytes.
pub const SPX_N: usize = 16;
/// Height of the hypertree. Equivalent to h parameter.
pub const SPX_FULL_HEIGHT: usize = 33;
/// Number of subtree layer. Equivalent to d parameter.
pub const SPX_D: usize = 3;
/// FORS tree height. Equivalent to a parameter.
pub const SPX_FORS_HEIGHT: usize = 15;
/// FORS tree base offset: 1 << SPX_FORS_HEIGHT.
pub const SPX_FORS_BASE_OFFSET: usize = 32768;
/// Number of FORS trees. Equivalent to k parameter.
pub const SPX_FORS_TREES: usize = 9;
/// Subtree size.
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D; // 11
/// FORS mhash size
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8; // 17
/// FORS signature size
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;
/// Hypertree address bit length.
pub const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT * (SPX_D - 1); // 22
/// Hypertree address byte length.
pub const SPX_TREE_BYTES: usize = (SPX_TREE_BITS + 7) / 8; // 3
/// Bottom leaf index bit length.
pub const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT; // 11
/// Bottom leaf index byte length.
pub const SPX_LEAF_BYTES: usize = (SPX_LEAF_BITS + 7) / 8; // 2
/// Extended message digest length.
pub const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES; // 22
/// WOTS+ word size
pub const SPX_WOTS_W: usize = 16;
/// WOTS+ log word size
pub const SPX_WOTS_LOGW: usize = 4;
/// WOTS+ W-encoded message length.
pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW; // 32

/// Target sum is ommited
pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1;

/// WOTS+C target checksum
pub const SPX_WOTS_CSUM: usize = 304;

