// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! FORS (Forest of Random Subsets) is a few-times signature (FTS) scheme.
//! See https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/ for an
//! overview and https://www.di-mgt.com.au/pqc-09-fors-sig.html for a step-by-step construction.
use crate::address::{Address, AddressTrait, AddressType};
use crate::hasher::{
    HashOutput, SpxCtx, thash_fors_tree_root, partial_seed_4, thash_single_partial_4,
    compute_root_with_pctx,
};
use crate::params_128s::{SPX_FORS_BASE_OFFSET, SPX_FORS_HEIGHT, SPX_FORS_TREES};
use crate::word_array::{WordSpan, WordSpanTrait};

/// FORS signature.
pub type ForsSignature = [ForsTreeSignature; SPX_FORS_TREES];

/// FORS tree signature.
#[derive(Drop, Copy, Serde, Default)]
pub struct ForsTreeSignature {
    pub sk_seed: HashOutput,
    pub auth_path: [HashOutput; SPX_FORS_HEIGHT],
}

/// Derive FORS public key from a signature.
/// Optimized to pre-absorb pk_seed + a0-a3 (shared across all 14 FORS trees),
/// then absorb only a4-a5 + data for each operation.
pub fn fors_pk_from_sig(
    ctx: SpxCtx, mut sig: ForsSignature, mhash: WordSpan, address: @Address,
) -> HashOutput {
    let mut fors_tree_addr = *address;
    fors_tree_addr.set_address_type(AddressType::FORSTREE);

    // Pre-absorb pk_seed + a0-a3 (constant across all FORS trees).
    // All 14 trees share layer=0, same hypertree_addr, type=FORSTREE, same keypair.
    let [a0, a1, a2, a3, _, _] = fors_tree_addr.into_field_components();
    let pctx = partial_seed_4(ctx, a0, a1, a2, a3);

    // Compute indices of leaves of the FORS trees
    let mut indices = message_to_indices_128s(mhash);
    // Offset for the leaves indices
    let mut idx_offset = 0;
    // FORS roots
    let mut roots = array![];

    let mut fors_sig = sig.span();

    while let Some(fors_tree_sig) = fors_sig.pop_front() {
        let ForsTreeSignature { sk_seed, auth_path } = *fors_tree_sig;
        let leaf_idx = indices.pop_front().unwrap();

        // NOTE: already zero `fors_tree_addr.set_tree_height(0);`
        fors_tree_addr.set_tree_index(idx_offset + leaf_idx);

        // Extract only the varying address components (a4, a5).
        let [_, _, _, _, a4, a5] = fors_tree_addr.into_field_components();

        // Derive the leaf hash from the secret key seed and tree address.
        let leaf = thash_single_partial_4(pctx, a4, a5, sk_seed);

        // Derive the corresponding root node of this tree.
        // Auth path has fixed length, so we don't need to assert tree height.
        let root = compute_root_with_pctx(
            pctx, @fors_tree_addr, leaf, auth_path.span(), leaf_idx, idx_offset,
        );
        roots.append(root);

        idx_offset += SPX_FORS_BASE_OFFSET;
    }

    // Hash horizontally across all tree roots to derive the public key.
    let mut fors_pk_addr = *address;
    fors_pk_addr.set_address_type(AddressType::FORSPK);

    let mut roots_sp = roots.span();
    if let Some(chunk) = roots_sp.multi_pop_front::<SPX_FORS_TREES>() {
        return thash_fors_tree_root(ctx, @fors_pk_addr, chunk.unbox());
    }

    panic!("invalid number of FORS trees");
}

/// Convert FORS mhash to leaf indices.
/// For Bitcoin params: k=9 trees, a=15 height
/// Total bits needed: 9 * 15 = 135 bits ~= 17 bytes
fn message_to_indices_128s(mut mhash: WordSpan) -> Array<u32> {
    let mut indices = array![];
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    while let Some((word, num_bytes)) = mhash.pop_front() {
        let mut remaining = word;
        let mut bytes_left = num_bytes;

        while bytes_left > 0 {
            // Extract one byte (big-endian)
            let shift = (bytes_left - 1) * 8;
            let byte_val = if shift == 24 {
                remaining / 0x1000000
            } else if shift == 16 {
                (remaining / 0x10000) % 0x100
            } else if shift == 8 {
                (remaining / 0x100) % 0x100
            } else {
                remaining % 0x100
            };

            acc = acc * 0x100 + byte_val;
            acc_bits += 8;

            // Extract 15-bit indices when we have enough bits
            extract_acc_bits(ref acc, ref acc_bits, ref indices);

            bytes_left -= 1;
        }
    }

    indices
}

#[inline]
fn pow2(exp: u32) -> u32 {
    let mut result: felt252 = 1;
    let mut base: felt252 = 2;
    let mut e = exp;
    while e > 0 {
        if e % 2 == 1 {
            result *= base;
        }
        base *= base;
        e /= 2;
    }
    result.try_into().unwrap()
}

fn extract_acc_bits(ref acc: u32, ref acc_bits: u32, ref indices: Array<u32>) {
    // Extract 15-bit indices when we have enough bits
    while acc_bits >= SPX_FORS_HEIGHT && indices.len() < SPX_FORS_HEIGHT {
        let shift_amount = acc_bits - SPX_FORS_HEIGHT;
        let divisor: u32 = pow2(shift_amount);
        let index = acc / divisor;
        let mask = divisor - 1;
        acc = acc & mask;
        acc_bits -= SPX_FORS_HEIGHT;
        indices.append(index);
    }
}

#[cfg(test)]
mod tests {
    use crate::word_array::WordArrayTrait;
    use crate::word_array::hex::words_from_hex;
    use super::*;

    #[test]
    fn test_message_to_indices_128s() {
        let mhash = words_from_hex("1a291170e1bac7a22b05937abd0a24585d");
        let indices = message_to_indices_128s(mhash.span());
        let expected = array![3348, 17500, 7223, 11386, 4440, 5709, 30074, 2596, 11310];
        assert_eq!(expected, indices);
    }
}
